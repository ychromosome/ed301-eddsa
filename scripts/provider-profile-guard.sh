#!/bin/sh
# Downstream release-profile guard for the provider workspace.
# Wraps every rustc invocation of the guarded build and records, per
# tracked crate, one marker line
#
#   overflow=<on|off|absent> panic=<unwind|abort|absent>
#   opt=<value|absent> cgu=<value|absent> dbgassert=<on|off|absent>
#
# plus the full effective rustc command line.  "absent" means rustc's
# documented default applies (release: overflow-checks follow
# debug-assertions, which default to off), so the matrix runner can
# decide the EFFECTIVE state of every claimed release-profile flag
# exactly.  The runner enforces: markers must exist (a missing marker is
# failure), crypto_bigint must be effectively off, the project crates
# explicitly on, panic=unwind explicitly present, opt=3 and cgu=1 explicit.
set -eu

if [ "$#" -lt 1 ]; then
    echo "rustc-profile-guard: missing rustc command" >&2
    exit 2
fi
if [ -z "${ED301_PROFILE_MARKER_DIR:-}" ]; then
    echo "rustc-profile-guard: ED301_PROFILE_MARKER_DIR is unset" >&2
    exit 2
fi

crate_name=
overflow_state=absent
panic_state=absent
opt_state=absent
cgu_state=absent
dbgassert_state=absent
previous=

classify() {
    case "$1" in
        overflow-checks=on|overflow-checks=yes|overflow-checks=true)
            overflow_state=on ;;
        overflow-checks=off|overflow-checks=no|overflow-checks=false)
            overflow_state=off ;;
        panic=abort) panic_state=abort ;;
        panic=unwind) panic_state=unwind ;;
        opt-level=*) opt_state=${1#opt-level=} ;;
        codegen-units=*) cgu_state=${1#codegen-units=} ;;
        debug-assertions=on|debug-assertions=yes|debug-assertions=true)
            dbgassert_state=on ;;
        debug-assertions=off|debug-assertions=no|debug-assertions=false)
            dbgassert_state=off ;;
        debug-assertions) dbgassert_state=on ;;
    esac
}

for argument in "$@"; do
    if [ "$previous" = crate-name ]; then
        crate_name=$argument
        previous=
        continue
    fi
    if [ "$previous" = codegen ]; then
        classify "$argument"
        previous=
        continue
    fi
    case "$argument" in
        --crate-name) previous=crate-name ;;
        --crate-name=*) crate_name=${argument#--crate-name=} ;;
        -C) previous=codegen ;;
        -C*) classify "${argument#-C}" ;;
    esac
done

case "$crate_name" in
    crypto_bigint|ed301_eddsa|ed301_eddsa_draft00)
        printf 'overflow=%s panic=%s opt=%s cgu=%s dbgassert=%s\n' \
            "$overflow_state" "$panic_state" "$opt_state" "$cgu_state" \
            "$dbgassert_state" \
            >>"$ED301_PROFILE_MARKER_DIR/$crate_name"
        printf '%s: %s\n' "$crate_name" "$*" \
            >>"$ED301_PROFILE_MARKER_DIR/rustc_invocations.log"
        ;;
esac

exec "$@"
