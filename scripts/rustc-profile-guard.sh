#!/bin/sh
set -eu

if [ "$#" -lt 1 ]; then
    echo "rustc-profile-guard: missing rustc command" >&2
    exit 2
fi
if [ -z "${ED301_PROFILE_MARKER_DIR:-}" ]; then
    echo "rustc-profile-guard: ED301_PROFILE_MARKER_DIR is unset" >&2
    exit 2
fi
if [ -z "${ED301_PROFILE_EXPECTATIONS:-}" ]; then
    echo "rustc-profile-guard: ED301_PROFILE_EXPECTATIONS is unset" >&2
    exit 2
fi

crate_name=
overflow_state=absent
panic_state=absent
opt_state=absent
cgu_state=absent
dbgassert_state=absent
previous=

classify_boolean() {
    case "$2" in
        on|yes|true|1) eval "$1=on" ;;
        off|no|false|0) eval "$1=off" ;;
        *) eval "$1=invalid" ;;
    esac
}

classify_codegen() {
    case "$1" in
        overflow-checks=*)
            classify_boolean overflow_state "${1#overflow-checks=}" ;;
        panic=abort) panic_state=abort ;;
        panic=unwind) panic_state=unwind ;;
        panic=*) panic_state=invalid ;;
        opt-level=*) opt_state=${1#opt-level=} ;;
        codegen-units=*) cgu_state=${1#codegen-units=} ;;
        debug-assertions=*)
            classify_boolean dbgassert_state "${1#debug-assertions=}" ;;
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
        classify_codegen "$argument"
        previous=
        continue
    fi
    case "$argument" in
        --crate-name) previous=crate-name ;;
        --crate-name=*) crate_name=${argument#--crate-name=} ;;
        -C) previous=codegen ;;
        -C*) classify_codegen "${argument#-C}" ;;
    esac
done

expected_overflow=
for expectation in $ED301_PROFILE_EXPECTATIONS; do
    expected_crate=${expectation%%=*}
    expected_value=${expectation#*=}
    if [ "$expected_crate" = "$crate_name" ]; then
        if [ "$expected_value" != on ] && [ "$expected_value" != off ]; then
            echo "rustc-profile-guard: invalid expectation: $expectation" >&2
            exit 2
        fi
        expected_overflow=$expected_value
        break
    fi
done

if [ -z "$expected_overflow" ]; then
    exec "$@"
fi

case "$crate_name" in
    *[!A-Za-z0-9_]*)
        echo "rustc-profile-guard: unsafe tracked crate name" >&2
        exit 2
        ;;
esac

if [ "$overflow_state" != absent ] && [ "$overflow_state" != "$expected_overflow" ]; then
    echo "rustc-profile-guard: $crate_name overflow=$overflow_state, expected $expected_overflow" >&2
    exit 1
fi
if [ "$panic_state" != absent ] && [ "$panic_state" != unwind ]; then
    echo "rustc-profile-guard: $crate_name panic=$panic_state, expected unwind" >&2
    exit 1
fi
if [ "$opt_state" != 3 ]; then
    echo "rustc-profile-guard: $crate_name opt=$opt_state, expected 3" >&2
    exit 1
fi
if [ "$cgu_state" != 1 ]; then
    echo "rustc-profile-guard: $crate_name cgu=$cgu_state, expected 1" >&2
    exit 1
fi
if [ "$dbgassert_state" != absent ] && [ "$dbgassert_state" != off ]; then
    echo "rustc-profile-guard: $crate_name debug-assertions=$dbgassert_state, expected off" >&2
    exit 1
fi

# Cargo omits flags whose effective value is the rustc default (notably
# panic=unwind for dependencies).  Append every security-relevant value to the
# real compiler invocation so the marker attests enforced code generation, not
# merely the presence or absence of a Cargo command-line spelling.  Explicitly
# conflicting values were rejected above; the final flags also dominate any
# opaque earlier argument source supported by rustc.
mkdir -p "$ED301_PROFILE_MARKER_DIR"
printf 'overflow=%s panic=unwind opt=3 cgu=1 dbgassert=off enforced=yes\n' \
    "$expected_overflow" \
    >>"$ED301_PROFILE_MARKER_DIR/$crate_name"
{
    printf '%s:' "$crate_name"
    for argument in "$@"; do
        printf ' [%s]' "$argument"
    done
    printf ' [-Coverflow-checks=%s]' "$expected_overflow"
    printf ' [-Cpanic=unwind]'
    printf ' [-Copt-level=3]'
    printf ' [-Ccodegen-units=1]'
    printf ' [-Cdebug-assertions=off]'
    printf '\n'
} >>"$ED301_PROFILE_MARKER_DIR/rustc_invocations.log"

exec "$@" "-Coverflow-checks=$expected_overflow" -Cpanic=unwind \
    -Copt-level=3 -Ccodegen-units=1 -Cdebug-assertions=off
