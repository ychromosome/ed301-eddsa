#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
REMAP_SOURCE=/usr/src/ed301-eddsa

if [ "$#" -lt 1 ] || [ -z "${ED301_PROFILE_MARKER_DIR:-}" ]; then
    echo "rustc-profile-guard: compiler or marker directory missing" >&2
    exit 2
fi
if [ -n "${ED301_PROFILE_EXCEPTIONS:-}" ]; then
    echo "rustc-profile-guard: overflow-check exceptions are forbidden" >&2
    exit 2
fi

compiler=$1
shift
case "$compiler" in
    rustc) compiler_selected=$(command -v rustc) ;;
    */*) compiler_selected=$compiler ;;
    *)
        echo "rustc-profile-guard: unsupported compiler selector" >&2
        exit 1
        ;;
esac
compiler_real=$(readlink -f -- "$compiler_selected")
trusted_rustc=$(readlink -f -- /usr/bin/rustc)
if [ "$compiler_real" != "$trusted_rustc" ]; then
    echo "rustc-profile-guard: compiler is not canonical /usr/bin/rustc" >&2
    exit 1
fi
test -d "$ED301_PROFILE_MARKER_DIR" \
    && test ! -L "$ED301_PROFILE_MARKER_DIR" || {
    echo "rustc-profile-guard: unsafe marker directory" >&2
    exit 2
}

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

record_success() {
    kind=$1
    shift
    marker=$(mktemp "$ED301_PROFILE_MARKER_DIR/invocation.XXXXXX")
    printf 'kind=%s %s\n' "$kind" "$*" >"$marker"
    mv -- "$marker" "$marker.success"
}

if [ -z "$crate_name" ]; then
    "$compiler_selected" "$@"
    record_success probe compiler="$compiler_real"
    exit 0
fi
case "$crate_name" in
    *[!A-Za-z0-9_]*|"")
        echo "rustc-profile-guard: unsafe crate name" >&2
        exit 2
        ;;
esac

if [ "$crate_name" = build_script_build ]; then
    "$compiler_selected" "$@" --remap-path-prefix "$ROOT=$REMAP_SOURCE"
    record_success host crate="$crate_name"
    exit 0
fi

expected_overflow=on

if [ "$overflow_state" != absent ] \
        && [ "$overflow_state" != "$expected_overflow" ]; then
    echo "rustc-profile-guard: $crate_name overflow=$overflow_state, expected $expected_overflow" >&2
    exit 1
fi
if [ "$panic_state" != absent ] && [ "$panic_state" != unwind ]; then
    echo "rustc-profile-guard: $crate_name panic=$panic_state, expected unwind" >&2
    exit 1
fi
if [ "$opt_state" != absent ] && [ "$opt_state" != 3 ]; then
    echo "rustc-profile-guard: $crate_name opt=$opt_state, expected 3" >&2
    exit 1
fi
if [ "$cgu_state" != absent ] && [ "$cgu_state" != 1 ]; then
    echo "rustc-profile-guard: $crate_name cgu=$cgu_state, expected 1" >&2
    exit 1
fi
if [ "$dbgassert_state" != absent ] && [ "$dbgassert_state" != off ]; then
    echo "rustc-profile-guard: $crate_name debug-assertions=$dbgassert_state, expected off" >&2
    exit 1
fi

"$compiler_selected" "$@" "-Coverflow-checks=$expected_overflow" \
    -Cpanic=unwind -Copt-level=3 -Ccodegen-units=1 \
    -Cdebug-assertions=off --remap-path-prefix "$ROOT=$REMAP_SOURCE"
record_success target crate="$crate_name" overflow="$expected_overflow" \
    panic=unwind opt=3 cgu=1 dbgassert=off enforced=yes
