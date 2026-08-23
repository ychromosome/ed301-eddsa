#!/bin/sh
set -eu

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <marker-directory> <crate=on|off>..." >&2
    exit 2
fi

MARKERS=$1
shift
test -d "$MARKERS" || {
    echo "missing profile marker directory: $MARKERS" >&2
    exit 1
}

for expectation in "$@"; do
    crate=${expectation%%=*}
    expected=${expectation#*=}
    case "$crate" in
        ''|*[!A-Za-z0-9_]*)
            echo "invalid profile expectation: $expectation" >&2
            exit 2
            ;;
    esac
    case "$expected" in
        on|off) ;;
        *)
            echo "invalid profile expectation: $expectation" >&2
            exit 2
            ;;
    esac
    marker=$MARKERS/$crate
    if [ ! -s "$marker" ]; then
        echo "missing rustc profile marker: $marker" >&2
        exit 1
    fi
    if grep -qvE \
            "^overflow=$expected panic=unwind opt=3 cgu=1 dbgassert=off enforced=yes$" \
            "$marker"; then
        echo "invalid effective profile for $crate:" >&2
        sed -n '1,20p' "$marker" >&2
        exit 1
    fi
done

test -s "$MARKERS/rustc_invocations.log" || {
    echo "missing complete rustc invocation log" >&2
    exit 1
}
test -s "$MARKERS/toolchain.txt" || {
    echo "missing bound Rust toolchain identity" >&2
    exit 1
}

printf 'rust_profile_verification=PASS markers=%s\n' "$MARKERS"
