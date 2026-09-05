#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <marker-directory> <required-crate=on|off>..." >&2
    exit 2
fi

MARKERS=$1
shift
test -d "$MARKERS" && test ! -L "$MARKERS" || {
    echo "unsafe profile marker directory: $MARKERS" >&2
    exit 1
}
test -s "$MARKERS/toolchain.txt" || {
    echo "missing bound Rust toolchain identity" >&2
    exit 1
}

target_count=0
for marker in "$MARKERS"/invocation.*.success; do
    test -f "$marker" || continue
    line=$(sed -n '1p' "$marker")
    case "$line" in
        kind=probe\ compiler=*|kind=host\ crate=build_script_build) ;;
        kind=target\ crate=*)
            if ! printf '%s\n' "$line" | grep -Eq \
                    '^kind=target crate=[A-Za-z0-9_]+ overflow=(on|off) panic=unwind opt=3 cgu=1 dbgassert=off enforced=yes$'; then
                echo "invalid successful rustc attestation: $marker" >&2
                exit 1
            fi
            crate=$(printf '%s\n' "$line" \
                | sed -n 's/^kind=target crate=\([A-Za-z0-9_]*\) .*/\1/p')
            actual=$(printf '%s\n' "$line" \
                | sed -n 's/.* overflow=\(on\|off\) .*/\1/p')
            expected=on
            for requirement in "$@"; do
                if [ "${requirement%%=*}" = "$crate" ]; then
                    expected=${requirement#*=}
                fi
            done
            [ "$actual" = "$expected" ] || {
                echo "$crate overflow=$actual, expected $expected" >&2
                exit 1
            }
            target_count=$((target_count + 1))
            ;;
        *)
            echo "unknown successful rustc attestation: $marker" >&2
            exit 1
            ;;
    esac
done
[ "$target_count" -gt 0 ] || {
    echo "no guarded target rustc invocation was recorded" >&2
    exit 1
}

for requirement in "$@"; do
    crate=${requirement%%=*}
    expected=${requirement#*=}
    case "$crate:$expected" in
        *[!A-Za-z0-9_:]*|:*)
            echo "invalid profile requirement: $requirement" >&2
            exit 2
            ;;
        *:on|*:off) ;;
        *)
            echo "invalid profile requirement: $requirement" >&2
            exit 2
            ;;
    esac
    grep -lEq \
        "^kind=target crate=$crate overflow=$expected panic=unwind opt=3 cgu=1 dbgassert=off enforced=yes$" \
        "$MARKERS"/invocation.*.success >/dev/null 2>&1 || {
        echo "missing guarded successful rustc invocation: $requirement" >&2
        exit 1
    }
done

printf 'rust_profile_verification=PASS targets=%s markers=%s\n' \
    "$target_count" "$MARKERS"
