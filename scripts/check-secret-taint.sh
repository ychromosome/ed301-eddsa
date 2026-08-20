#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
for tool in cargo valgrind; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing required tool: $tool" >&2
        exit 127
    }
done

cleanup_home=0
cleanup_target=0
cleanup() {
    if [ "$cleanup_target" -eq 1 ]; then
        rm -rf -- "$CARGO_TARGET_DIR"
    fi
    if [ "$cleanup_home" -eq 1 ]; then
        rm -rf -- "$CARGO_HOME"
    fi
}
trap cleanup EXIT HUP INT TERM

case "${ED301_USE_CALLER_CARGO_HOME:-0}" in
    0)
        CARGO_HOME=$(mktemp -d "${TMPDIR:-/tmp}/ed301-rust-r2-taint-cargo-home.XXXXXX")
        cleanup_home=1
        ;;
    1)
        if [ -z "${CARGO_HOME:-}" ]; then
            echo "ED301_USE_CALLER_CARGO_HOME=1 requires an explicit CARGO_HOME" >&2
            exit 2
        fi
        echo "warning: using caller CARGO_HOME; this is not the isolated review gate" >&2
        ;;
    *)
        echo "ED301_USE_CALLER_CARGO_HOME must be 0 or 1" >&2
        exit 2
        ;;
esac

case "${ED301_USE_CALLER_CARGO_TARGET_DIR:-0}" in
    0)
        CARGO_TARGET_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ed301-rust-r2-taint.XXXXXX")
        cleanup_target=1
        ;;
    1)
        if [ -z "${CARGO_TARGET_DIR:-}" ]; then
            echo "ED301_USE_CALLER_CARGO_TARGET_DIR=1 requires an explicit CARGO_TARGET_DIR" >&2
            exit 2
        fi
        echo "warning: using caller CARGO_TARGET_DIR; this is not the isolated review gate" >&2
        ;;
    *)
        echo "ED301_USE_CALLER_CARGO_TARGET_DIR must be 0 or 1" >&2
        exit 2
        ;;
esac

export CARGO_HOME
export CARGO_TARGET_DIR
export CARGO_NET_OFFLINE=true
export CARGO_INCREMENTAL=0
export CCACHE_DISABLE=1

cd "$ROOT/secret-taint"
cargo build --locked --offline --release

export ED301_CT_SECRET_HEX=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425
export ED301_CT_EXPECTED_PUBLIC_HEX=8cad07b4f9a308523a8df9bee22a721b8ff5e597c1ce47e39df67f97a475fd018013fc188890
export ED301_CT_EXPECTED_SIGNATURE_HEX=2964a4e22d5ed6e41ad5d5bbfdf4d518bb067b8982f3f8f5900d074a6bee97567b95810336944dfdce74dd889ee9d9db3c10bd1f9da0799bad501c8f3e9260020ad64fa6b02a8c27ce837d00

for mode in defined tainted; do
    for case_name in public sign; do
        valgrind \
            --tool=memcheck \
            --vgdb=no \
            --error-exitcode=99 \
            --track-origins=yes \
            --undef-value-errors=yes \
            --leak-check=full \
            --errors-for-leak-kinds=definite,indirect,possible \
            --quiet \
            "$CARGO_TARGET_DIR/release/ed301-eddsa-secret-taint" \
            "--case=$case_name" "--mode=$mode"
    done
done
