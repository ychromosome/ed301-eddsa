#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

for tool in sha256sum cargo rustc rustfmt cargo-clippy; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing required tool: $tool" >&2
        exit 127
    }
done

(cd "$ROOT" && sha256sum --strict --quiet -c SOURCE_MANIFEST.sha256)
(cd "$ROOT/inputs/round4" && sha256sum --strict --quiet -c SHA256SUMS)

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
        CARGO_HOME=$(mktemp -d "${TMPDIR:-/tmp}/ed301-rust-r2-cargo-home.XXXXXX")
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
        CARGO_TARGET_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ed301-rust-r2-target.XXXXXX")
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

cargo --version --verbose
rustc --version --verbose
rustfmt --version
cargo clippy --version

cd "$ROOT"
cargo metadata --locked --offline --format-version=1 >/dev/null
cargo fmt --all -- --check
cargo clippy --locked --offline --workspace --all-targets -- -D warnings
cargo test --locked --offline --workspace --all-targets
cargo test --locked --offline --release --workspace --all-targets
RUSTDOCFLAGS="-D warnings" cargo doc --locked --offline --workspace --no-deps
sh "$ROOT/scripts/check-downstream.sh"
