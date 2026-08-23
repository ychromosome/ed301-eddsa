#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
FIXTURE=$ROOT/integration/downstream-workspace

if [ -z "${CARGO_HOME:-}" ]; then
    echo "check-downstream.sh requires CARGO_HOME to be set by the invoking gate" >&2
    exit 2
fi

sh "$ROOT/scripts/verify-source-tree.sh"
sh "$ROOT/scripts/check-rust-build-environment.sh"

DOWNSTREAM_TARGET_DIR=
ED301_PROFILE_MARKER_DIR=
cleanup() {
    if [ -n "$DOWNSTREAM_TARGET_DIR" ]; then
        rm -rf -- "$DOWNSTREAM_TARGET_DIR"
    fi
    if [ -n "$ED301_PROFILE_MARKER_DIR" ]; then
        rm -rf -- "$ED301_PROFILE_MARKER_DIR"
    fi
}
trap cleanup EXIT HUP INT TERM

DOWNSTREAM_TARGET_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ed301-rust-r2-downstream-target.XXXXXX")
ED301_PROFILE_MARKER_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ed301-rust-r2-profile-markers.XXXXXX")

export CARGO_TARGET_DIR=$DOWNSTREAM_TARGET_DIR
export ED301_PROFILE_MARKER_DIR
export ED301_PROFILE_EXPECTATIONS='crypto_bigint=off ed301_eddsa=on ed301_eddsa_downstream_check=on'
export RUSTC_WRAPPER=$ROOT/scripts/rustc-profile-guard.sh

{
    command -v rustc
    rustc --version --verbose
} >"$ED301_PROFILE_MARKER_DIR/toolchain.txt"

cargo build --locked --offline --release --manifest-path "$FIXTURE/Cargo.toml"
cargo fmt --manifest-path "$FIXTURE/Cargo.toml" -- --check
cargo clippy --locked --offline --release --manifest-path "$FIXTURE/Cargo.toml" --all-targets -- -D warnings
cargo test --locked --offline --release --manifest-path "$FIXTURE/Cargo.toml"
cargo run --locked --offline --release --manifest-path "$FIXTURE/Cargo.toml"
sh "$ROOT/scripts/check-profile-markers.sh" "$ED301_PROFILE_MARKER_DIR" \
    crypto_bigint=off ed301_eddsa=on ed301_eddsa_downstream_check=on
