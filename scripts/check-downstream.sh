#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
FIXTURE=$ROOT/integration/downstream-workspace

if [ -z "${CARGO_HOME:-}" ]; then
    echo "check-downstream.sh requires CARGO_HOME to be set by the invoking gate" >&2
    exit 2
fi

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
export RUSTC_WRAPPER=$FIXTURE/rustc-profile-guard.sh

cargo build --locked --offline --release --manifest-path "$FIXTURE/Cargo.toml"

crypto_marker=$ED301_PROFILE_MARKER_DIR/crypto_bigint
ed301_marker=$ED301_PROFILE_MARKER_DIR/ed301_eddsa
for marker in "$crypto_marker" "$ed301_marker"; do
    if [ ! -s "$marker" ]; then
        echo "missing rustc profile marker: $marker" >&2
        exit 1
    fi
done
if grep -qvE '^(off|absent)$' "$crypto_marker"; then
    echo "crypto_bigint unexpectedly enabled overflow checks:" >&2
    sed -n '1,20p' "$crypto_marker" >&2
    exit 1
fi
if grep -qvx on "$ed301_marker"; then
    echo "ed301_eddsa did not retain top-level overflow checks:" >&2
    sed -n '1,20p' "$ed301_marker" >&2
    exit 1
fi

unset RUSTC_WRAPPER
cargo fmt --manifest-path "$FIXTURE/Cargo.toml" -- --check
cargo clippy --locked --offline --release --manifest-path "$FIXTURE/Cargo.toml" --all-targets -- -D warnings
cargo test --locked --offline --release --manifest-path "$FIXTURE/Cargo.toml"
cargo run --locked --offline --release --manifest-path "$FIXTURE/Cargo.toml"
