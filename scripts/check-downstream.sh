#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
FIXTURE=$ROOT/integration/downstream-workspace
sh "$ROOT/scripts/require-verified-snapshot.sh"
sh "$ROOT/scripts/check-rust-build-environment.sh"
case "$ROOT" in
    *"'"*) echo "source snapshot path may not contain an apostrophe" >&2; exit 2 ;;
esac

WORK=$(mktemp -d /tmp/ed301-downstream-gate.XXXXXX)
HOME_DIR=$WORK/home
CARGO_HOME_DIR=$WORK/cargo-home
ANALYSIS_TARGET_DIR=$WORK/analysis-target
TARGET_DIR=$WORK/target
MARKERS=$WORK/profile-markers
mkdir -m 700 "$HOME_DIR" "$CARGO_HOME_DIR" "$ANALYSIS_TARGET_DIR" \
    "$TARGET_DIR" "$MARKERS"
{
    printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' \
        '' '[source.vendored-sources]'
    printf "directory = '%s'\n" "$ROOT/vendor"
    printf '%s\n' '' '[net]' 'offline = true'
} >"$CARGO_HOME_DIR/config.toml"
chmod 600 "$CARGO_HOME_DIR/config.toml"
printf 'cargo_config_sha256=%s\n' \
    "$(sha256sum "$CARGO_HOME_DIR/config.toml" | awk '{print $1}')"
cleanup() {
    rm -rf -- "$WORK"
}
trap cleanup EXIT HUP INT TERM

run_cargo() {
    (cd / && env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
        CARGO_HOME="$CARGO_HOME_DIR" \
        CARGO_TARGET_DIR="$ANALYSIS_TARGET_DIR" \
        CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CCACHE_DISABLE=1 \
        /usr/bin/cargo "$@")
}
run_guarded_cargo() {
    (cd / && env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
        CARGO_HOME="$CARGO_HOME_DIR" CARGO_TARGET_DIR="$TARGET_DIR" \
        CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CCACHE_DISABLE=1 \
        ED301_PROFILE_MARKER_DIR="$MARKERS" \
        ED301_PROFILE_EXCEPTIONS=crypto_bigint=off \
        RUSTC_WRAPPER="$ROOT/scripts/rustc-profile-guard.sh" \
        /usr/bin/cargo "$@")
}

env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    /usr/bin/rustc --version --verbose >"$MARKERS/toolchain.txt"
run_guarded_cargo build --manifest-path "$FIXTURE/Cargo.toml" \
    --locked --offline --release
run_cargo fmt --manifest-path "$FIXTURE/Cargo.toml" -- --check
run_cargo clippy --manifest-path "$FIXTURE/Cargo.toml" \
    --locked --offline --release --all-targets -- -D warnings
run_guarded_cargo test --manifest-path "$FIXTURE/Cargo.toml" \
    --locked --offline --release
run_guarded_cargo run --manifest-path "$FIXTURE/Cargo.toml" \
    --locked --offline --release
sh "$ROOT/scripts/check-profile-markers.sh" "$MARKERS" \
    crypto_bigint=off ed301_eddsa=on ed301_eddsa_downstream_check=on
sh "$ROOT/scripts/require-verified-snapshot.sh"
