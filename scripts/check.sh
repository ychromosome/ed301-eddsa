#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
sh "$ROOT/scripts/require-verified-snapshot.sh"
sh "$ROOT/scripts/check-rust-build-environment.sh"
case "$ROOT" in
    *"'"*) echo "source snapshot path may not contain an apostrophe" >&2; exit 2 ;;
esac

WORK=$(mktemp -d /tmp/ed301-core-gate.XXXXXX)
HOME_DIR=$WORK/home
CARGO_HOME_DIR=$WORK/cargo-home
TARGET_DIR=$WORK/target
MARKERS=$WORK/profile-markers
mkdir -m 700 "$HOME_DIR" "$CARGO_HOME_DIR" "$TARGET_DIR" "$MARKERS"
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

clean_env() {
    env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
        CARGO_HOME="$CARGO_HOME_DIR" CARGO_TARGET_DIR="$TARGET_DIR" \
        CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CCACHE_DISABLE=1 \
        "$@"
}
cargo_clean() {
    (cd / && clean_env /usr/bin/cargo "$@")
}

(cd "$ROOT/inputs/round4" && sha256sum --strict --quiet -c SHA256SUMS)
sh "$ROOT/scripts/test-source-tree-gate.sh"
sh "$ROOT/scripts/test-rustc-profile-guard.sh"

clean_env /usr/bin/cargo --version --verbose
clean_env /usr/bin/rustc --version --verbose
clean_env /usr/bin/rustfmt --version
clean_env /usr/bin/cargo-clippy --version

cargo_clean metadata --manifest-path "$ROOT/Cargo.toml" \
    --locked --offline --format-version=1 >/dev/null
cargo_clean fmt --manifest-path "$ROOT/Cargo.toml" --all -- --check
cargo_clean clippy --manifest-path "$ROOT/Cargo.toml" \
    --locked --offline --workspace --all-targets -- -D warnings
cargo_clean clippy --manifest-path "$ROOT/Cargo.toml" \
    --locked --offline --workspace --all-targets \
    --features sign-self-verify -- -D warnings
cargo_clean test --manifest-path "$ROOT/Cargo.toml" \
    --locked --offline --workspace --all-targets
cargo_clean test --manifest-path "$ROOT/Cargo.toml" \
    --locked --offline --workspace --all-targets \
    --features sign-self-verify

clean_env /usr/bin/rustc --version --verbose >"$MARKERS/toolchain.txt"
(cd / && env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    CARGO_HOME="$CARGO_HOME_DIR" CARGO_TARGET_DIR="$TARGET_DIR" \
    CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CCACHE_DISABLE=1 \
    ED301_PROFILE_MARKER_DIR="$MARKERS" \
    ED301_PROFILE_EXCEPTIONS=crypto_bigint=off \
    RUSTC_WRAPPER="$ROOT/scripts/rustc-profile-guard.sh" \
    /usr/bin/cargo test \
        --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        --release --workspace --all-targets)
(cd / && env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    CARGO_HOME="$CARGO_HOME_DIR" CARGO_TARGET_DIR="$TARGET_DIR" \
    CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CCACHE_DISABLE=1 \
    ED301_PROFILE_MARKER_DIR="$MARKERS" \
    ED301_PROFILE_EXCEPTIONS=crypto_bigint=off \
    RUSTC_WRAPPER="$ROOT/scripts/rustc-profile-guard.sh" \
    /usr/bin/cargo test \
        --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        --release --workspace --all-targets \
        --features sign-self-verify)
sh "$ROOT/scripts/check-profile-markers.sh" "$MARKERS" \
    crypto_bigint=off ed301_eddsa=on

(cd / && env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    CARGO_HOME="$CARGO_HOME_DIR" CARGO_TARGET_DIR="$TARGET_DIR" \
    CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CCACHE_DISABLE=1 \
    RUSTDOCFLAGS='-D warnings' \
    /usr/bin/cargo doc \
        --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        --workspace --no-deps)

sh "$ROOT/scripts/check-downstream.sh"
sh "$ROOT/scripts/require-verified-snapshot.sh"
