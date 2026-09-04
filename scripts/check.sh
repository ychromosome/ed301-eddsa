#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
sh "$ROOT/scripts/check-rust-build-environment.sh"
sh "$ROOT/scripts/require-verified-snapshot.sh"

WORK=$(mktemp -d /tmp/ed301-core-gate.XXXXXX)
HOME_DIR=$WORK/home
CARGO_HOME_DIR=$WORK/cargo-home
TARGET_DIR=$WORK/target
MARKERS=$WORK/profile-markers
mkdir -m 700 "$HOME_DIR" "$CARGO_HOME_DIR" "$TARGET_DIR" "$MARKERS"
/usr/bin/python3 -I -B "$ROOT/scripts/write-cargo-config.py" \
    "$CARGO_HOME_DIR/config.toml" "$ROOT/vendor"
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
/usr/bin/python3 -I -B "$ROOT/scripts/check-vendor-forks.py"
# This regression test materializes many intentionally corrupted snapshots.
# Keep that copy-heavy work off small tmpfs mounts.
TMPDIR=/var/tmp sh "$ROOT/scripts/test-source-tree-gate.sh"
sh "$ROOT/scripts/test-build-input-hardening.sh"
sh "$ROOT/scripts/test-rustc-profile-guard.sh"
sh "$ROOT/scripts/check-blind-reference.sh"
/usr/bin/bash -n "$ROOT/scripts/run-performance-receipt.sh"
/usr/bin/python3 -I -B -c \
    'import pathlib; p = pathlib.Path(__import__("sys").argv[1]); compile(p.read_bytes(), str(p), "exec")' \
    "$ROOT/performance/summarize.py"
printf 'round\tposition\talgorithm\toperation\tcount\tmean_ns\tlog\n1\ttarget\tEd301\texpand\t1\t10\ta\n1\ttarget\tEd301\tsign\t1\t20\tb\n1\ttarget\tEd301\tverify\t1\t30\tc\n1\ttarget\tEd301\timport\t1\t40\td\n1\tpre\tED25519\tkeygen\t1\t5\te\n1\tpre\tED25519\tsign\t1\t10\tf\n1\tpre\tED25519\tverify\t1\t15\tg\n1\tpre\tED448\tkeygen\t1\t20\th\n1\tpre\tED448\tsign\t1\t40\ti\n1\tpre\tED448\tverify\t1\t60\tj\n' \
    >"$WORK/performance-fixture.tsv"
/usr/bin/python3 -I -B "$ROOT/performance/summarize.py" \
    "$WORK/performance-fixture.tsv" >"$WORK/performance-summary.txt"
grep -F 'Ed301/Ed25519=2.000000' "$WORK/performance-summary.txt" >/dev/null

clean_env /usr/bin/cargo --version --verbose
clean_env /usr/bin/rustc --version --verbose
clean_env /usr/bin/rustfmt --version
clean_env /usr/bin/cargo-clippy --version

cargo_clean metadata --manifest-path "$ROOT/Cargo.toml" \
    --locked --offline --format-version=1 >/dev/null
cargo_clean check --manifest-path "$ROOT/performance/ed301-bench/Cargo.toml" \
    --locked --offline
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

case "$(/usr/bin/uname -m)" in
    aarch64|arm64)
        CPUFEATURES_TEST_ROOT=$WORK/cpufeatures
        /usr/bin/cp -a -- "$ROOT/vendor/cpufeatures" \
            "$CPUFEATURES_TEST_ROOT"
        /usr/bin/chmod -R u+w -- "$CPUFEATURES_TEST_ROOT"
        /usr/bin/rm -f -- "$CPUFEATURES_TEST_ROOT/Cargo.lock"
        cargo_clean generate-lockfile \
            --manifest-path "$CPUFEATURES_TEST_ROOT/Cargo.toml" \
            --offline
        cargo_clean test \
            --manifest-path "$CPUFEATURES_TEST_ROOT/Cargo.toml" \
            --locked --offline
        ;;
esac

clean_env /usr/bin/rustc --version --verbose >"$MARKERS/toolchain.txt"
(cd / && env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    CARGO_HOME="$CARGO_HOME_DIR" CARGO_TARGET_DIR="$TARGET_DIR" \
    CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CCACHE_DISABLE=1 \
    ED301_PROFILE_MARKER_DIR="$MARKERS" \
    RUSTC_WRAPPER="$ROOT/scripts/rustc-profile-guard.sh" \
    /usr/bin/cargo test \
        --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        --release --workspace --all-targets)
(cd / && env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    CARGO_HOME="$CARGO_HOME_DIR" CARGO_TARGET_DIR="$TARGET_DIR" \
    CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CCACHE_DISABLE=1 \
    ED301_PROFILE_MARKER_DIR="$MARKERS" \
    RUSTC_WRAPPER="$ROOT/scripts/rustc-profile-guard.sh" \
    /usr/bin/cargo test \
        --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        --release --workspace --all-targets \
        --features sign-self-verify)
sh "$ROOT/scripts/check-profile-markers.sh" "$MARKERS" \
    crypto_bigint=on ed301_eddsa=on

(cd / && env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    CARGO_HOME="$CARGO_HOME_DIR" CARGO_TARGET_DIR="$TARGET_DIR" \
    CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CCACHE_DISABLE=1 \
    RUSTDOCFLAGS='-D warnings' \
    /usr/bin/cargo doc \
        --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        --workspace --no-deps)

sh "$ROOT/scripts/check-downstream.sh"
sh "$ROOT/scripts/require-verified-snapshot.sh"
