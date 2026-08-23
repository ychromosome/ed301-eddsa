#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
GUARD=$ROOT/scripts/rustc-profile-guard.sh
CHECK=$ROOT/scripts/check-profile-markers.sh
ENV_GUARD=$ROOT/scripts/check-rust-build-environment.sh
TMP=$(mktemp -d /tmp/ed301-profile-guard-test.XXXXXX)
cleanup() {
    rm -rf -- "$TMP"
}
trap cleanup EXIT HUP INT TERM

printf '%s\n' '#![no_std]' >"$TMP/valid.rs"
printf '%s\n' 'this is not Rust' >"$TMP/invalid.rs"

run_pass() {
    crate=$1
    exceptions=$2
    shift 2
    markers=$TMP/pass-$crate-$$
    mkdir -p "$markers"
    ED301_PROFILE_MARKER_DIR=$markers \
    ED301_PROFILE_EXCEPTIONS=$exceptions \
        sh "$GUARD" /usr/bin/rustc --crate-name "$crate" \
            --crate-type lib "$TMP/valid.rs" \
            --emit metadata -o "$markers/$crate.rmeta" "$@"
    printf '%s\n' /usr/bin/rustc >"$markers/toolchain.txt"
    sh "$CHECK" "$markers" "$crate=${exceptions#*=}"
}

run_fail() {
    crate=$1
    exceptions=$2
    shift 2
    markers=$TMP/fail-$crate-$$
    mkdir -p "$markers"
    if ED301_PROFILE_MARKER_DIR=$markers \
       ED301_PROFILE_EXCEPTIONS=$exceptions \
            sh "$GUARD" /usr/bin/rustc --crate-name "$crate" \
                --crate-type lib "$TMP/valid.rs" \
                --emit metadata -o "$markers/$crate.rmeta" "$@" \
                >"$markers/output.log" 2>&1; then
        echo "profile guard accepted an unsafe case for $crate" >&2
        exit 1
    fi
    if find "$markers" -name '*.success' -print -quit | grep -q .; then
        echo "failed compiler/profile case produced a success marker" >&2
        exit 1
    fi
}

run_pass ed301_eddsa ed301_eddsa=on -Coverflow-checks=on \
    -Cpanic=unwind -Copt-level=3 -Ccodegen-units=1
run_pass crypto_bigint crypto_bigint=off -Coverflow-checks=off \
    -Cpanic=unwind -Copt-level=3 -Ccodegen-units=1
run_fail ed301_eddsa ed301_eddsa=on -Coverflow-checks=off
run_fail ed301_eddsa ed301_eddsa=on -Cpanic=abort
run_fail ed301_eddsa ed301_eddsa=on -Copt-level=2
run_fail ed301_eddsa ed301_eddsa=on -Ccodegen-units=2
run_fail ed301_eddsa ed301_eddsa=on -Cdebug-assertions=yes

# An unlisted linked dependency receives the secure default, not a bypass.
markers=$TMP/default-dependency
mkdir -p "$markers"
ED301_PROFILE_MARKER_DIR=$markers ED301_PROFILE_EXCEPTIONS=crypto_bigint=off \
    sh "$GUARD" /usr/bin/rustc --crate-name dependency_crate \
        --crate-type lib "$TMP/valid.rs" --emit metadata \
        -o "$markers/dependency.rmeta"
printf '%s\n' /usr/bin/rustc >"$markers/toolchain.txt"
sh "$CHECK" "$markers" dependency_crate=on

# Cargo normally supplies the bare compiler name.  It must resolve through
# the gate's pinned PATH to the same canonical compiler.
markers=$TMP/bare-compiler
mkdir -p "$markers"
ED301_PROFILE_MARKER_DIR=$markers ED301_PROFILE_EXCEPTIONS= \
    sh "$GUARD" rustc --crate-name bare_compiler \
        --crate-type lib "$TMP/valid.rs" --emit metadata \
        -o "$markers/bare.rmeta"
printf '%s\n' /usr/bin/rustc >"$markers/toolchain.txt"
sh "$CHECK" "$markers" bare_compiler=on

# A compiler failure can never create successful profile evidence.
markers=$TMP/compiler-failure
mkdir -p "$markers"
if ED301_PROFILE_MARKER_DIR=$markers ED301_PROFILE_EXCEPTIONS= \
        sh "$GUARD" /usr/bin/rustc --crate-name invalid_crate \
            --crate-type lib "$TMP/invalid.rs" --emit metadata \
            -o "$markers/invalid.rmeta" >/dev/null 2>&1; then
    echo "invalid Rust unexpectedly compiled" >&2
    exit 1
fi
if find "$markers" -name '*.success' -print -quit | grep -q .; then
    echo "failed rustc invocation produced a success marker" >&2
    exit 1
fi

# A wrapper-selected executable cannot replace the canonical compiler.
printf '%s\n' '#!/bin/sh' 'exit 0' >"$TMP/fake-rustc"
chmod +x "$TMP/fake-rustc"
markers=$TMP/fake-compiler
mkdir -p "$markers"
if ED301_PROFILE_MARKER_DIR=$markers ED301_PROFILE_EXCEPTIONS= \
        sh "$GUARD" "$TMP/fake-rustc" --crate-name fake \
            "$TMP/valid.rs" >/dev/null 2>&1; then
    echo "profile guard accepted a noncanonical compiler" >&2
    exit 1
fi

sh "$ENV_GUARD" >/dev/null
env_case_count=0
for name in RUSTFLAGS CARGO_HOME CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER \
        CC CFLAGS AR LDFLAGS PYTHONPATH PYTHONSTARTUP LD_PRELOAD \
        OPENSSL_LIB_DIR TMPDIR; do
    env_case_count=$((env_case_count + 1))
    if env "$name=unsafe" sh "$ENV_GUARD" >/dev/null 2>&1; then
        echo "environment guard accepted override: $name" >&2
        exit 1
    fi
done

printf 'rustc_profile_guard_regressions=PASS profile_cases=11 env_cases=%s\n' \
    "$env_case_count"
