#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
GUARD=$ROOT/scripts/rustc-profile-guard.sh
ENV_GUARD=$ROOT/scripts/check-rust-build-environment.sh
TMP=$(mktemp -d "${TMPDIR:-/tmp}/ed301-profile-guard-test.XXXXXX")
cleanup() {
    rm -rf -- "$TMP"
}
trap cleanup EXIT HUP INT TERM

FAKE=$TMP/fake-rustc
cat >"$FAKE" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" >>"$FAKE_RUSTC_LOG"
EOF
chmod +x "$FAKE"

case_index=0
run_pass() {
    expected=$1
    crate=$2
    shift 2
    case_index=$((case_index + 1))
    markers=$TMP/pass-$case_index
    mkdir -p "$markers"
    FAKE_RUSTC_LOG=$markers/fake.log \
    ED301_PROFILE_MARKER_DIR=$markers \
    ED301_PROFILE_EXPECTATIONS="$crate=$expected" \
        sh "$GUARD" "$FAKE" --crate-name "$crate" "$@"
    grep -Eq "^overflow=$expected panic=unwind opt=3 cgu=1 dbgassert=off " \
        "$markers/$crate"
}

run_fail() {
    expected=$1
    crate=$2
    shift 2
    case_index=$((case_index + 1))
    markers=$TMP/fail-$case_index
    mkdir -p "$markers"
    if FAKE_RUSTC_LOG=$markers/fake.log \
       ED301_PROFILE_MARKER_DIR=$markers \
       ED301_PROFILE_EXPECTATIONS="$crate=$expected" \
           sh "$GUARD" "$FAKE" --crate-name "$crate" "$@" \
               >"$markers/output.log" 2>&1; then
        echo "profile guard accepted unsafe case $case_index" >&2
        exit 1
    fi
    test ! -e "$markers/fake.log"
}

for value in on yes true 1; do
    run_pass on ed301_eddsa "-Coverflow-checks=$value" \
        -Cpanic=unwind -Copt-level=3 -Ccodegen-units=1
done
for value in off no false 0; do
    run_pass off crypto_bigint -C "overflow-checks=$value" \
        -C panic=unwind -C opt-level=3 -C codegen-units=1
done

run_pass off crypto_bigint -Coverflow-checks=yes -C overflow-checks=no \
    -Cpanic=unwind -Copt-level=3 -Ccodegen-units=1
run_fail off crypto_bigint -Coverflow-checks=no -Coverflow-checks=yes \
    -Cpanic=unwind -Copt-level=3 -Ccodegen-units=1

run_pass off crypto_bigint -Cpanic=unwind -Copt-level=3 \
    -Ccodegen-units=1
grep -Fx -- '-Coverflow-checks=off' "$TMP/pass-$case_index/fake.log" \
    >/dev/null
grep -Fx -- '-Cpanic=unwind' "$TMP/pass-$case_index/fake.log" \
    >/dev/null
grep -Fx -- '-Copt-level=3' "$TMP/pass-$case_index/fake.log" \
    >/dev/null
grep -Fx -- '-Ccodegen-units=1' "$TMP/pass-$case_index/fake.log" \
    >/dev/null
grep -Fx -- '-Cdebug-assertions=off' "$TMP/pass-$case_index/fake.log" \
    >/dev/null

run_fail on ed301_eddsa -Coverflow-checks=off -Cpanic=unwind \
    -Copt-level=3 -Ccodegen-units=1
run_fail on ed301_eddsa -Coverflow-checks=on -Cpanic=abort \
    -Copt-level=3 -Ccodegen-units=1
run_pass on ed301_eddsa -Coverflow-checks=on \
    -Copt-level=3 -Ccodegen-units=1
run_fail on ed301_eddsa -Coverflow-checks=on -Cpanic=unexpected \
    -Copt-level=3 -Ccodegen-units=1
run_fail on ed301_eddsa -Coverflow-checks=maybe -Cpanic=unwind \
    -Copt-level=3 -Ccodegen-units=1
run_fail on ed301_eddsa -Coverflow-checks=on -Cpanic=unwind \
    -Copt-level=2 -Ccodegen-units=1
run_fail on ed301_eddsa -Coverflow-checks=on -Cpanic=unwind \
    -Copt-level=3 -Ccodegen-units=2
run_fail on ed301_eddsa -Coverflow-checks=on -Cpanic=unwind \
    -Copt-level=3 -Ccodegen-units=1 -Cdebug-assertions=yes

sh "$ENV_GUARD" >/dev/null
env_case_count=0
for name in RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC RUSTC_WRAPPER \
        RUSTC_WORKSPACE_WRAPPER CARGO_PROFILE_RELEASE_PANIC \
        CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS \
        CARGO_PROFILE_RELEASE_CODEGEN_UNITS \
        CARGO_PROFILE_RELEASE_OPT_LEVEL \
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS \
        CARGO_BUILD_RUSTFLAGS CARGO_BUILD_RUSTC \
        CARGO_BUILD_RUSTC_WRAPPER \
        CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER; do
    env_case_count=$((env_case_count + 1))
    if env "$name=unsafe" sh "$ENV_GUARD" >/dev/null 2>&1; then
        echo "environment guard accepted override: $name" >&2
        exit 1
    fi
done

printf 'rustc_profile_guard_regressions=PASS parser_cases=%s env_cases=%s\n' \
    "$case_index" "$env_case_count"
