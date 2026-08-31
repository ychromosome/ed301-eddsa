#!/bin/bash
set -Eeuo pipefail

PATH=/usr/bin:/bin
export PATH LC_ALL=C
umask 077

if (( $# != 3 )); then
    printf 'usage: %s <sealed-lane-root> <3.5.7|4.0.1> <lane-evidence-sha256>\n' \
        "$0" >&2
    exit 2
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
LANE_ROOT_ARG=$1
LANE=$2
LANE_EVIDENCE=$3

sh "$ROOT/scripts/check-rust-build-environment.sh"
sh "$ROOT/scripts/require-verified-snapshot.sh"
verify_lane() {
    sh "$ROOT/scripts/verify-openssl-provider-lane.sh" \
        "$LANE_ROOT_ARG" "$LANE" "$LANE_EVIDENCE"
}
BUILD=$(mktemp -d "/tmp/ed301-provider-${LANE}.XXXXXX")
if ! sh "$ROOT/scripts/materialize-openssl-provider-lane.sh" \
        "$LANE_ROOT_ARG" "$LANE" "$LANE_EVIDENCE" \
        "$BUILD/openssl-lane"; then
    chmod -R u+w "$BUILD" 2>/dev/null || true
    rm -rf -- "$BUILD"
    exit 1
fi
LANE_ROOT_ARG=$BUILD/openssl-lane
verify_lane

LANE_ROOT=$(readlink -f -- "$LANE_ROOT_ARG")
OPENSSL_PREFIX=$LANE_ROOT/inst/$LANE
OPENSSL_LIB=$OPENSSL_PREFIX/lib
OPENSSL_BIN=$OPENSSL_PREFIX/bin/openssl
HOME_DIR=$BUILD/home
CARGO_HOME_DIR=$BUILD/cargo-home
mkdir -m 700 "$HOME_DIR" "$CARGO_HOME_DIR" "$BUILD/bin" \
    "$BUILD/modules" "$BUILD/fresh-modules" "$BUILD/evidence" \
    "$BUILD/generated" "$BUILD/targets" "$BUILD/profile-markers"
/usr/bin/python3 -I -B "$ROOT/scripts/write-cargo-config.py" \
    "$CARGO_HOME_DIR/config.toml" "$ROOT/vendor" panic-unwind

LOG=$BUILD/evidence/run.log
STATUS=$BUILD/evidence/status.txt
finish() {
    rc=$?
    if (( rc == 0 )); then
        printf 'PASS provider lane %s result=%s\n' "$LANE" "$BUILD" \
            | tee "$STATUS"
    else
        printf 'FAIL provider lane %s exit=%s result=%s\n' \
            "$LANE" "$rc" "$BUILD" | tee "$STATUS"
    fi
    exit "$rc"
}
trap finish EXIT
exec > >(tee "$LOG") 2>&1

for tool in /usr/bin/cargo /usr/bin/rustc /usr/bin/rustfmt \
        /usr/bin/cargo-clippy /usr/bin/rustdoc /usr/bin/python3 \
        /usr/bin/gcc /usr/bin/clang /usr/bin/nm /usr/bin/objdump /usr/bin/strings \
        /usr/bin/readelf /usr/bin/ldd /usr/bin/sha256sum \
        /usr/bin/timeout /usr/bin/valgrind /usr/bin/scan-build \
        /usr/bin/jq; do
    test -x "$tool"
done

printf 'repository_snapshot=%s\nlane=%s\nlane_root=%s\nopenssl_prefix=%s\nresult=%s\n' \
    "$ROOT" "$LANE" "$LANE_ROOT" "$OPENSSL_PREFIX" "$BUILD"

provider_env() {
    local target=$1
    shift
    env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
        CARGO_HOME="$CARGO_HOME_DIR" CARGO_TARGET_DIR="$target" \
        CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CCACHE_DISABLE=1 \
        CC=/usr/bin/gcc AR=/usr/bin/ar \
        ED301_HERMETIC_PROVIDER_BUILD=1 \
        OPENSSL_INCLUDE_DIR="$OPENSSL_PREFIX/include" \
        OPENSSL_LIB_DIR="$OPENSSL_LIB" LD_LIBRARY_PATH="$OPENSSL_LIB" \
        "$@"
}
cargo_provider() {
    local target=$1
    shift
    (cd / && provider_env "$target" /usr/bin/cargo "$@")
}

provider_env "$BUILD/targets/identity" /usr/bin/rustc --version --verbose
provider_env "$BUILD/targets/identity" /usr/bin/cargo --version --verbose
provider_env "$BUILD/targets/identity" /usr/bin/rustfmt --version
provider_env "$BUILD/targets/identity" /usr/bin/cargo-clippy --version
env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    OPENSSL_CONF=/dev/null LD_LIBRARY_PATH="$OPENSSL_LIB" \
    "$OPENSSL_BIN" version -a
(cd "$ROOT/inputs/round4" && sha256sum --strict --quiet -c SHA256SUMS)

# Isolated Python cannot import user startup state.  It writes only to the
# private result tree.  The generated Rust module is formatted by the
# canonical Fedora tool whose exact version is recorded, and must equal the
# committed, manifest-bound module byte for byte.
env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -B \
    "$ROOT/provider-tests/gen_vectors.py" "$ROOT" \
    "$BUILD/generated/vectors.h" "$BUILD/generated/policy_vectors_data.rs"
env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    /usr/bin/rustfmt --edition 2024 \
    "$BUILD/generated/policy_vectors_data.rs"
cmp "$BUILD/generated/policy_vectors_data.rs" \
    "$ROOT/provider/crates/ed301-eddsa-provider/src/policy_vectors_data.rs"
{
    printf '%s\n' \
        'openssl_conf = openssl_init' \
        '' \
        '[openssl_init]' \
        'oid_section = ed301_oids' \
        '' \
        '[ed301_oids]' \
        'Ed301-EdDSA-v1 = 1.3.6.1.4.1.66282.301.4'
} >"$BUILD/generated/native-evp-test.cnf"
(
    cd "$BUILD"
    find generated -type f -print0 | sort -z | xargs -0 sha256sum
) >"$BUILD/evidence/generated-inputs.sha256"
sha256sum "$BUILD/evidence/generated-inputs.sha256" \
    >"$BUILD/evidence/generated-inputs.seal"
sha256sum --strict --quiet -c "$BUILD/evidence/generated-inputs.seal"
(cd "$BUILD" && sha256sum --strict --quiet -c \
    evidence/generated-inputs.sha256)

QA_ANALYSIS_TARGET=$BUILD/targets/qa-analysis
QA_TARGET=$BUILD/targets/qa-release-test
QA_MARKERS=$BUILD/profile-markers/qa
mkdir -m 700 "$QA_ANALYSIS_TARGET" "$QA_TARGET" "$QA_MARKERS"
cargo_provider "$QA_ANALYSIS_TARGET" fmt \
    --manifest-path "$ROOT/provider/Cargo.toml" --all -- --check
cargo_provider "$QA_ANALYSIS_TARGET" metadata \
    --manifest-path "$ROOT/provider/Cargo.toml" \
    --locked --offline --format-version=1 >/dev/null
cargo_provider "$QA_ANALYSIS_TARGET" clippy \
    --manifest-path "$ROOT/provider/Cargo.toml" \
    --locked --offline --workspace --all-targets -- -D warnings
cargo_provider "$QA_ANALYSIS_TARGET" clippy \
    --manifest-path "$ROOT/provider/Cargo.toml" --release \
    --locked --offline --workspace --all-targets -- -D warnings
cargo_provider "$QA_ANALYSIS_TARGET" clippy \
    --manifest-path "$ROOT/provider/Cargo.toml" --release \
    --locked --offline --workspace --all-targets \
    --features sign-self-verify -- -D warnings
(cd / && provider_env "$QA_ANALYSIS_TARGET" env \
    RUSTDOCFLAGS='-D warnings' /usr/bin/cargo \
    doc \
    --manifest-path "$ROOT/provider/Cargo.toml" \
    --locked --offline --workspace --no-deps)

provider_env "$QA_TARGET" /usr/bin/rustc --version --verbose \
    >"$QA_MARKERS/toolchain.txt"
(cd / && provider_env "$QA_TARGET" env \
    ED301_PROFILE_MARKER_DIR="$QA_MARKERS" \
    RUSTC_WRAPPER="$ROOT/scripts/rustc-profile-guard.sh" \
    /usr/bin/cargo test \
    --manifest-path "$ROOT/provider/Cargo.toml" --release \
    --locked --offline --no-run --message-format=json \
    >"$BUILD/evidence/provider-unit-artifacts.jsonl")
sh "$ROOT/scripts/check-profile-markers.sh" "$QA_MARKERS" \
    crypto_bigint=on ed301_eddsa=on ed301_eddsa_v1=on
/usr/bin/jq -r \
    'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null) | .executable' \
    "$BUILD/evidence/provider-unit-artifacts.jsonl" \
    | sort -u >"$BUILD/evidence/provider-unit-executables.lst"
test -s "$BUILD/evidence/provider-unit-executables.lst"
while IFS= read -r executable; do
    test -x "$executable"
    sha256sum "$executable"
done <"$BUILD/evidence/provider-unit-executables.lst" \
    >"$BUILD/evidence/provider-unit-executables.sha256"
sha256sum "$BUILD/evidence/provider-unit-executables.lst" \
    "$BUILD/evidence/provider-unit-executables.sha256" \
    >"$BUILD/evidence/provider-unit-executables.seal"
sha256sum --strict --quiet -c \
    "$BUILD/evidence/provider-unit-executables.seal"
sh "$ROOT/scripts/require-verified-snapshot.sh"
while IFS= read -r executable; do
    provider_env "$QA_TARGET" "$executable"
done <"$BUILD/evidence/provider-unit-executables.lst"
sha256sum --strict --quiet -c \
    "$BUILD/evidence/provider-unit-executables.sha256"
sha256sum --strict --quiet -c \
    "$BUILD/evidence/provider-unit-executables.seal"

build_variant() {
    local variant=$1 feature=$2 module=$3
    local target=$BUILD/targets/$variant
    local markers=$BUILD/profile-markers/$variant
    local command=(/usr/bin/cargo build \
        --manifest-path "$ROOT/provider/Cargo.toml" \
        --release --locked --offline)
    mkdir -m 700 "$target" "$markers"
    provider_env "$target" /usr/bin/rustc --version --verbose \
        >"$markers/toolchain.txt"
    if [[ -n "$feature" ]]; then
        command+=(--features "$feature")
    fi
    (cd / && provider_env "$target" env \
        ED301_PROFILE_MARKER_DIR="$markers" \
        RUSTC_WRAPPER="$ROOT/scripts/rustc-profile-guard.sh" \
        "${command[@]}")
    sh "$ROOT/scripts/check-profile-markers.sh" "$markers" \
        crypto_bigint=on ed301_eddsa=on ed301_eddsa_v1=on
    cp "$target/release/libed301_eddsa_v1.so" \
        "$BUILD/modules/$module"
    rm -rf -- "$target"
}

build_variant normal '' ed301_eddsa_v1.so
sh "$ROOT/scripts/check-final-provider-codegen.sh" \
    "$BUILD/modules/ed301_eddsa_v1.so" \
    "$BUILD/profile-markers/normal/toolchain.txt" \
    "$BUILD/evidence/final-provider-codegen"
build_variant failpoint test-failpoint ed301_eddsa_v1_failpoint.so
build_variant pki pki-experiment ed301_eddsa_v1_pki_test.so
build_variant tls tls-experiment ed301_eddsa_v1_tls_test.so
build_variant collider tls-collider ed301_eddsa_v1_tls_collider.so

env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    LD_LIBRARY_PATH="$OPENSSL_LIB" \
    "$OPENSSL_BIN" list -objects \
    >"$BUILD/evidence/openssl-objects.txt"

cp "$BUILD/modules/ed301_eddsa_v1_pki_test.so" \
    "$BUILD/fresh-modules/ed301_eddsa_v1_pki_test.so"

# The full EVP taint lane uses a separately named directory containing an
# instrumented ordinary provider. It is test-only and never mixed with the
# normal provider artifacts.
TAINT_TARGET=$BUILD/targets/secret-taint
TAINT_MARKERS=$BUILD/profile-markers/secret-taint
mkdir -m 700 "$TAINT_TARGET" "$TAINT_MARKERS" "$BUILD/modules-taint"
provider_env "$TAINT_TARGET" /usr/bin/rustc --version --verbose \
    >"$TAINT_MARKERS/toolchain.txt"
(cd / && provider_env "$TAINT_TARGET" env \
    ED301_HERMETIC_NATIVE_BUILD=1 \
    ED301_PROFILE_MARKER_DIR="$TAINT_MARKERS" \
    RUSTC_WRAPPER="$ROOT/scripts/rustc-profile-guard.sh" \
    /usr/bin/cargo build \
        --manifest-path "$ROOT/provider/Cargo.toml" \
        --release --locked --offline \
        --features secret-taint-instrumentation)
sh "$ROOT/scripts/check-profile-markers.sh" "$TAINT_MARKERS" \
    crypto_bigint=on ed301_eddsa=on ed301_valgrind_client=on \
    ed301_eddsa_v1=on
cp "$TAINT_TARGET/release/libed301_eddsa_v1.so" \
    "$BUILD/modules-taint/ed301_eddsa_v1.so"
rm -rf -- "$TAINT_TARGET"

if strings "$BUILD/modules/ed301_eddsa_v1.so" \
        | grep -E 'ED301_EDDSA_V1_(PANIC|ALLOC)_FAILPOINT|TLS-SIGALG|BEGIN PRIVATE KEY|1\.3\.6\.1\.4\.1\.66282\.301\.[34]'; then
    echo "ordinary module contains a diagnostic, TLS or PKI-only surface" >&2
    exit 1
fi
strings "$BUILD/modules/ed301_eddsa_v1_failpoint.so" \
    | grep -F ED301_EDDSA_V1_PANIC_FAILPOINT >/dev/null
strings "$BUILD/modules/ed301_eddsa_v1_tls_test.so" \
    | grep -F TLS-SIGALG >/dev/null
strings "$BUILD/modules/ed301_eddsa_v1_tls_collider.so" \
    | grep -F TLS-SIGALG >/dev/null
strings "$BUILD/modules/ed301_eddsa_v1_pki_test.so" \
    | grep -F 'structure=PrivateKeyInfo' >/dev/null

test "$(nm -D --defined-only "$BUILD/modules/ed301_eddsa_v1.so" \
    | awk '$2 == "T" { count++ } END { print count + 0 }')" -eq 1
nm -D --defined-only "$BUILD/modules/ed301_eddsa_v1.so" \
    | grep -E ' T OSSL_provider_init$' >/dev/null

HARNESSES=(
    provider_load provider_keymgmt provider_signature
    provider_serialization provider_pki provider_oid_collision provider_rand
    provider_lifecycle provider_tls provider_hardening provider_load_fresh
    provider_shim_unit val01_decoder_bio val03_retry val05_codepoint
)
(cd "$BUILD" && sha256sum --strict --quiet -c \
    evidence/generated-inputs.sha256)
for harness in "${HARNESSES[@]}"; do
    /usr/bin/gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror \
        -I"$OPENSSL_PREFIX/include" \
        -I"$ROOT/provider/crates/ed301-eddsa-provider/c" \
        -I"$BUILD/generated" -I"$ROOT/provider-tests" \
        -o "$BUILD/bin/$harness" "$ROOT/provider-tests/$harness.c" \
        -L"$OPENSSL_LIB" -Wl,-rpath,"$OPENSSL_LIB" \
        -lcrypto -lssl -lpthread -ldl
done
/usr/bin/gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror \
    -I"$OPENSSL_PREFIX/include" -I"$BUILD/generated" \
    -I"$ROOT/provider-tests" -o "$BUILD/bin/provider_secret_taint" \
    "$ROOT/provider-tests/provider_secret_taint.c" \
    -L"$OPENSSL_LIB" -Wl,-rpath,"$OPENSSL_LIB" \
    -lcrypto -lssl -lpthread -ldl
/usr/bin/gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror \
    -I"$OPENSSL_PREFIX/include" -I"$BUILD/generated" \
    -I"$ROOT/provider-tests" -o "$BUILD/bin/provider_load_no_rpath" \
    "$ROOT/provider-tests/provider_load.c" \
    -L"$OPENSSL_LIB" -lcrypto -lssl -lpthread -ldl
/usr/bin/gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror \
    -I"$OPENSSL_PREFIX/include" -I"$ROOT/provider-tests" \
    -o "$BUILD/bin/provider_context_contract" \
    "$ROOT/review-tests/provider-context-contract.c" \
    -L"$OPENSSL_LIB" -Wl,-rpath,"$OPENSSL_LIB" \
    -lcrypto -lssl -lpthread -ldl

for harness in provider_signature provider_keymgmt provider_serialization \
        val01_decoder_bio provider_load provider_rand provider_lifecycle \
        provider_tls; do
    /usr/bin/clang -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -g \
        -fsanitize=address,undefined -fno-sanitize-recover=all \
        -I"$OPENSSL_PREFIX/include" -I"$BUILD/generated" \
        -I"$ROOT/provider/crates/ed301-eddsa-provider/c" \
        -I"$ROOT/provider-tests" -o "$BUILD/bin/${harness}_asan" \
        "$ROOT/provider-tests/$harness.c" \
        -L"$OPENSSL_LIB" -Wl,-rpath,"$OPENSSL_LIB" \
        -lcrypto -lssl -lpthread -ldl
done

/usr/bin/gcc -std=c11 -Wall -Wextra -Werror -fanalyzer -c \
    -I"$OPENSSL_PREFIX/include" -o "$BUILD/provider_shim.analyzer.o" \
    "$ROOT/provider/crates/ed301-eddsa-provider/c/provider_shim.c"
/usr/bin/scan-build --status-bugs --use-cc=/usr/bin/clang \
    -o "$BUILD/scan-build" /usr/bin/clang -std=c11 -D_GNU_SOURCE \
    -Wall -Wextra -Werror -I"$OPENSSL_PREFIX/include" \
    -I"$BUILD/generated" -c \
    "$ROOT/provider/crates/ed301-eddsa-provider/c/provider_shim.c" \
    -o "$BUILD/provider_shim.scan-build.o"
(cd "$BUILD" && sha256sum --strict --quiet -c \
    evidence/generated-inputs.sha256)

# Seal every generated executable or module before the first execution.
(
    cd "$BUILD"
    sha256sum cargo-home/config.toml
    sha256sum evidence/openssl-objects.txt
    sha256sum profile-markers/normal/toolchain.txt \
        profile-markers/secret-taint/toolchain.txt
    find modules modules-taint fresh-modules bin generated \
        evidence/final-provider-codegen -type f -print0 \
        | sort -z | xargs -0 sha256sum
) >"$BUILD/evidence/pre-execution-artifacts.sha256"
sha256sum "$BUILD/evidence/pre-execution-artifacts.sha256" \
    >"$BUILD/evidence/pre-execution-artifacts.seal"
sha256sum --strict --quiet -c \
    "$BUILD/evidence/pre-execution-artifacts.seal"
(cd "$BUILD" && sha256sum --strict --quiet -c \
    evidence/pre-execution-artifacts.sha256)
(cd "$LANE_ROOT" && \
    sha256sum --strict --quiet -c PRIVATE_LANE_SHA256SUMS.seal && \
    sha256sum --strict --quiet -c PRIVATE_LANE_SHA256SUMS)
verify_lane

env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    ED301_HERMETIC_LAUNCH=1 ED301_SOURCE_MODE=archive \
    ED301_VERIFIED_SNAPSHOT=1 \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256="$ED301_EXPECTED_SOURCE_MANIFEST_SHA256" \
    OPENSSL_PREFIX="$OPENSSL_PREFIX" \
    ED301_MODULE_DIR="$BUILD/modules" \
    ED301_PROVIDER_CONTEXT_HARNESS="$BUILD/bin/provider_context_contract" \
    OPENSSL_OBJECT_LISTS="$BUILD/evidence/openssl-objects.txt" \
    "$ROOT/review-tests/run.sh" \
    | tee "$BUILD/evidence/hostile-regressions.log"
grep -Fq 'openssl_object_lists=1' \
    "$BUILD/evidence/hostile-regressions.log"

run_harness() {
    env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
        OPENSSL_MODULES="$BUILD/modules" OPENSSL_CONF=/dev/null \
        LD_LIBRARY_PATH="$OPENSSL_LIB" \
        ED301V1_EXPECT_OPENSSL_PREFIX="$OPENSSL_PREFIX" \
        ED301V1_FRESH_COPY_DIR="$BUILD/fresh-modules" \
        /usr/bin/timeout 240 "$BUILD/bin/$1"
}
for harness in provider_load provider_keymgmt provider_signature \
        provider_serialization provider_pki provider_rand \
        provider_lifecycle provider_tls provider_hardening \
        provider_load_fresh provider_shim_unit \
        val01_decoder_bio val05_codepoint; do
    run_harness "$harness"
done

# Reuse OpenSSL's own Ed25519/Ed448-style EVP test driver.  The ordinary
# provider intentionally does not register an OID, so the native driver's
# legacy NID-only raw-key parser receives a host-local OID solely through this
# private config file.  No PKI or TLS surface is added to the ordinary module.
env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    OPENSSL_MODULES="$BUILD/modules" \
    OPENSSL_CONF="$BUILD/generated/native-evp-test.cnf" \
    LD_LIBRARY_PATH="$OPENSSL_LIB" \
    ED301V1_EXPECT_OPENSSL_PREFIX="$OPENSSL_PREFIX" \
    /usr/bin/timeout 240 "$LANE_ROOT/src/openssl-$LANE/test/evp_test" \
        -provider ed301_eddsa_v1 \
        "$ROOT/provider-tests/openssl_evp_ed301.txt"

for mode in free object-only exact occupied-oid occupied-name sigid-conflict \
        digest-slot public-slot; do
    env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
        OPENSSL_MODULES="$BUILD/modules" OPENSSL_CONF=/dev/null \
        LD_LIBRARY_PATH="$OPENSSL_LIB" \
        ED301V1_EXPECT_OPENSSL_PREFIX="$OPENSSL_PREFIX" \
        /usr/bin/timeout 60 "$BUILD/bin/provider_oid_collision" "$mode"
done
for mode in exact-fast exact-stalled conflict; do
    env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
        OPENSSL_MODULES="$BUILD/modules" OPENSSL_CONF=/dev/null \
        LD_LIBRARY_PATH="$OPENSSL_LIB" \
        ED301V1_EXPECT_OPENSSL_PREFIX="$OPENSSL_PREFIX" \
        /usr/bin/timeout 60 "$BUILD/bin/val03_retry" \
        "$mode" "$BUILD/modules"
done

POLICY_LOG=$BUILD/evidence/policy-mutation.log
set +e
env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    OPENSSL_MODULES="$BUILD/modules" OPENSSL_CONF=/dev/null \
    LD_LIBRARY_PATH="$OPENSSL_LIB" \
    ED301V1_EXPECT_OPENSSL_PREFIX="$OPENSSL_PREFIX" \
    ED301V1_POLICY_MUTATE=1 "$BUILD/bin/provider_signature" \
    >"$POLICY_LOG" 2>&1
POLICY_RC=$?
set -e
test "$POLICY_RC" -ne 0
grep -E 'failed|FAIL provider_signature' "$POLICY_LOG" >/dev/null

WRONG_RUNTIME_LOG=$BUILD/evidence/wrong-runtime.log
set +e
env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    OPENSSL_MODULES="$BUILD/modules" OPENSSL_CONF=/dev/null \
    ED301V1_EXPECT_OPENSSL_PREFIX="$OPENSSL_PREFIX" \
    "$BUILD/bin/provider_load_no_rpath" >"$WRONG_RUNTIME_LOG" 2>&1
WRONG_RUNTIME_RC=$?
set -e
test "$WRONG_RUNTIME_RC" -ne 0
grep -E 'FATAL: runtime OpenSSL|FATAL: libcrypto resolved|error while loading shared libraries' \
    "$WRONG_RUNTIME_LOG" >/dev/null

# CLI coverage is intentionally limited to discovery and key encoding.  The
# ordinary and PKI artifacts expose no decoder; private-key imports use the
# strict complete-buffer C boundary.  The TLS-only SPKI decoder is exercised
# by the transactional decoder and wire-certificate harnesses above.
env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    OPENSSL_MODULES="$BUILD/modules" OPENSSL_CONF=/dev/null \
    LD_LIBRARY_PATH="$OPENSSL_LIB" \
    "$OPENSSL_BIN" list -provider-path "$BUILD/modules" \
        -provider default -provider ed301_eddsa_v1 \
        -signature-algorithms | grep -F Ed301-EdDSA-v1 >/dev/null
env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    OPENSSL_MODULES="$BUILD/modules" OPENSSL_CONF=/dev/null \
    LD_LIBRARY_PATH="$OPENSSL_LIB" \
    "$OPENSSL_BIN" genpkey -provider-path "$BUILD/modules" \
        -provider default -provider ed301_eddsa_v1_pki_test \
        -algorithm Ed301-EdDSA-v1 \
        -out "$BUILD/evidence/cli-generated-key.pem"
grep -F 'BEGIN PRIVATE KEY' "$BUILD/evidence/cli-generated-key.pem" \
    >/dev/null

for harness in provider_signature provider_keymgmt provider_serialization \
        val01_decoder_bio provider_load provider_rand provider_lifecycle \
        provider_tls; do
    env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
        OPENSSL_MODULES="$BUILD/modules" OPENSSL_CONF=/dev/null \
        LD_LIBRARY_PATH="$OPENSSL_LIB" \
        ED301V1_EXPECT_OPENSSL_PREFIX="$OPENSSL_PREFIX" \
        ED301V1_FRESH_COPY_DIR="$BUILD/fresh-modules" \
        ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
        UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
        /usr/bin/timeout 240 "$BUILD/bin/${harness}_asan"
done
for harness in provider_signature provider_serialization val01_decoder_bio \
        provider_load provider_rand provider_lifecycle; do
    env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
        OPENSSL_MODULES="$BUILD/modules" OPENSSL_CONF=/dev/null \
        LD_LIBRARY_PATH="$OPENSSL_LIB" \
        ED301V1_EXPECT_OPENSSL_PREFIX="$OPENSSL_PREFIX" \
        ED301V1_FRESH_COPY_DIR="$BUILD/fresh-modules" \
        /usr/bin/valgrind --error-exitcode=99 \
        --errors-for-leak-kinds=definite --leak-check=full --quiet \
        "$BUILD/bin/$harness"
done
for mode in defined tainted; do
    env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
        OPENSSL_MODULES="$BUILD/modules-taint" OPENSSL_CONF=/dev/null \
        LD_LIBRARY_PATH="$OPENSSL_LIB" \
        ED301V1_EXPECT_OPENSSL_PREFIX="$OPENSSL_PREFIX" \
        /usr/bin/valgrind --tool=memcheck --vgdb=no \
        --error-exitcode=99 --track-origins=yes \
        --undef-value-errors=yes --leak-check=full \
        --errors-for-leak-kinds=definite,indirect,possible --quiet \
        "$BUILD/bin/provider_secret_taint" "$mode"
done
env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    OPENSSL_MODULES="$BUILD/modules" OPENSSL_CONF=/dev/null \
    LD_LIBRARY_PATH="$OPENSSL_LIB" \
    ED301V1_EXPECT_OPENSSL_PREFIX="$OPENSSL_PREFIX" \
    ED301V1_RUST_ALLOC_ONLY=1 /usr/bin/valgrind --error-exitcode=99 \
    --errors-for-leak-kinds=definite --leak-check=full --quiet \
    "$BUILD/bin/provider_hardening"

(cd "$BUILD" && sha256sum --strict --quiet -c \
    evidence/pre-execution-artifacts.sha256)
verify_lane
sh "$ROOT/scripts/require-verified-snapshot.sh"
printf 'provider_acceptance=PASS lane=%s result=%s\n' "$LANE" "$BUILD"
