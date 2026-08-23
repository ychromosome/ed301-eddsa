#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <openssl-prefix> <3.5.7|4.0.1>" >&2
    exit 2
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
OPENSSL_PREFIX=$(readlink -f -- "$1")
LANE=$2

case "$LANE" in
    3.5.7|4.0.1) ;;
    *) echo "unsupported OpenSSL lane: $LANE" >&2; exit 2 ;;
esac

OPENSSL_LIB="$OPENSSL_PREFIX/lib"
OPENSSL_BIN="$OPENSSL_PREFIX/bin/openssl"
BUILD="$ROOT/target/provider-$LANE"
EXPECTED_BUILD="$ROOT/target/provider-$LANE"

test "$BUILD" = "$EXPECTED_BUILD"
test -x "$OPENSSL_BIN"
test -d "$OPENSSL_PREFIX/include/openssl"
test -d "$OPENSSL_LIB"

rm -rf -- "$BUILD"
mkdir -p "$BUILD/bin" "$BUILD/modules" "$BUILD/evidence"

LOG="$BUILD/evidence/run.log"
STATUS="$BUILD/evidence/status.txt"
TEMP_CARGO_HOME=$(mktemp -d "$BUILD/cargo-home.XXXXXX")

finish()
{
    rc=$?
    rm -rf -- "$TEMP_CARGO_HOME"
    if [ "$rc" -eq 0 ]; then
        echo "PASS provider lane $LANE" | tee "$STATUS"
    else
        echo "FAIL provider lane $LANE exit=$rc" | tee "$STATUS"
    fi
    exit "$rc"
}
trap finish EXIT
exec > >(tee "$LOG") 2>&1

for tool in cargo rustc rustfmt cargo-clippy python3 gcc clang nm strings \
        readelf ldd sha256sum timeout valgrind scan-build; do
    command -v "$tool" >/dev/null
done

sh "$ROOT/scripts/verify-source-tree.sh"
sh "$ROOT/scripts/check-rust-build-environment.sh"

export CARGO_HOME="$TEMP_CARGO_HOME"
export CARGO_TARGET_DIR="$BUILD/cargo-target"
export CARGO_NET_OFFLINE=true
export CARGO_INCREMENTAL=0
export CCACHE_DISABLE=1
export CC=/usr/bin/gcc
export RUSTFLAGS="-Cpanic=unwind"
export OPENSSL_INCLUDE_DIR="$OPENSSL_PREFIX/include"
export OPENSSL_LIB_DIR="$OPENSSL_LIB"
export OPENSSL_MODULES="$BUILD/modules"
export OPENSSL_CONF=/dev/null
export LD_LIBRARY_PATH="$OPENSSL_LIB"
export D00_EXPECT_OPENSSL_PREFIX="$OPENSSL_PREFIX"

echo "repository=$ROOT"
echo "lane=$LANE"
echo "openssl_prefix=$OPENSSL_PREFIX"
rustc -Vv
cargo -V
rustfmt -V
cargo clippy -V
"$OPENSSL_BIN" version -a

(
    cd "$ROOT/inputs/round4"
    sha256sum --strict --quiet -c SHA256SUMS
)

mkdir -p "$BUILD/generated"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/provider-tests/gen_vectors.py" \
    "$ROOT" "$BUILD/generated/vectors.h"

cargo fmt --manifest-path "$ROOT/provider/Cargo.toml" --all -- --check
cargo metadata --manifest-path "$ROOT/provider/Cargo.toml" \
    --locked --offline --format-version=1 >/dev/null
cargo clippy --manifest-path "$ROOT/provider/Cargo.toml" \
    --locked --offline --workspace --all-targets -- -D warnings
cargo clippy --manifest-path "$ROOT/provider/Cargo.toml" \
    --release --locked --offline --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc \
    --manifest-path "$ROOT/provider/Cargo.toml" \
    --locked --offline --workspace --no-deps
cargo test --manifest-path "$ROOT/provider/Cargo.toml" \
    --release --locked --offline

MARKERS="$BUILD/profile-markers"
mkdir -p "$MARKERS"
{
    command -v rustc
    rustc --version --verbose
} >"$MARKERS/toolchain.txt"
cargo clean --manifest-path "$ROOT/provider/Cargo.toml"
ED301_PROFILE_MARKER_DIR="$MARKERS" \
ED301_PROFILE_EXPECTATIONS='crypto_bigint=off ed301_eddsa=on ed301_eddsa_draft00=on' \
RUSTC_WRAPPER="$ROOT/scripts/rustc-profile-guard.sh" \
    cargo build --manifest-path "$ROOT/provider/Cargo.toml" \
        --release --locked --offline

sh "$ROOT/scripts/check-profile-markers.sh" "$MARKERS" \
    crypto_bigint=off ed301_eddsa=on ed301_eddsa_draft00=on

cp "$CARGO_TARGET_DIR/release/libed301_eddsa_draft00.so" \
    "$BUILD/modules/ed301_eddsa_draft00.so"

cargo build --manifest-path "$ROOT/provider/Cargo.toml" \
    --release --locked --offline --features test-failpoint
cp "$CARGO_TARGET_DIR/release/libed301_eddsa_draft00.so" \
    "$BUILD/modules/ed301_eddsa_draft00_failpoint.so"

cargo build --manifest-path "$ROOT/provider/Cargo.toml" \
    --release --locked --offline --features tls-experiment
cp "$CARGO_TARGET_DIR/release/libed301_eddsa_draft00.so" \
    "$BUILD/modules/ed301_eddsa_draft00_tls_test.so"

cargo build --manifest-path "$ROOT/provider/Cargo.toml" \
    --release --locked --offline --features tls-collider
cp "$CARGO_TARGET_DIR/release/libed301_eddsa_draft00.so" \
    "$BUILD/modules/ed301_eddsa_draft00_tls_collider.so"

if strings "$BUILD/modules/ed301_eddsa_draft00.so" \
        | grep -E 'ED301_EDDSA_DRAFT00_(PANIC|ALLOC)_FAILPOINT'; then
    echo "ordinary module contains a test failpoint" >&2
    exit 1
fi
strings "$BUILD/modules/ed301_eddsa_draft00_failpoint.so" \
    | grep -F ED301_EDDSA_DRAFT00_PANIC_FAILPOINT >/dev/null
if strings "$BUILD/modules/ed301_eddsa_draft00.so" \
        | grep -E 'TLS-SIGALG|ed301_eddsa_draft00_test'; then
    echo "ordinary module contains the private-use TLS capability" >&2
    exit 1
fi
strings "$BUILD/modules/ed301_eddsa_draft00_tls_test.so" \
    | grep -F TLS-SIGALG >/dev/null
strings "$BUILD/modules/ed301_eddsa_draft00_tls_collider.so" \
    | grep -F TLS-SIGALG >/dev/null

test "$(nm -D --defined-only "$BUILD/modules/ed301_eddsa_draft00.so" \
    | awk '$2 == "T" { count++ } END { print count + 0 }')" -eq 1
nm -D --defined-only "$BUILD/modules/ed301_eddsa_draft00.so" \
    | grep -E ' T OSSL_provider_init$' >/dev/null

HARNESSES=(
    provider_load provider_keymgmt provider_signature
    provider_serialization provider_pki provider_oid_collision provider_rand
    provider_tls provider_hardening provider_load_fresh
    provider_shim_unit val01_decoder_bio val03_retry val05_codepoint
)

for harness in "${HARNESSES[@]}"; do
    gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror \
        -I"$OPENSSL_PREFIX/include" \
        -I"$ROOT/provider/crates/ed301-eddsa-provider/c" \
        -I"$BUILD/generated" \
        -I"$ROOT/provider-tests" \
        -o "$BUILD/bin/$harness" \
        "$ROOT/provider-tests/$harness.c" \
        -L"$OPENSSL_LIB" -Wl,-rpath,"$OPENSSL_LIB" \
        -lcrypto -lssl -lpthread -ldl
done

for harness in provider_load provider_keymgmt provider_signature \
        provider_serialization provider_pki provider_rand provider_tls \
        provider_hardening \
        provider_load_fresh provider_shim_unit val01_decoder_bio \
        val05_codepoint; do
    timeout 240 "$BUILD/bin/$harness"
done

for mode in free object-only exact occupied-oid occupied-name sigid-conflict \
        digest-slot public-slot; do
    timeout 60 "$BUILD/bin/provider_oid_collision" "$mode"
done

for mode in exact-fast exact-stalled conflict; do
    timeout 60 "$BUILD/bin/val03_retry" "$mode" "$BUILD/modules"
done

POLICY_LOG="$BUILD/evidence/policy-mutation.log"
set +e
ED301D00_POLICY_MUTATE=1 \
    "$BUILD/bin/provider_signature" >"$POLICY_LOG" 2>&1
POLICY_RC=$?
set -e
test "$POLICY_RC" -ne 0
grep -E 'failed|FAIL provider_signature' "$POLICY_LOG" >/dev/null

gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror \
    -I"$OPENSSL_PREFIX/include" -I"$BUILD/generated" \
    -I"$ROOT/provider-tests" \
    -o "$BUILD/bin/provider_load_no_rpath" \
    "$ROOT/provider-tests/provider_load.c" \
    -L"$OPENSSL_LIB" -lcrypto -lssl -lpthread -ldl

WRONG_RUNTIME_LOG="$BUILD/evidence/wrong-runtime.log"
set +e
env -u LD_LIBRARY_PATH "$BUILD/bin/provider_load_no_rpath" \
    >"$WRONG_RUNTIME_LOG" 2>&1
WRONG_RUNTIME_RC=$?
set -e
test "$WRONG_RUNTIME_RC" -ne 0
grep -E 'FATAL: libcrypto resolved|error while loading shared libraries' \
    "$WRONG_RUNTIME_LOG" >/dev/null

CLI="$BUILD/cli"
mkdir -p "$CLI"
PROVIDER_ARGUMENTS=(
    -provider-path "$BUILD/modules"
    -provider default
    -provider ed301_eddsa_draft00
)
"$OPENSSL_BIN" list "${PROVIDER_ARGUMENTS[@]}" -signature-algorithms \
    | grep -F Ed301-EdDSA-draft-00 >/dev/null
"$OPENSSL_BIN" genpkey "${PROVIDER_ARGUMENTS[@]}" \
    -algorithm Ed301-EdDSA-draft-00 -out "$CLI/key.pem"
"$OPENSSL_BIN" pkey "${PROVIDER_ARGUMENTS[@]}" \
    -in "$CLI/key.pem" -pubout -out "$CLI/public.pem"
printf 'provider CLI acceptance message' >"$CLI/message.bin"
printf 'provider CLI wrong message' >"$CLI/wrong-message.bin"
"$OPENSSL_BIN" pkeyutl "${PROVIDER_ARGUMENTS[@]}" \
    -sign -rawin -inkey "$CLI/key.pem" -in "$CLI/message.bin" \
    -out "$CLI/message.sig"
test "$(stat -c%s "$CLI/message.sig")" -eq 76
"$OPENSSL_BIN" pkeyutl "${PROVIDER_ARGUMENTS[@]}" \
    -verify -rawin -pubin -inkey "$CLI/public.pem" \
    -in "$CLI/message.bin" -sigfile "$CLI/message.sig"
if "$OPENSSL_BIN" pkeyutl "${PROVIDER_ARGUMENTS[@]}" \
        -verify -rawin -pubin -inkey "$CLI/public.pem" \
        -in "$CLI/wrong-message.bin" -sigfile "$CLI/message.sig"; then
    echo "CLI accepted a signature for the wrong message" >&2
    exit 1
fi
"$OPENSSL_BIN" pkcs8 "${PROVIDER_ARGUMENTS[@]}" \
    -topk8 -in "$CLI/key.pem" -passout pass:ed301-test \
    -out "$CLI/encrypted.pem"
"$OPENSSL_BIN" pkey "${PROVIDER_ARGUMENTS[@]}" \
    -in "$CLI/encrypted.pem" -passin pass:ed301-test \
    -out "$CLI/decrypted.pem"
cmp "$CLI/key.pem" "$CLI/decrypted.pem"

for harness in provider_signature provider_keymgmt provider_serialization \
        val01_decoder_bio provider_load provider_rand provider_tls; do
    clang -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -g \
        -fsanitize=address,undefined -fno-sanitize-recover=all \
        -I"$OPENSSL_PREFIX/include" -I"$BUILD/generated" \
        -I"$ROOT/provider/crates/ed301-eddsa-provider/c" \
        -I"$ROOT/provider-tests" \
        -o "$BUILD/bin/${harness}_asan" \
        "$ROOT/provider-tests/$harness.c" \
        -L"$OPENSSL_LIB" -Wl,-rpath,"$OPENSSL_LIB" \
        -lcrypto -lssl -lpthread -ldl
    ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
    UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
        timeout 240 "$BUILD/bin/${harness}_asan"
done

for harness in provider_signature provider_serialization val01_decoder_bio \
        provider_load provider_rand; do
    valgrind --error-exitcode=99 --errors-for-leak-kinds=definite \
        --leak-check=full --quiet "$BUILD/bin/$harness"
done

ED301D00_RUST_ALLOC_ONLY=1 \
    valgrind --error-exitcode=99 --errors-for-leak-kinds=definite \
    --leak-check=full --quiet "$BUILD/bin/provider_hardening"

gcc -std=c11 -Wall -Wextra -Werror -fanalyzer -c \
    -I"$OPENSSL_PREFIX/include" \
    -o "$BUILD/provider_shim.analyzer.o" \
    "$ROOT/provider/crates/ed301-eddsa-provider/c/provider_shim.c"

scan-build --status-bugs --use-cc=clang -o "$BUILD/scan-build" \
    clang -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror \
    -I"$OPENSSL_PREFIX/include" -I"$BUILD/generated" -c \
    "$ROOT/provider/crates/ed301-eddsa-provider/c/provider_shim.c" \
    -o "$BUILD/provider_shim.scan-build.o"

for artifact in "$OPENSSL_BIN" \
        "$BUILD/modules/ed301_eddsa_draft00.so" \
        "$BUILD/modules/ed301_eddsa_draft00_failpoint.so" \
        "$BUILD/modules/ed301_eddsa_draft00_tls_test.so" \
        "$BUILD/modules/ed301_eddsa_draft00_tls_collider.so" \
        "$BUILD/bin/"*; do
    sha256sum "$artifact"
done > "$BUILD/evidence/artifacts.sha256"

sh "$ROOT/scripts/verify-source-tree.sh"
