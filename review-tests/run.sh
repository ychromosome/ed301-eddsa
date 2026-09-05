#!/bin/sh
set -u

PATH=/usr/bin:/bin
export PATH LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
TEST_ROOT=$ROOT/review-tests
if ! sh "$ROOT/scripts/check-rust-build-environment.sh"; then
    exit 1
fi
if ! sh "$ROOT/scripts/require-verified-snapshot.sh"; then
    exit 1
fi
WORK=$(mktemp -d /tmp/ed301-hostile-regression.XXXXXX)
HOME_DIR=$WORK/home
CARGO_HOME_DIR=$WORK/cargo-home
failures=0
passes=0
skips=0

mkdir -m 700 "$HOME_DIR" "$CARGO_HOME_DIR"
/usr/bin/python3 -I -B "$ROOT/scripts/write-cargo-config.py" \
    "$CARGO_HOME_DIR/config.toml" "$ROOT/vendor"

cleanup() {
    rm -rf -- "$WORK"
}
trap cleanup EXIT HUP INT TERM

pass() {
    passes=$((passes + 1))
    printf 'PASS %s\n' "$1"
}

fail() {
    failures=$((failures + 1))
    printf 'FAIL %s\n' "$1" >&2
}

skip() {
    skips=$((skips + 1))
    printf 'SKIP %s\n' "$1"
}

build_crate() {
    crate=$1
    target=$2
    (cd / && env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
        CARGO_HOME="$CARGO_HOME_DIR" CARGO_TARGET_DIR="$target" \
        CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 \
        ED301_HERMETIC_NATIVE_BUILD=1 CC=/usr/bin/gcc AR=/usr/bin/ar \
        /usr/bin/cargo build \
            --manifest-path "$TEST_ROOT/$crate/Cargo.toml" \
            --locked --offline --release)
}

printf 'source_manifest_sha256=%s\n' \
    "$(/usr/bin/sha256sum "$ROOT/SOURCE_MANIFEST.sha256" \
        | /usr/bin/awk '{ print $1 }')"
printf 'rustc=%s\n' "$(/usr/bin/rustc --version)"
printf 'valgrind=%s\n' "$(/usr/bin/valgrind --version)"

if env -i PATH=/usr/bin:/bin LC_ALL=C \
        OPENSSL_OBJECT_LISTS="${OPENSSL_OBJECT_LISTS:-}" \
        /usr/bin/python3 -I -B "$TEST_ROOT/oid-independent-check.py"; then
    pass oid-independent-check
else
    fail oid-independent-check
fi

if env -i PATH=/usr/bin:/bin LC_ALL=C \
        /usr/bin/python3 -I -B "$TEST_ROOT/independent-v1-oracle.py"; then
    pass independent-v1-oracle
else
    fail independent-v1-oracle
fi

target=$WORK/wire-target
if build_crate wire-negative-matrix "$target" \
        && /usr/bin/sha256sum "$target/release/wire-negative-matrix" \
        && "$target/release/wire-negative-matrix"; then
    pass wire-negative-matrix
else
    fail wire-negative-matrix
fi

target=$WORK/signature-target
if build_crate signature-object-taint "$target" \
        && /usr/bin/sha256sum "$target/release/signature-object-taint" \
        && /usr/bin/valgrind --tool=memcheck --vgdb=no \
            --error-exitcode=99 --track-origins=yes \
            --undef-value-errors=yes --leak-check=full \
            --errors-for-leak-kinds=definite,indirect,possible \
            --quiet "$target/release/signature-object-taint"; then
    pass signature-object-taint
else
    fail signature-object-taint
fi

target=$WORK/profile-target
profile_log=$WORK/external-profile-taint.valgrind.log
if build_crate external-profile-taint "$target" \
        && /usr/bin/sha256sum "$target/release/external-profile-taint" \
        && /usr/bin/valgrind --tool=memcheck --vgdb=no \
            --error-exitcode=99 --track-origins=yes \
            --undef-value-errors=yes --leak-check=no \
            --log-file="$profile_log" \
            "$target/release/external-profile-taint"; then
    pass external-profile-taint
else
    fail external-profile-taint
    if test -s "$profile_log"; then
        sed -n '1,24p' "$profile_log" >&2
        grep 'ERROR SUMMARY' "$profile_log" | tail -1 >&2 || true
    fi
fi

if "$TEST_ROOT/check-openssl-header-contract.sh" /usr unsupported; then
    pass openssl-system-header-rejection
else
    fail openssl-system-header-rejection
fi

if test -n "${OPENSSL_PREFIX:-}" || test -n "${ED301_MODULE_DIR:-}"; then
    if test -z "${OPENSSL_PREFIX:-}" || test -z "${ED301_MODULE_DIR:-}"; then
        fail provider-context-contract-incomplete-environment
    else
        if "$TEST_ROOT/check-openssl-header-contract.sh" \
                "$OPENSSL_PREFIX" supported; then
            pass openssl-configured-header-support
        else
            fail openssl-configured-header-support
        fi
        context_result=1
        if test -n "${ED301_PROVIDER_CONTEXT_HARNESS:-}" \
                && test -x "$ED301_PROVIDER_CONTEXT_HARNESS" \
                && test ! -L "$ED301_PROVIDER_CONTEXT_HARNESS" \
                && test -f "$ED301_MODULE_DIR/ed301_eddsa_v1.so" \
                && test ! -L "$ED301_MODULE_DIR/ed301_eddsa_v1.so"; then
            printf 'provider_context_inputs prefix=%s harness_sha256=%s module_sha256=%s\n' \
                "$OPENSSL_PREFIX" \
                "$(/usr/bin/sha256sum "$ED301_PROVIDER_CONTEXT_HARNESS" \
                    | /usr/bin/awk '{ print $1 }')" \
                "$(/usr/bin/sha256sum "$ED301_MODULE_DIR/ed301_eddsa_v1.so" \
                    | /usr/bin/awk '{ print $1 }')"
            env ED301V1_EXPECT_OPENSSL_PREFIX="$OPENSSL_PREFIX" \
                OPENSSL_MODULES="$ED301_MODULE_DIR" \
                "$ED301_PROVIDER_CONTEXT_HARNESS"
            context_result=$?
        fi
        if test "$context_result" -eq 0; then
            pass provider-context-contract
        else
            fail provider-context-contract
        fi
    fi
else
    skip 'provider-context-contract (set OPENSSL_PREFIX and ED301_MODULE_DIR)'
fi

printf 'hostile_regression_summary passes=%d failures=%d skips=%d\n' \
    "$passes" "$failures" "$skips"
test "$failures" -eq 0
