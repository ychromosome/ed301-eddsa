#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

if test "$#" -ne 2; then
    echo 'usage: run-provider-context-contract.sh <openssl-prefix> <module-dir>' >&2
    exit 2
fi

PREFIX=$(readlink -f -- "$1")
MODULE_DIR=$(readlink -f -- "$2")
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
WORK=$(mktemp -d /tmp/ed301-provider-context-contract.XXXXXX)
trap 'rm -rf -- "$WORK"' EXIT HUP INT TERM

test -x "$PREFIX/bin/openssl" || {
    echo "missing OpenSSL executable below $PREFIX" >&2
    exit 2
}
test -f "$MODULE_DIR/ed301_eddsa_v1.so" || {
    echo "missing ed301_eddsa_v1.so below $MODULE_DIR" >&2
    exit 2
}

/usr/bin/gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror \
    -I"$PREFIX/include" -I"$ROOT/provider-tests" \
    -o "$WORK/provider-context-contract" \
    "$ROOT/review-tests/provider-context-contract.c" \
    -L"$PREFIX/lib" -Wl,-rpath,"$PREFIX/lib" \
    -lcrypto -lssl -lpthread -ldl

/usr/bin/sha256sum "$WORK/provider-context-contract"
env ED301V1_EXPECT_OPENSSL_PREFIX="$PREFIX" OPENSSL_MODULES="$MODULE_DIR" \
    "$WORK/provider-context-contract"
