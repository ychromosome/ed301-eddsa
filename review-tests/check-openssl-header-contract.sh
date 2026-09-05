#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

if test "$#" -ne 2; then
    echo 'usage: check-openssl-header-contract.sh <openssl-prefix> <supported|unsupported>' >&2
    exit 2
fi

PREFIX=$(readlink -f -- "$1")
EXPECTATION=$2
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
WORK=$(mktemp -d /tmp/ed301-header-contract.XXXXXX)
LOG=$WORK/compiler.log
trap 'rm -rf -- "$WORK"' EXIT HUP INT TERM

case "$EXPECTATION" in
    supported|unsupported) ;;
    *) echo "invalid expectation: $EXPECTATION" >&2; exit 2 ;;
esac
test -f "$PREFIX/include/openssl/opensslv.h" || {
    echo "missing OpenSSL headers below $PREFIX" >&2
    exit 2
}

VERSION_OVERRIDE=
if test "$EXPECTATION" = unsupported; then
    VERSION_OVERRIDE="-include $ROOT/review-tests/unsupported-openssl-version.h"
fi

# VERSION_OVERRIDE contains one option and its path.
# shellcheck disable=SC2086
if /usr/bin/gcc -std=c11 -D_GNU_SOURCE -fsyntax-only -Wall -Wextra \
        $VERSION_OVERRIDE \
        -I"$PREFIX/include" \
        -I"$ROOT/provider/crates/ed301-eddsa-provider/c" \
        "$ROOT/provider/crates/ed301-eddsa-provider/c/provider_shim.c" \
        >"$LOG" 2>&1; then
    if test "$EXPECTATION" = supported; then
        printf 'openssl_header_contract=PASS expectation=supported prefix=%s\n' "$PREFIX"
        exit 0
    fi
    echo "unsupported OpenSSL headers compiled successfully: $PREFIX" >&2
    exit 1
fi

if test "$EXPECTATION" = supported; then
    echo "supported OpenSSL headers failed to compile: $PREFIX" >&2
    sed -n '1,120p' "$LOG" >&2
    exit 1
fi

if grep -Eiq 'undeclared|implicit declaration|did you mean' "$LOG"; then
    echo 'unsupported headers failed accidentally through missing API identifiers' >&2
    sed -n '1,120p' "$LOG" >&2
    exit 1
fi
if ! grep -Eiq '#error|unsupported.*OpenSSL|requires OpenSSL|OpenSSL.*required' "$LOG"; then
    echo 'unsupported headers did not fail through an intentional version guard' >&2
    sed -n '1,120p' "$LOG" >&2
    exit 1
fi

printf 'openssl_header_contract=PASS expectation=unsupported prefix=%s\n' "$PREFIX"
