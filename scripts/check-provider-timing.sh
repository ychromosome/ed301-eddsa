#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
sh "$ROOT/scripts/check-rust-build-environment.sh"
sh "$ROOT/scripts/require-verified-snapshot.sh"

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <openssl-prefix> <provider-modules-dir> <new-evidence-dir>" >&2
    exit 2
fi
PREFIX=$(readlink -f -- "$1")
MODULE_SOURCE=$(readlink -f -- "$2")
EVIDENCE=$3
MEASUREMENTS=${ED301_TIMING_MEASUREMENTS:-200000}
case "$MEASUREMENTS" in
    ''|*[!0-9]*) echo "ED301_TIMING_MEASUREMENTS must be an integer" >&2; exit 2 ;;
esac
case "$(uname -m)" in
    x86_64|aarch64|arm64) ;;
    *) echo "unsupported timing architecture: $(uname -m)" >&2; exit 2 ;;
esac

for tool in awk cat cc cp find grep ldd mkdir readelf sed sha256sum sort \
        uname xargs; do
    test -x "/usr/bin/$tool" || {
        echo "missing timing tool: /usr/bin/$tool" >&2
        exit 127
    }
done
test -f "$PREFIX/include/openssl/evp.h"
test -d "$PREFIX/lib" && test ! -L "$PREFIX/lib"
test -f "$MODULE_SOURCE/ed301_eddsa_v1.so"
test ! -L "$MODULE_SOURCE/ed301_eddsa_v1.so"
test ! -e "$EVIDENCE" && test ! -L "$EVIDENCE"
/usr/bin/mkdir -m 700 -p -- "$EVIDENCE/modules" "$EVIDENCE/lib"
EVIDENCE=$(readlink -f -- "$EVIDENCE")

/usr/bin/cp -- "$MODULE_SOURCE/ed301_eddsa_v1.so" \
    "$EVIDENCE/modules/ed301_eddsa_v1.so"
LIBCRYPTO=$(readlink -f -- "$PREFIX/lib/libcrypto.so")
SONAME=$(/usr/bin/readelf -d "$LIBCRYPTO" \
    | /usr/bin/sed -n 's/.*(SONAME).*\[\([^]]*\)\].*/\1/p')
test -n "$SONAME"
/usr/bin/cp -- "$LIBCRYPTO" "$EVIDENCE/lib/$SONAME"

HARNESS=$EVIDENCE/provider_timing
/usr/bin/cc -std=c11 -O2 -Wall -Wextra -Werror \
    -I"$PREFIX/include" -I"$ROOT/provider-tests" \
    "$ROOT/provider-tests/provider_timing.c" \
    -L"$PREFIX/lib" -Wl,-rpath,"$EVIDENCE/lib" -lcrypto -lm \
    -o "$HARNESS"

{
    printf 'format=ed301-provider-timing-v1\n'
    printf 'source_manifest_sha256=%s\n' \
        "$ED301_EXPECTED_SOURCE_MANIFEST_SHA256"
    printf 'measurements_per_test=%s\n' "$MEASUREMENTS"
    printf 'architecture=%s\n' "$(uname -m)"
    printf 'kernel=%s\n' "$(uname -srvmo)"
    printf 'cpu_model=%s\n' "$(awk -F': ' '/^model name/ { print $2; exit }' /proc/cpuinfo)"
    printf 'loadavg_before=%s\n' "$(awk '{ print $1, $2, $3 }' /proc/loadavg)"
    printf 'compiler=%s\n' "$(readlink -f -- /usr/bin/cc)"
    printf 'compiler_sha256=%s\n' "$(sha256sum "$(readlink -f -- /usr/bin/cc)" | awk '{ print $1 }')"
    printf 'provider_sha256=%s\n' "$(sha256sum "$EVIDENCE/modules/ed301_eddsa_v1.so" | awk '{ print $1 }')"
    printf 'libcrypto_sha256=%s\n' "$(sha256sum "$EVIDENCE/lib/$SONAME" | awk '{ print $1 }')"
    printf 'harness_source_sha256=%s\n' "$(sha256sum "$ROOT/provider-tests/provider_timing.c" | awk '{ print $1 }')"
    printf 'dudect_sha256=%s\n' "$(sha256sum "$ROOT/provider-tests/third_party/dudect/dudect.h" | awk '{ print $1 }')"
    if [ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
        printf 'cpu0_governor=%s\n' "$(sed -n '1p' /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
    fi
    "$PREFIX/bin/openssl" version -a
    /usr/bin/cc --version
} >"$EVIDENCE/RUN_IDENTITY.txt" 2>&1

env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
    OPENSSL_MODULES="$EVIDENCE/modules" \
    LD_LIBRARY_PATH="$EVIDENCE/lib" \
    "$HARNESS" "$EVIDENCE/modules" "$MEASUREMENTS" \
    >"$EVIDENCE/provider_timing.log" 2>&1
/usr/bin/grep -E '^ed301_timing|^P0 |^T[12] ' \
    "$EVIDENCE/provider_timing.log" >"$EVIDENCE/SUMMARY.txt"
/usr/bin/ldd "$HARNESS" >"$EVIDENCE/harness.ldd"
/usr/bin/grep -F "$EVIDENCE/lib/$SONAME" "$EVIDENCE/harness.ldd" >/dev/null
printf 'loadavg_after=%s\n' "$(awk '{ print $1, $2, $3 }' /proc/loadavg)" \
    >>"$EVIDENCE/RUN_IDENTITY.txt"

(cd "$EVIDENCE" && \
    find . -type f ! -name SHA256SUMS -print0 \
        | sort -z | xargs -0 sha256sum >SHA256SUMS && \
    sha256sum --strict --quiet -c SHA256SUMS)
sh "$ROOT/scripts/require-verified-snapshot.sh"
cat "$EVIDENCE/SUMMARY.txt"
printf 'ed301_provider_timing=PASS evidence=%s\n' "$EVIDENCE"
