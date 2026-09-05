#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)

if [ "${ED301_VERIFIED_SNAPSHOT:-}" != 1 ] \
        || [ "${ED301_SOURCE_MODE:-}" != archive ]; then
    echo "authoritative gates require a private verified archive snapshot" >&2
    exit 2
fi
if [ -z "${ED301_EXPECTED_SOURCE_MANIFEST_SHA256:-}" ]; then
    echo "verified snapshot requires an external manifest digest" >&2
    exit 2
fi
EXPECTED_MANIFEST=$ED301_EXPECTED_SOURCE_MANIFEST_SHA256

/usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
    ED301_HERMETIC_LAUNCH="${ED301_HERMETIC_LAUNCH:-}" \
    ED301_SOURCE_MODE="$ED301_SOURCE_MODE" \
    ED301_VERIFIED_SNAPSHOT="$ED301_VERIFIED_SNAPSHOT" \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256="$EXPECTED_MANIFEST" \
    /bin/sh "$ROOT/scripts/verify-source-tree.sh"

if find "$ROOT" -xdev -perm /222 -print -quit | grep -q .; then
    echo "verified snapshot still contains writable source paths" >&2
    find "$ROOT" -xdev -perm /222 -print | sed -n '1,20p' >&2
    exit 1
fi

printf 'verified_snapshot=PASS root=%s\n' "$ROOT"
