#!/bin/sh
set -eu

PATH=/usr/bin:/bin
LC_ALL=C
export PATH LC_ALL

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
STAGER=$ROOT/scripts/stage-openssl-inputs.py
TMP=$(mktemp -d /tmp/ed301-build-input-test.XXXXXX)
trap 'rm -rf -- "$TMP"' EXIT HUP INT TERM

mkdir "$TMP/upstream" "$TMP/private"
printf 'authenticated archive bytes\n' >"$TMP/upstream/source.tar.gz"
printf 'authenticated sidecar bytes\n' >"$TMP/upstream/source.tar.gz.sha256"
/usr/bin/python3 -I -B "$STAGER" \
    "$TMP/upstream/source.tar.gz" "$TMP/private/source.tar.gz" \
    "$TMP/upstream/source.tar.gz.sha256" \
    "$TMP/private/source.tar.gz.sha256"
private_digest=$(/usr/bin/sha256sum "$TMP/private/source.tar.gz" \
    | /usr/bin/awk '{ print $1 }')
printf 'replacement archive bytes\n' >"$TMP/replacement"
mv -f "$TMP/replacement" "$TMP/upstream/source.tar.gz"
test "$(/usr/bin/sha256sum "$TMP/private/source.tar.gz" \
    | /usr/bin/awk '{ print $1 }')" = "$private_digest"
grep -Fqx 'authenticated archive bytes' "$TMP/private/source.tar.gz"

mkdir "$TMP/symlink-private"
ln -s "$TMP/upstream/source.tar.gz" "$TMP/symlink-source"
if /usr/bin/python3 -I -B "$STAGER" \
        "$TMP/symlink-source" "$TMP/symlink-private/source.tar.gz" \
        "$TMP/upstream/source.tar.gz.sha256" \
        "$TMP/symlink-private/source.tar.gz.sha256" \
        >/dev/null 2>&1; then
    echo "OpenSSL input staging followed a source symlink" >&2
    exit 1
fi

mkdir "$TMP/exclusive-private"
printf 'preexisting\n' >"$TMP/exclusive-private/source.tar.gz"
if /usr/bin/python3 -I -B "$STAGER" \
        "$TMP/upstream/source.tar.gz" \
        "$TMP/exclusive-private/source.tar.gz" \
        "$TMP/upstream/source.tar.gz.sha256" \
        "$TMP/exclusive-private/source.tar.gz.sha256" \
        >/dev/null 2>&1; then
    echo "OpenSSL input staging replaced an existing destination" >&2
    exit 1
fi

mkdir "$TMP/fifo-private"
mkfifo "$TMP/fifo-source"
fifo_rc=0
/usr/bin/timeout 5 /usr/bin/python3 -I -B "$STAGER" \
        "$TMP/fifo-source" "$TMP/fifo-private/source.tar.gz" \
        "$TMP/upstream/source.tar.gz.sha256" \
        "$TMP/fifo-private/source.tar.gz.sha256" \
        >/dev/null 2>&1 || fifo_rc=$?
test "$fifo_rc" -eq 1 || {
    echo "OpenSSL input staging did not promptly reject a source FIFO" >&2
    exit 1
}

# Exercise the provider's actual setup and EXIT cleanup without rebuilding it.
PROVIDER=$ROOT/scripts/test-provider.sh
SOURCE=$TMP/canonical-test-test
RUNNER=$TMP/provider-source.sh
{
    printf '%s\n' '#!/bin/bash' 'set -Eeuo pipefail' \
        'BUILD=$1' 'LANE=test' 'ED301_EXPECTED_SOURCE_MANIFEST_SHA256=test' \
        'STATUS=$BUILD/status' 'CANONICAL_SOURCE='
    awk '/^finish\(\) \{/ {copy=1} copy {print} copy && /^}/ {exit}' \
        "$PROVIDER"
    printf '%s\n' 'trap finish EXIT'
    awk -v prefix="$TMP/canonical-" '
        /^CANONICAL_(SOURCE|CANDIDATE)=\/tmp\/ed301-provider-source-/ {copy=1}
        copy {sub(/\/tmp\/ed301-provider-source-/, prefix); print}
        copy && /^mkdir -m 700 "\$CANONICAL_SOURCE\/scripts"/ {exit}
    ' "$PROVIDER"
} >"$RUNNER"
mkdir "$TMP/existing-run" "$SOURCE"
printf 'retained snapshot\n' >"$SOURCE/sentinel"
chmod 500 "$SOURCE"
if /usr/bin/bash "$RUNNER" "$TMP/existing-run" \
        >"$TMP/existing-run.log" 2>&1; then
    echo 'provider accepted an existing source directory' >&2
    exit 1
fi
grep -Fx 'retained snapshot' "$SOURCE/sentinel" >/dev/null
test "$(stat -c %a "$SOURCE")" = 500
chmod 700 "$SOURCE"
rm -rf -- "$SOURCE"

mkdir "$TMP/failed-run" "$TMP/failed-run/canonical-cargo-home"
if /usr/bin/bash "$RUNNER" "$TMP/failed-run" \
        >"$TMP/failed-run.log" 2>&1; then
    echo 'provider accepted an existing Cargo home' >&2
    exit 1
fi
test ! -e "$SOURCE"
mkdir "$TMP/successful-run"
/usr/bin/bash "$RUNNER" "$TMP/successful-run" \
    >"$TMP/successful-run.log" 2>&1
test ! -e "$SOURCE"

printf 'build_input_hardening_regressions=PASS cases=7\n'
