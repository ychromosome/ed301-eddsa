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

printf 'build_input_hardening_regressions=PASS cases=4\n'
