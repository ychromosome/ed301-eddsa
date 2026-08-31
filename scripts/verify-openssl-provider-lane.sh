#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

SCRIPT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
sh "$SCRIPT_ROOT/scripts/check-rust-build-environment.sh" --environment-only
sh "$SCRIPT_ROOT/scripts/require-verified-snapshot.sh"

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <lane-root> <3.5.7|4.0.1> <evidence-manifest-sha256>" >&2
    exit 2
fi

ROOT_ARG=$1
VERSION=$2
EXPECTED=$3
case "$VERSION" in
    3.5.7) EXPECTED_TAR=a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8 ;;
    4.0.1) EXPECTED_TAR=2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09 ;;
    *) echo "unsupported OpenSSL lane: $VERSION" >&2; exit 2 ;;
esac
if ! printf '%s\n' "$EXPECTED" | grep -Eq '^[0-9a-f]{64}$'; then
    echo "lane evidence digest must be an external lowercase SHA-256" >&2
    exit 2
fi
if printf '%s\n' "$ROOT_ARG" | grep -q '[[:cntrl:]]'; then
    echo "lane root contains a control character" >&2
    exit 2
fi
test -d "$ROOT_ARG" && test ! -L "$ROOT_ARG" || {
    echo "lane root must be a non-symlink directory" >&2
    exit 1
}
ROOT=$(readlink -f -- "$ROOT_ARG")
PREFIX=$ROOT/inst/$VERSION
LOGS=$ROOT/logs/$VERSION
MANIFEST=$LOGS/evidence_manifest.sha256
SOURCE=$ROOT/src/openssl-$VERSION

test -d "$PREFIX" && test ! -L "$PREFIX" \
    && test -d "$LOGS" && test ! -L "$LOGS" || {
    echo "lane prefix or evidence directory is unsafe" >&2
    exit 1
}
test "$(cat "$LOGS/lane_status")" = "LANE $VERSION OK"
test "$(cat "$LOGS/lane_status.exit")" = 0

ACTUAL=$(sha256sum "$MANIFEST" | awk '{print $1}')
[ "$ACTUAL" = "$EXPECTED" ] || {
    echo "OpenSSL lane evidence does not match the external seal" >&2
    echo "expected: $EXPECTED" >&2
    echo "actual:   $ACTUAL" >&2
    exit 1
}
(cd "$ROOT" && sha256sum --strict --quiet -c \
    "logs/$VERSION/evidence_manifest.sha256")

# The provider acceptance lane also reuses OpenSSL's native evp_test binary.
# Bind that executable to the already externally sealed post-build source
# manifest instead of trusting an arbitrary file under the lane directory.
sha256sum --strict --quiet -c "$LOGS/source_manifest_post.sha256.seal"
test -d "$SOURCE" && test ! -L "$SOURCE"
test -x "$SOURCE/test/evp_test" && test ! -L "$SOURCE/test/evp_test"
EVP_TEST_EXPECTED=$(awk '$2 == "./test/evp_test" { print $1 }' \
    "$LOGS/source_manifest_post.sha256")
test -n "$EVP_TEST_EXPECTED"
test "$(sha256sum "$SOURCE/test/evp_test" | awk '{ print $1 }')" \
    = "$EVP_TEST_EXPECTED"
MLKEM_DATA=./test/recipes/30-test_evp_data/evppkey_ml_kem_encap_decap.txt
MLKEM_DATA_EXPECTED=$(awk -v path="$MLKEM_DATA" \
    '$2 == path { print $1 }' "$LOGS/source_manifest_post.sha256")
test -n "$MLKEM_DATA_EXPECTED"
test -f "$SOURCE/${MLKEM_DATA#./}" \
    && test ! -L "$SOURCE/${MLKEM_DATA#./}"
test "$(sha256sum "$SOURCE/${MLKEM_DATA#./}" | awk '{ print $1 }')" \
    = "$MLKEM_DATA_EXPECTED"

grep -Fqx "lane=$VERSION" "$LOGS/lane_identity.seal"
grep -Fqx "prefix_rel=inst/$VERSION" "$LOGS/lane_identity.seal"
grep -Fqx "installed_prefix_manifest_rel=logs/$VERSION/installed_prefix.sha256" \
    "$LOGS/lane_identity.seal"
grep -Fqx "pinned_tar_sha256=$EXPECTED_TAR" "$LOGS/source_identity.tsv"
grep -Fqx "tarball_sha256=$EXPECTED_TAR" "$LOGS/source_identity.tsv"

sha256sum --strict --quiet -c "$LOGS/installed_prefix_manifest.seal"
(cd "$PREFIX" && sha256sum --strict --quiet -c \
    "$LOGS/installed_prefix.sha256")

TMP=$(mktemp -d /tmp/ed301-openssl-lane-verify.XXXXXX)
cleanup() {
    rm -rf -- "$TMP"
}
trap cleanup EXIT HUP INT TERM
(
    cd "$PREFIX"
    find . -type f -printf '%P\n' | sort >"$TMP/files"
    find . -mindepth 1 -type d -printf '%P\n' | sort >"$TMP/directories"
    find . -type l -printf '%P\t%l\n' | sort >"$TMP/symlinks"
    find . -mindepth 1 ! -type d ! -type f ! -type l -print \
        >"$TMP/special"
)
cmp -s "$LOGS/installed_prefix_files.lst" "$TMP/files"
cmp -s "$LOGS/installed_prefix_directories.lst" "$TMP/directories"
cmp -s "$LOGS/installed_prefix_symlinks.tsv" "$TMP/symlinks"
test ! -s "$TMP/special"

while IFS="$(printf '\t')" read -r link target; do
    test -n "$link" && test -n "$target"
    case "$target" in /*) exit 1 ;; esac
    canonical=$(readlink -f -- "$PREFIX/$link")
    case "$canonical" in "$PREFIX"/*) ;; *) exit 1 ;; esac
done <"$LOGS/installed_prefix_symlinks.tsv"

test -x "$PREFIX/bin/openssl"
test -d "$PREFIX/include/openssl"
test -d "$PREFIX/lib"
printf 'openssl_lane_verification=PASS version=%s prefix=%s evidence=%s\n' \
    "$VERSION" "$PREFIX" "$EXPECTED"
