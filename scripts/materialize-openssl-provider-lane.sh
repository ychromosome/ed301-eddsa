#!/bin/sh
set -eu

PATH=/usr/bin:/bin
LC_ALL=C
export PATH LC_ALL
umask 077

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
sh "$ROOT/scripts/check-rust-build-environment.sh" --environment-only
sh "$ROOT/scripts/require-verified-snapshot.sh"

if [ "$#" -ne 4 ]; then
    echo "usage: $0 <source-lane> <3.5.8|4.0.2> <evidence-sha256> <private-copy>" >&2
    exit 2
fi

SOURCE_ARG=$1
VERSION=$2
EVIDENCE=$3
DEST_ARG=$4
case "$VERSION" in
    3.5.8) SHLIB_MAJOR=3 ;;
    4.0.2) SHLIB_MAJOR=4 ;;
    *) echo "unsupported OpenSSL lane: $VERSION" >&2; exit 2 ;;
esac
if printf '%s\n' "$SOURCE_ARG" "$DEST_ARG" | grep -q '[[:cntrl:]]'; then
    echo "lane path contains a control character" >&2
    exit 2
fi
test ! -e "$DEST_ARG" && test ! -L "$DEST_ARG" || {
    echo "private lane destination must not exist: $DEST_ARG" >&2
    exit 2
}

SOURCE=$(readlink -f -- "$SOURCE_ARG")
DEST_PARENT=$(dirname -- "$DEST_ARG")
mkdir -p -- "$DEST_PARENT"
DEST_PARENT=$(readlink -f -- "$DEST_PARENT")
DEST=$DEST_PARENT/$(basename -- "$DEST_ARG")
case "$DEST/" in
    "$SOURCE/"*) echo "private lane destination is inside source lane" >&2; exit 2 ;;
esac

sh "$ROOT/scripts/verify-openssl-provider-lane.sh" \
    "$SOURCE" "$VERSION" "$EVIDENCE"

mkdir -m 700 -- "$DEST"
mkdir -p -- "$DEST/logs" "$DEST/inst" \
    "$DEST/src/openssl-$VERSION/test/recipes/30-test_evp_data"
/usr/bin/cp -a --reflink=never --no-preserve=ownership -- \
    "$SOURCE/logs/$VERSION" "$DEST/logs/"
/usr/bin/cp -a --reflink=never --no-preserve=ownership -- \
    "$SOURCE/inst/$VERSION" "$DEST/inst/"
if [ -d "$SOURCE/input" ] && [ ! -L "$SOURCE/input" ]; then
    /usr/bin/cp -a --reflink=never --no-preserve=ownership -- \
        "$SOURCE/input" "$DEST/"
fi
/usr/bin/cp -a --reflink=never --no-preserve=ownership -- \
    "$SOURCE/src/openssl-$VERSION/test/evp_test" \
    "$DEST/src/openssl-$VERSION/test/evp_test"
/usr/bin/cp -a --reflink=never --no-preserve=ownership -- \
    "$SOURCE/src/openssl-$VERSION/test/recipes/30-test_evp_data/evppkey_ml_kem_encap_decap.txt" \
    "$DEST/src/openssl-$VERSION/test/recipes/30-test_evp_data/evppkey_ml_kem_encap_decap.txt"

for tree in "$DEST/logs" "$DEST/src"; do
    if find "$tree" -mindepth 1 ! -type d ! -type f -print -quit \
            | grep -q .; then
        echo "private lane metadata/source copy contains a non-regular path" >&2
        exit 1
    fi
done
if [ -d "$DEST/input" ] && \
        find "$DEST/input" -mindepth 1 ! -type d ! -type f -print -quit \
            | grep -q .; then
    echo "private lane input copy contains a non-regular path" >&2
    exit 1
fi

sh "$ROOT/scripts/verify-openssl-provider-lane.sh" \
    "$DEST" "$VERSION" "$EVIDENCE"

PREFIX=$DEST/inst/$VERSION
SOURCE_COPY=$DEST/src/openssl-$VERSION
for executable in "$PREFIX/bin/openssl" "$SOURCE_COPY/test/evp_test"; do
    name=$(basename -- "$executable")
    /usr/bin/readelf -d "$executable" >"$DEST/$name.dynamic.txt"
    if grep -q '(RPATH)' "$DEST/$name.dynamic.txt"; then
        echo "copied OpenSSL executable uses DT_RPATH: $executable" >&2
        exit 1
    fi
    env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
        LD_LIBRARY_PATH="$PREFIX/lib" /usr/bin/ldd "$executable" \
        >"$DEST/$name.ldd.txt"
    for soname in "libcrypto.so.$SHLIB_MAJOR" "libssl.so.$SHLIB_MAJOR"; do
        resolved=$(awk -v soname="$soname" \
            '$1 == soname && $2 == "=>" { print $3; exit }' \
            "$DEST/$name.ldd.txt")
        if [ -n "$resolved" ]; then
            canonical=$(readlink -f -- "$resolved")
            case "$canonical" in
                "$PREFIX/lib/"*) ;;
                *) echo "$name resolves $soname outside private lane" >&2; exit 1 ;;
            esac
        fi
    done
done

env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
    OPENSSL_CONF=/dev/null LD_LIBRARY_PATH="$PREFIX/lib" \
    "$PREFIX/bin/openssl" version >"$DEST/openssl-version.txt"
grep -Fq "OpenSSL $VERSION " "$DEST/openssl-version.txt"

(
    cd "$DEST"
    find . -type f ! -name PRIVATE_LANE_SHA256SUMS -print0 \
        | sort -z | xargs -0 sha256sum >PRIVATE_LANE_SHA256SUMS
    sha256sum --strict --quiet -c PRIVATE_LANE_SHA256SUMS
    sha256sum PRIVATE_LANE_SHA256SUMS >PRIVATE_LANE_SHA256SUMS.seal
)
chmod -R a-w "$DEST"
printf 'private_openssl_lane=PASS version=%s root=%s evidence=%s\n' \
    "$VERSION" "$DEST" "$EVIDENCE"
