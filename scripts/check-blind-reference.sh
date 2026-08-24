#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C PYTHONDONTWRITEBYTECODE=1

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
ORACLE=$ROOT/provider-tests/oracle/blind-0c482948
SOURCE=$ORACLE/source
VECTORS=$ORACLE/blind_oracle_vectors.json
WORK=$(mktemp -d /tmp/ed301-blind-oracle.XXXXXX)
cleanup() {
    rm -rf -- "$WORK"
}
trap cleanup EXIT HUP INT TERM

test ! -L "$ORACLE"
test ! -L "$SOURCE"
if find "$ORACLE" -mindepth 1 ! -type d ! -type f -print -quit | grep -q .; then
    echo "blind oracle contains a symlink or special path" >&2
    exit 1
fi
printf '%s\n' AMBIGUITIES.md MANIFEST.sha256 README.md ed301_eddsa.py \
    >"$WORK/expected-source-files"
find "$SOURCE" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' \
    | sort >"$WORK/actual-source-files"
cmp "$WORK/expected-source-files" "$WORK/actual-source-files"
test "$(find "$SOURCE" -mindepth 1 -type d -print -quit)" = ""

test "$(sha256sum "$SOURCE/ed301_eddsa.py" | awk '{print $1}')" = \
    2364f483696c81dba7b81f0cc37f4037983a2c6795c204586e6c09f6a3669bf3
test "$(sha256sum "$SOURCE/MANIFEST.sha256" | awk '{print $1}')" = \
    bda1c016894a55efb94fab1df5969b3540fc797bd9121214853d6a555a208fca
(cd "$SOURCE" && sha256sum --strict --quiet -c MANIFEST.sha256)

/usr/bin/python3 -I -B "$ORACLE/materialize_vectors.py" \
    "$ROOT" "$WORK/blind_oracle_vectors.json"
cmp "$WORK/blind_oracle_vectors.json" "$VECTORS"
/usr/bin/python3 -I -B "$ORACLE/test_oracle.py"
/usr/bin/python3 -I -B -O "$ORACLE/test_oracle.py"

printf '%s\n' 'blind_reference_gate=PASS source=immutable adapter=strict-bytes'
