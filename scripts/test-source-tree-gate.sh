#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
for tool in cp ln mkfifo mktemp tar; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing source-gate regression tool: $tool" >&2
        exit 127
    }
done
test -x /usr/bin/cargo || {
    echo "missing canonical Cargo for source-path regressions" >&2
    exit 127
}

TMP=$(mktemp -d "${TMPDIR:-/tmp}/ed301-source-gate-test.XXXXXX")
unset TMPDIR
cleanup() {
    rm -rf -- "$TMP"
}
trap cleanup EXIT HUP INT TERM

BASE=$TMP/base
mkdir -p "$BASE"
(
    cd "$ROOT"
    {
        printf '%s\n' SOURCE_MANIFEST.sha256
        awk '{ print substr($0, 67) }' SOURCE_MANIFEST.sha256
    } | tar -cf "$TMP/source.tar" -T -
)
tar -xf "$TMP/source.tar" -C "$BASE"
chmod -R u+w "$BASE"
EXPECTED=$(sha256sum "$BASE/SOURCE_MANIFEST.sha256" | awk '{ print $1 }')

ED301_SOURCE_MODE=archive \
ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$BASE/scripts/verify-source-tree.sh" >/dev/null

new_case() {
    CASE=$TMP/case-$1
    mkdir -p "$CASE"
    cp -a "$BASE/." "$CASE/"
    chmod -R u+w "$CASE"
}

must_reject() {
    label=$1
    shift
    if "$@" >"$TMP/$label.log" 2>&1; then
        echo "source gate accepted malicious case: $label" >&2
        exit 1
    fi
}

new_case build-script
printf '%s\n' 'fn main() { panic!("must not execute"); }' \
    >"$CASE/crates/ed301-eddsa/build.rs"
must_reject build-script env ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

for kind in tests examples benches; do
    new_case "$kind"
    mkdir -p "$CASE/crates/ed301-eddsa/$kind"
    printf '%s\n' '#![allow(dead_code)]' \
        >"$CASE/crates/ed301-eddsa/$kind/unlisted.rs"
    must_reject "$kind" env \
        ED301_SOURCE_MODE=archive \
        ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
        sh "$CASE/scripts/verify-source-tree.sh"
done

new_case symlink
ln -s README.md "$CASE/unlisted-link"
must_reject symlink env ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case reserved-target-symlink
ln -s README.md "$CASE/target"
must_reject reserved-target-symlink env \
    ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case reserved-target-file
printf '%s\n' 'not a build directory' >"$CASE/target"
must_reject reserved-target-file env \
    ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case reserved-target-directory
mkdir "$CASE/target"
printf '%s\n' 'untrusted prior artifact' >"$CASE/target/injected"
must_reject reserved-target-directory env \
    ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case fifo
mkfifo "$CASE/unlisted-fifo"
must_reject fifo env ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case empty-directory
mkdir "$CASE/unlisted-directory"
must_reject empty-directory env \
    ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case missing-file
rm "$CASE/README.md"
must_reject missing-file env \
    ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case altered-manifest
printf '%s\n' '# attacker-controlled replacement' \
    >>"$CASE/SOURCE_MANIFEST.sha256"
must_reject altered-manifest env \
    ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case caller-order
printf '%s\n' 'fn main() { panic!("must not execute"); }' \
    >"$CASE/crates/ed301-eddsa/build.rs"
mkdir -p "$CASE/fakebin" "$CASE/cargo-home"
cat >"$CASE/fakebin/cargo" <<'EOF'
#!/bin/sh
printf 'cargo reached\n' >"$FAKE_CARGO_SENTINEL"
exit 99
EOF
chmod +x "$CASE/fakebin/cargo"
SENTINEL=$CASE/cargo-was-reached
for gate in scripts/check.sh scripts/check-downstream.sh \
        scripts/check-secret-taint.sh; do
    must_reject "caller-$(basename "$gate")" env \
        PATH="$CASE/fakebin:$PATH" \
        CARGO_HOME="$CASE/cargo-home" \
        FAKE_CARGO_SENTINEL="$SENTINEL" \
        ED301_SOURCE_MODE=archive \
        ED301_VERIFIED_SNAPSHOT=1 \
        ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
        sh "$CASE/$gate"
    if [ -e "$SENTINEL" ]; then
        echo "$gate reached Cargo before rejecting the source tree" >&2
        exit 1
    fi
done

CARGO_HOME_DIR=$TMP/cargo-path-home
CARGO_TARGET_DIR=$TMP/cargo-path-target
CARGO_USER_HOME=$TMP/cargo-path-user-home
mkdir -p "$CARGO_HOME_DIR" "$CARGO_TARGET_DIR" "$CARGO_USER_HOME"

check_cargo_source_path() {
    test_root=$TMP/$1
    mkdir -p "$test_root/vendor"
    /usr/bin/python3 -I -B "$ROOT/scripts/write-cargo-config.py" \
        "$test_root/config.toml" "$test_root/vendor"
    /usr/bin/python3 -I -B - "$test_root/config.toml" \
        "$test_root/vendor" <<'PY'
import pathlib
import sys
import tomllib

config_path, vendor_path = sys.argv[1:]
with open(config_path, "rb") as source:
    configured = tomllib.load(source)["source"]["vendored-sources"]["directory"]
expected = str(pathlib.Path(vendor_path).resolve(strict=True))
if configured != expected:
    raise SystemExit("serialized Cargo source path changed value")
PY
}

check_cargo_source_path 'quote"path'
check_cargo_source_path "apostrophe'path"
check_cargo_source_path 'comment#path'
check_cargo_source_path 'back\slash'
newline_name=$(printf 'new\nline')
check_cargo_source_path "$newline_name"
check_cargo_source_path 'unicode-😀'

/usr/bin/python3 -I -B "$ROOT/scripts/write-cargo-config.py" \
    "$CARGO_HOME_DIR/config.toml" "$ROOT/vendor"
(cd / && env -i PATH=/usr/bin:/bin HOME="$CARGO_USER_HOME" LC_ALL=C \
    CARGO_HOME="$CARGO_HOME_DIR" CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
    CARGO_NET_OFFLINE=true /usr/bin/cargo metadata \
        --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        --format-version=1 >/dev/null)

for gate in scripts/check.sh scripts/check-downstream.sh \
        scripts/check-secret-taint.sh scripts/test-provider.sh \
        review-tests/run.sh; do
    grep -F 'scripts/write-cargo-config.py' "$ROOT/$gate" >/dev/null || {
        echo "$gate does not bind Cargo to the verified vendor directory" >&2
        exit 1
    }
done

printf 'source_tree_gate_regressions=PASS cases=15 cargo_path_cases=7\n'
