#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
for tool in cp ln mkfifo mktemp tar; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing source-gate regression tool: $tool" >&2
        exit 127
    }
done

TMP=$(mktemp -d "${TMPDIR:-/tmp}/ed301-source-gate-test.XXXXXX")
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
EXPECTED=$(sha256sum "$BASE/SOURCE_MANIFEST.sha256" | awk '{ print $1 }')

ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$BASE/scripts/verify-source-tree.sh" >/dev/null

new_case() {
    CASE=$TMP/case-$1
    mkdir -p "$CASE"
    cp -a "$BASE/." "$CASE/"
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
must_reject build-script env ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

for kind in tests examples benches; do
    new_case "$kind"
    mkdir -p "$CASE/crates/ed301-eddsa/$kind"
    printf '%s\n' '#![allow(dead_code)]' \
        >"$CASE/crates/ed301-eddsa/$kind/unlisted.rs"
    must_reject "$kind" env \
        ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
        sh "$CASE/scripts/verify-source-tree.sh"
done

new_case symlink
ln -s README.md "$CASE/unlisted-link"
must_reject symlink env ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case reserved-target-symlink
ln -s README.md "$CASE/target"
must_reject reserved-target-symlink env \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case reserved-target-file
printf '%s\n' 'not a build directory' >"$CASE/target"
must_reject reserved-target-file env \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case fifo
mkfifo "$CASE/unlisted-fifo"
must_reject fifo env ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case empty-directory
mkdir "$CASE/unlisted-directory"
must_reject empty-directory env \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case missing-file
rm "$CASE/README.md"
must_reject missing-file env \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case altered-manifest
printf '%s\n' '# attacker-controlled replacement' \
    >>"$CASE/SOURCE_MANIFEST.sha256"
must_reject altered-manifest env \
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
        ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
        sh "$CASE/$gate"
    if [ -e "$SENTINEL" ]; then
        echo "$gate reached Cargo before rejecting the source tree" >&2
        exit 1
    fi
done

printf 'source_tree_gate_regressions=PASS cases=14\n'
