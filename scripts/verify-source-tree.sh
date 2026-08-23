#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
MANIFEST=$ROOT/SOURCE_MANIFEST.sha256

for tool in awk cmp diff find grep mktemp sed sha256sum sort tr wc; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing source-verifier tool: $tool" >&2
        exit 127
    }
done

test -f "$MANIFEST" || {
    echo "missing source manifest: $MANIFEST" >&2
    exit 1
}

TMP=$(mktemp -d "${TMPDIR:-/tmp}/ed301-source-tree.XXXXXX")
cleanup() {
    rm -rf -- "$TMP"
}
trap cleanup EXIT HUP INT TERM

for generated_directory in target provider/target \
        integration/downstream-workspace/target secret-taint/target \
        secret-taint/valgrind-client/target; do
    generated_path=$ROOT/$generated_directory
    if [ -e "$generated_path" ] || [ -L "$generated_path" ]; then
        if [ ! -d "$generated_path" ] || [ -L "$generated_path" ]; then
            echo "reserved build path is not a real directory: $generated_directory" >&2
            exit 1
        fi
    fi
done

manifest_digest=$(sha256sum "$MANIFEST" | awk '{ print $1 }')
expected_digest=${ED301_EXPECTED_SOURCE_MANIFEST_SHA256:-}

if [ -n "$expected_digest" ]; then
    if ! printf '%s\n' "$expected_digest" \
            | grep -Eq '^[0-9a-f]{64}$'; then
        echo "ED301_EXPECTED_SOURCE_MANIFEST_SHA256 is not lowercase SHA-256" >&2
        exit 2
    fi
    if [ "$manifest_digest" != "$expected_digest" ]; then
        echo "source manifest does not match the externally supplied digest" >&2
        echo "expected: $expected_digest" >&2
        echo "actual:   $manifest_digest" >&2
        exit 1
    fi
    anchor="external manifest digest $expected_digest"
elif command -v git >/dev/null 2>&1 \
        && git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git_root=$(git -C "$ROOT" rev-parse --show-toplevel)
    git_root=$(CDPATH= cd -- "$git_root" && pwd -P)
    if [ "$git_root" != "$ROOT" ]; then
        echo "source root is not the Git worktree root" >&2
        exit 1
    fi
    if ! git -C "$ROOT" show HEAD:SOURCE_MANIFEST.sha256 \
            >"$TMP/manifest.from-head"; then
        echo "HEAD does not contain SOURCE_MANIFEST.sha256" >&2
        exit 1
    fi
    if ! cmp -s "$MANIFEST" "$TMP/manifest.from-head"; then
        echo "working source manifest is not anchored to HEAD" >&2
        echo "for an intentional uncommitted candidate, supply its trusted digest" >&2
        echo "through ED301_EXPECTED_SOURCE_MANIFEST_SHA256" >&2
        exit 1
    fi
    revision=$(git -C "$ROOT" rev-parse HEAD)
    anchor="Git HEAD $revision"
else
    echo "source manifest has no external trust anchor" >&2
    echo "verify the enclosing archive first, then pass its trusted manifest" >&2
    echo "digest through ED301_EXPECTED_SOURCE_MANIFEST_SHA256" >&2
    exit 1
fi

LC_ALL=C awk '
    {
        digest = substr($0, 1, 64)
        separator = substr($0, 65, 2)
        path = substr($0, 67)
        if (length(digest) != 64 || digest !~ /^[0-9a-f]+$/ ||
                separator != "  " || path == "") {
            print "invalid source-manifest line " NR > "/dev/stderr"
            exit 1
        }
        if (path !~ /^[A-Za-z0-9._+\/-]+$/ || substr(path, 1, 1) == "/" ||
                path ~ /(^|\/)\.\.?(\/|$)/ || path ~ /\/\// ||
                path == "SOURCE_MANIFEST.sha256") {
            print "unsafe source-manifest path at line " NR ": " path \
                > "/dev/stderr"
            exit 1
        }
        if (previous != "" && path <= previous) {
            print "source-manifest paths are not strictly sorted at line " NR \
                > "/dev/stderr"
            exit 1
        }
        print path
        previous = path
    }
' "$MANIFEST" >"$TMP/expected-files"

LC_ALL=C awk '
    {
        count = split($0, component, "/")
        directory = ""
        for (part_index = 1; part_index < count; part_index++) {
            if (directory == "")
                directory = component[part_index]
            else
                directory = directory "/" component[part_index]
            print directory
        }
    }
' "$TMP/expected-files" | LC_ALL=C sort -u >"$TMP/expected-directories"

(
    cd "$ROOT"
    find . -mindepth 1 \
        \( -path './.git' -o -path './target' \
           -o -path './provider/target' \
           -o -path './integration/downstream-workspace/target' \
           -o -path './secret-taint/target' \
           -o -path './secret-taint/valgrind-client/target' \) -prune -o \
        ! -type d ! -type f -print
) >"$TMP/special-paths"
if [ -s "$TMP/special-paths" ]; then
    echo "source tree contains symlinks or other non-regular paths:" >&2
    sed -n '1,20p' "$TMP/special-paths" >&2
    exit 1
fi

(
    cd "$ROOT"
    find . -mindepth 1 \
        \( -path './.git' -o -path './target' \
           -o -path './provider/target' \
           -o -path './integration/downstream-workspace/target' \
           -o -path './secret-taint/target' \
           -o -path './secret-taint/valgrind-client/target' \) -prune -o \
        -type f ! -path './SOURCE_MANIFEST.sha256' -print
) | sed 's|^\./||' | LC_ALL=C sort >"$TMP/actual-files"

(
    cd "$ROOT"
    find . -mindepth 1 \
        \( -path './.git' -o -path './target' \
           -o -path './provider/target' \
           -o -path './integration/downstream-workspace/target' \
           -o -path './secret-taint/target' \
           -o -path './secret-taint/valgrind-client/target' \) -prune -o \
        -type d -print
) | sed 's|^\./||' | LC_ALL=C sort >"$TMP/actual-directories"

if ! cmp -s "$TMP/expected-files" "$TMP/actual-files"; then
    echo "source file inventory does not match SOURCE_MANIFEST.sha256" >&2
    diff -u "$TMP/expected-files" "$TMP/actual-files" >&2 || true
    exit 1
fi
if ! cmp -s "$TMP/expected-directories" "$TMP/actual-directories"; then
    echo "source directory inventory is not derived solely from listed files" >&2
    diff -u "$TMP/expected-directories" "$TMP/actual-directories" >&2 || true
    exit 1
fi

(cd "$ROOT" && sha256sum --strict --quiet -c SOURCE_MANIFEST.sha256)
printf 'source_tree_verification=PASS anchor=%s files=%s directories=%s\n' \
    "$anchor" \
    "$(wc -l <"$TMP/expected-files" | tr -d ' ')" \
    "$(wc -l <"$TMP/expected-directories" | tr -d ' ')"
