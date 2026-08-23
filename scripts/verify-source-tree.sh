#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
MANIFEST=$ROOT/SOURCE_MANIFEST.sha256
MODE=${ED301_SOURCE_MODE:-}
EXPECTED_DIGEST=${ED301_EXPECTED_SOURCE_MANIFEST_SHA256:-}

for tool in awk cmp diff find grep mktemp sed sha256sum sort tr wc; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing source-verifier tool: $tool" >&2
        exit 127
    }
done

if ! printf '%s\n' "$EXPECTED_DIGEST" | grep -Eq '^[0-9a-f]{64}$'; then
    echo "ED301_EXPECTED_SOURCE_MANIFEST_SHA256 must be an external lowercase SHA-256" >&2
    exit 2
fi
test -f "$MANIFEST" && test ! -L "$MANIFEST" || {
    echo "missing regular source manifest: $MANIFEST" >&2
    exit 1
}

TMP=$(mktemp -d /tmp/ed301-source-tree.XXXXXX)
cleanup() {
    rm -rf -- "$TMP"
}
trap cleanup EXIT HUP INT TERM
mkdir -m 700 "$TMP/home"

manifest_digest=$(sha256sum "$MANIFEST" | awk '{ print $1 }')
if [ "$manifest_digest" != "$EXPECTED_DIGEST" ]; then
    echo "source manifest does not match the external trust anchor" >&2
    echo "expected: $EXPECTED_DIGEST" >&2
    echo "actual:   $manifest_digest" >&2
    exit 1
fi

case "$MODE" in
    git)
        EXPECTED_COMMIT=${ED301_EXPECTED_GIT_COMMIT:-}
        if ! printf '%s\n' "$EXPECTED_COMMIT" \
                | grep -Eq '^[0-9a-f]{40}$'; then
            echo "git mode requires external ED301_EXPECTED_GIT_COMMIT" >&2
            exit 2
        fi
        test -d "$ROOT/.git" && test ! -L "$ROOT/.git" || {
            echo "git mode requires a non-symlink .git directory at the source root" >&2
            exit 1
        }
        git_clean() {
            env -i PATH=/usr/bin:/bin HOME="$TMP/home" LC_ALL=C \
                GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
                /usr/bin/git --no-optional-locks --no-replace-objects \
                -C "$ROOT" "$@"
        }
        git_root=$(git_clean rev-parse --show-toplevel)
        git_root=$(CDPATH= cd -- "$git_root" && pwd -P)
        [ "$git_root" = "$ROOT" ] || {
            echo "source root is not the Git worktree root" >&2
            exit 1
        }
        revision=$(git_clean rev-parse --verify 'HEAD^{commit}')
        [ "$revision" = "$EXPECTED_COMMIT" ] || {
            echo "Git HEAD does not match the external commit anchor" >&2
            exit 1
        }
        git_clean cat-file blob \
            "$EXPECTED_COMMIT:SOURCE_MANIFEST.sha256" \
            >"$TMP/manifest.from-commit"
        cmp -s "$MANIFEST" "$TMP/manifest.from-commit" || {
            echo "source manifest is not the blob from the anchored commit" >&2
            exit 1
        }
        anchor="git-commit:$EXPECTED_COMMIT manifest:$EXPECTED_DIGEST"
        ;;
    archive)
        if [ -e "$ROOT/.git" ] || [ -L "$ROOT/.git" ]; then
            echo "archive mode rejects Git metadata" >&2
            exit 1
        fi
        if [ -n "${ED301_EXPECTED_GIT_COMMIT:-}" ]; then
            echo "archive mode rejects ED301_EXPECTED_GIT_COMMIT" >&2
            exit 2
        fi
        anchor="archive-manifest:$EXPECTED_DIGEST"
        ;;
    *)
        echo "ED301_SOURCE_MODE must explicitly be git or archive" >&2
        exit 2
        ;;
esac

awk '
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

awk '
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
' "$TMP/expected-files" | sort -u >"$TMP/expected-directories"

(
    cd "$ROOT"
    find . -mindepth 1 \
        \( -path './.git' \) -prune -o \
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
        \( -path './.git' \) -prune -o \
        -type f ! -path './SOURCE_MANIFEST.sha256' -print
) | sed 's|^\./||' | sort >"$TMP/actual-files"

(
    cd "$ROOT"
    find . -mindepth 1 \
        \( -path './.git' \) -prune -o \
        -type d -print
) | sed 's|^\./||' | sort >"$TMP/actual-directories"

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
