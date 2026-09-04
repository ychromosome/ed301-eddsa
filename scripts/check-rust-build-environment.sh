#!/bin/sh
set -eu

PATH=/usr/bin:/bin
HOME=/nonexistent
LC_ALL=C
export PATH HOME LC_ALL

case "${1:-}" in
    "") CHECK_TOOLS=1 ;;
    --environment-only) CHECK_TOOLS=0 ;;
    *) echo "usage: $0 [--environment-only]" >&2; exit 2 ;;
esac

if [ "${ED301_HERMETIC_LAUNCH:-}" != 1 ]; then
    echo "authoritative gates require scripts/run-authoritative-gate.sh" >&2
    exit 2
fi

ALLOWED='^(ED301_BENCH_PINNED|ED301_HERMETIC_LAUNCH|ED301_SOURCE_MODE|ED301_VERIFIED_SNAPSHOT|ED301_EXPECTED_SOURCE_MANIFEST_SHA256|ED301_EXPECTED_GIT_COMMIT|ED301_MODULE_DIR|ED301_PROVIDER_CONTEXT_HARNESS|ED301_PROVIDER_RESULT_ROOT|ED301_TIMING_MEASUREMENTS|OPENSSL_PREFIX|OPENSSL_OBJECT_LISTS|PATH|HOME|LC_ALL|PWD|SHLVL|_)='

if /usr/bin/env -0 | /usr/bin/awk -v RS='\0' -v pattern="$ALLOWED" '
        $0 !~ pattern { found = 1 }
        END { exit !found }
    '; then
    echo "authoritative gate environment contains a non-allowlisted value" >&2
    /usr/bin/env -0 | /usr/bin/awk -v RS='\0' -v pattern="$ALLOWED" '
        $0 !~ pattern {
            name = $0
            sub(/=.*/, "", name)
            print name "=<redacted>"
        }
    ' | /usr/bin/sort >&2
    exit 1
fi

if [ "$CHECK_TOOLS" -eq 1 ]; then
    for tool in /usr/bin/cargo /usr/bin/rustc /usr/bin/rustfmt \
            /usr/bin/cargo-clippy /usr/bin/rustdoc /usr/bin/gcc /usr/bin/ar \
            /usr/bin/python3; do
        test -x "$tool" || {
            echo "missing canonical build tool: $tool" >&2
            exit 127
        }
    done
fi

printf 'gate_environment=PASS launcher=hermetic tools=%s path=%s\n' \
    "$CHECK_TOOLS" "$PATH"
