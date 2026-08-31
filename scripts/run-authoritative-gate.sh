#!/usr/bin/env -S -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C ED301_LAUNCH_STAGE=clean /bin/sh
set -eu

if [ "${ED301_LAUNCH_STAGE:-}" != clean ]; then
    exec /usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
        ED301_LAUNCH_STAGE=clean /bin/sh "$0" "$@"
fi
unset ED301_LAUNCH_STAGE

PATH=/usr/bin:/bin
HOME=/nonexistent
LC_ALL=C
export PATH HOME LC_ALL
umask 077

ROOT=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")/.." && /bin/pwd -P)

usage() {
    echo "usage: $0 archive <manifest-sha256> <gate> [gate-arguments...]" >&2
    echo "       $0 git <manifest-sha256> <commit> verify-source-tree" >&2
    exit 2
}

[ "$#" -ge 3 ] || usage
MODE=$1
MANIFEST_DIGEST=$2
shift 2

if [ "${#MANIFEST_DIGEST}" -ne 64 ]; then
    echo "manifest digest must be a lowercase SHA-256" >&2
    exit 2
fi
case "$MANIFEST_DIGEST" in
    *[!0-9a-f]*)
        echo "manifest digest must be a lowercase SHA-256" >&2
        exit 2
        ;;
esac

ED301_HERMETIC_LAUNCH=1
ED301_SOURCE_MODE=$MODE
ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$MANIFEST_DIGEST
export ED301_HERMETIC_LAUNCH ED301_SOURCE_MODE
export ED301_EXPECTED_SOURCE_MANIFEST_SHA256

case "$MODE" in
    archive)
        ED301_VERIFIED_SNAPSHOT=1
        export ED301_VERIFIED_SNAPSHOT
        ;;
    git)
        [ "$#" -eq 2 ] || usage
        ED301_EXPECTED_GIT_COMMIT=$1
        [ "${#ED301_EXPECTED_GIT_COMMIT}" -eq 40 ] || usage
        case "$ED301_EXPECTED_GIT_COMMIT" in
            *[!0-9a-f]*) usage ;;
        esac
        export ED301_EXPECTED_GIT_COMMIT
        shift
        [ "$1" = verify-source-tree ] || usage
        ;;
    *) usage ;;
esac

GATE=$1
shift
TARGET_SHELL=/bin/sh
case "$GATE" in
    environment-check)
        TARGET=$ROOT/scripts/check-rust-build-environment.sh
        ;;
    verify-source-tree)
        TARGET=$ROOT/scripts/verify-source-tree.sh
        ;;
    check)
        TARGET=$ROOT/scripts/check.sh
        ;;
    check-downstream)
        TARGET=$ROOT/scripts/check-downstream.sh
        ;;
    check-secret-taint)
        TARGET=$ROOT/scripts/check-secret-taint.sh
        ;;
    review-tests)
        TARGET=$ROOT/review-tests/run.sh
        [ "$#" -eq 0 ] || usage
        ;;
    build-openssl-provider-lane)
        TARGET=$ROOT/scripts/build-openssl-provider-lane.sh
        TARGET_SHELL=/bin/bash
        ;;
    verify-openssl-provider-lane)
        TARGET=$ROOT/scripts/verify-openssl-provider-lane.sh
        ;;
    test-provider)
        TARGET=$ROOT/scripts/test-provider.sh
        TARGET_SHELL=/bin/bash
        ;;
    *) usage ;;
esac

if [ "$TARGET_SHELL" = /bin/bash ]; then
    exec /bin/bash --noprofile --norc "$TARGET" "$@"
fi
exec /bin/sh "$TARGET" "$@"
