#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
SPEC=$ROOT/packaging/rpm/ed301-openssl-provider.spec
PATCH=$ROOT/packaging/rpm/0001-Allow-standard-RPM-native-build-flags.patch

command -v rpmspec >/dev/null
rpmspec -P "$SPEC" >/dev/null
git -C "$ROOT" apply --check --whitespace=error-all "$PATCH"

commit=$(awk '$1 == "%global" && $2 == "commit" { print $3 }' "$SPEC")
case $commit in
    *[!0-9a-f]* ) echo 'RPM Source0 commit is not hexadecimal' >&2; exit 1 ;;
esac
test "${#commit}" -eq 40

printf '%s\n' 'ed301_rpm_packaging=PASS'
