#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
SPEC=$ROOT/packaging/rpm/ed301-openssl-provider.spec
PATCH=$ROOT/packaging/rpm/0001-Allow-standard-RPM-native-build-flags.patch
RPM_DIR=$ROOT/packaging/rpm

command -v rpmspec >/dev/null
rpmspec -P "$SPEC" >/dev/null
git -C "$ROOT" apply --check --whitespace=error-all "$PATCH"

awk '$1 ~ /^(Source[1-9][0-9]*|Patch[0-9]+):$/ { print $2 }' "$SPEC" \
    | while IFS= read -r source; do
        test -f "$RPM_DIR/$source" || {
            echo "missing local RPM source: $source" >&2
            exit 1
        }
    done

commit=$(awk '$1 == "%global" && $2 == "commit" { print $3 }' "$SPEC")
case $commit in
    *[!0-9a-f]* ) echo 'RPM Source0 commit is not hexadecimal' >&2; exit 1 ;;
esac
test "${#commit}" -eq 40

grep -F 'opensslcnf-zz-ed301.config.example' "$SPEC" >/dev/null
if sed '/^%changelog/,$d' "$SPEC" \
        | grep -F '%{_sysconfdir}/crypto-policies/local.d/' >/dev/null
then
    echo 'policy package still installs an active crypto-policy overlay' >&2
    exit 1
fi

printf '%s\n' 'ed301_rpm_packaging=PASS'
