#!/bin/sh
set -eu

test -e /run/.containerenv || test -e /.dockerenv || {
    echo 'this test may run only inside a disposable container' >&2
    exit 2
}
test "$(id -u)" -eq 0 || {
    echo 'this container test requires root' >&2
    exit 2
}
test "$#" -eq 1 || {
    echo "usage: $0 RPM_DIRECTORY" >&2
    exit 2
}

RPM_DIR=$1
PACKAGE=$(find "$RPM_DIR" -maxdepth 1 -type f \
    -name 'ed301-openssl-provider-0*.rpm' -print -quit)
test -n "$PACKAGE"
if rpm -q ed301-openssl-provider >/dev/null 2>&1; then
    echo 'container already has the Ed301 package installed' >&2
    exit 2
fi

cleanup() {
    dnf -qy remove ed301-openssl-provider >/dev/null 2>&1 || :
}
trap cleanup EXIT HUP INT TERM

dnf -qy install "$PACKAGE" >/dev/null
test -f /usr/lib64/ossl-modules/ed301_eddsa_v1.so
test -f /etc/pki/tls/openssl.d/ed301-provider.conf
openssl list -providers | grep -F ed301_eddsa_v1 >/dev/null
openssl list -signature-algorithms | grep -F Ed301-EdDSA-v1 >/dev/null

dnf -qy reinstall "$PACKAGE" >/dev/null
openssl list -signature-algorithms | grep -F Ed301-EdDSA-v1 >/dev/null
dnf -qy remove ed301-openssl-provider >/dev/null
test ! -e /usr/lib64/ossl-modules/ed301_eddsa_v1.so
test ! -e /etc/pki/tls/openssl.d/ed301-provider.conf

printf '%s\n' 'ed301_rpm_install=PASS provider=active reinstall=clean remove=clean'
