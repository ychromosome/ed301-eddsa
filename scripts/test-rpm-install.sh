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
command -v update-crypto-policies >/dev/null

RPM_DIR=$1
BACKEND=/etc/crypto-policies/back-ends/opensslcnf.config
ACTIVE=/etc/crypto-policies/local.d/opensslcnf-zz-ed301.config
PACKAGE=$(find "$RPM_DIR" -maxdepth 1 -type f \
    -name 'ed301-openssl-provider-0*.rpm' -print -quit)
POLICY_PACKAGE=$(find "$RPM_DIR" -maxdepth 1 -type f \
    -name 'ed301-openssl-provider-policy-0*.rpm' -print -quit)
test -n "$PACKAGE" && test -n "$POLICY_PACKAGE"
if rpm -q ed301-openssl-provider >/dev/null 2>&1; then
    echo 'container already has the Ed301 package installed' >&2
    exit 2
fi

cleanup() {
    dnf -qy remove ed301-openssl-provider-policy \
        ed301-openssl-provider >/dev/null 2>&1 || :
    update-crypto-policies --set DEFAULT >/dev/null 2>&1 || :
}
trap cleanup EXIT HUP INT TERM

dnf -qy install "$PACKAGE" >/dev/null
test -f /usr/lib64/ossl-modules/ed301_eddsa_v1.so
test ! -e /etc/pki/tls/openssl.d/ed301-tls-experiment.conf
test ! -e "$ACTIVE"
if openssl list -providers | grep -F ed301_eddsa_v1 >/dev/null; then
    echo 'ordinary provider became globally active' >&2
    exit 1
fi
openssl list -provider default -provider ed301_eddsa_v1 \
    -signature-algorithms | grep -F Ed301-EdDSA-v1 >/dev/null

dnf -qy reinstall "$PACKAGE" >/dev/null
openssl list -provider default -provider ed301_eddsa_v1 \
    -signature-algorithms | grep -F Ed301-EdDSA-v1 >/dev/null

dnf -qy install "$POLICY_PACKAGE" >/dev/null
test -f /usr/lib64/ossl-modules/ed301_eddsa_v1_tls_test.so
test -f /etc/pki/tls/openssl.d/ed301-tls-experiment.conf
test ! -e "$ACTIVE"
rpm -ql ed301-openssl-provider-policy \
    | grep -F '/opensslcnf-zz-ed301.config.example' >/dev/null
openssl list -providers | grep -F ed301_eddsa_v1_tls_test >/dev/null
openssl list -signature-algorithms | grep -F Ed301-EdDSA-v1 >/dev/null

for policy in DEFAULT FUTURE FIPS BSI EMPTY; do
    if test -f "/usr/share/crypto-policies/policies/$policy.pol"; then
        update-crypto-policies --set "$policy" >/dev/null
        if grep -F ed301_eddsa_v1_test "$BACKEND" >/dev/null; then
            echo "inert Ed301 package changed policy $policy" >&2
            exit 1
        fi
    fi
done
update-crypto-policies --set DEFAULT >/dev/null

dnf -qy remove ed301-openssl-provider-policy >/dev/null
test ! -e /usr/lib64/ossl-modules/ed301_eddsa_v1_tls_test.so
test ! -e /etc/pki/tls/openssl.d/ed301-tls-experiment.conf
test ! -e "$ACTIVE"
test -f /usr/lib64/ossl-modules/ed301_eddsa_v1.so
dnf -qy remove ed301-openssl-provider >/dev/null
test ! -e /usr/lib64/ossl-modules/ed301_eddsa_v1.so

printf '%s\n' \
    'ed301_rpm_install=PASS base=explicit tls_provider=active policy=inert transitions=clean reinstall=clean remove=clean'
