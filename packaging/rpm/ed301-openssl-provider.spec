%bcond_without tests

%global commit 69b30b6182765029d8e3b508bde81a3d9c6a3c15
%global shortcommit 69b30b6
%global snapshot 20260904
%global source_manifest_sha256 324c1fb6378104d58de6afffb61f8f77c10b0eadafc05cdacb7f76ecb8bc596a
%global openssl_fork_evr 1:4.1.0~dev.1-0.3.git7d9c89d%{?dist}
%global provider_modulesdir %{_libdir}/ossl-modules
%global __provides_exclude_from ^%{provider_modulesdir}/.*\.so$

Name:           ed301-openssl-provider
Version:        0.1.0
Release:        0.11.%{snapshot}git%{shortcommit}%{?dist}
Summary:        Experimental Ed301-EdDSA provider for OpenSSL
License:        Apache-2.0
URL:            https://github.com/ychromosome/ed301-eddsa
Source0:        %{url}/archive/%{commit}/ed301-eddsa-%{commit}.tar.gz
Source1:        ed301-tls-experiment.conf
Source2:        opensslcnf-zz-ed301.config
Source3:        README.crypto-policy
Patch0:         0001-Allow-standard-RPM-native-build-flags.patch

BuildRequires:  cargo-rpm-macros
BuildRequires:  cargo >= 1.91
BuildRequires:  rust >= 1.91
BuildRequires:  gcc
BuildRequires:  binutils
BuildRequires:  openssl = %{openssl_fork_evr}
BuildRequires:  openssl-devel = %{openssl_fork_evr}
%if %{with tests}
BuildRequires:  python3
BuildRequires:  rustfmt
%endif

Requires:       openssl-libs%{?_isa} = %{openssl_fork_evr}

# crypto-bigint is a source-bound path dependency.
Provides:       bundled(crate(crypto-bigint)) = 0.7.5
Provides:       bundled(crate(cpufeatures)) = 0.3.0

%description
Ed301-EdDSA-v1 is an experimental signature algorithm. This package installs
the ordinary OpenSSL provider for explicit loading. It does not activate the
provider globally or advertise a TLS signature scheme. The algorithm is not
standardized or FIPS validated.

%package policy
Summary:        Private-use Ed301 TLS experiment for the review environment
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       openssl-libs%{?_isa} = %{openssl_fork_evr}
# Rebuild once after upgrading from releases that installed a local.d file.
Requires(posttrans): crypto-policies-scripts

%description policy
This laboratory package activates the separately named Ed301 TLS experiment
provider. It advertises a private-use TLS signature scheme for the joint test.
It includes an inert OpenSSL policy-fragment example but does not change the
selected Fedora crypto policy.

%prep
%setup -q -n ed301-eddsa-%{commit}
test "$(sha256sum SOURCE_MANIFEST.sha256 | awk '{ print $1 }')" = \
    %{source_manifest_sha256}
sha256sum --strict --quiet -c SOURCE_MANIFEST.sha256
%autopatch -p1
install -pm 0644 %{SOURCE3} README.crypto-policy
install -pm 0644 %{SOURCE2} opensslcnf-zz-ed301.config.example
pushd provider
%cargo_prep -v ../vendor
popd

%build
%set_build_flags
pushd provider
export CC=/usr/bin/gcc
export AR=/usr/bin/ar
export ED301_HERMETIC_PROVIDER_BUILD=1
export ED301_ALLOW_PACKAGE_BUILD_FLAGS=1
export OPENSSL_INCLUDE_DIR=%{_includedir}
export OPENSSL_LIB_DIR=%{_libdir}
export CARGO_INCREMENTAL=0

%cargo_build -- -p ed301-eddsa-provider
install -Dpm 0755 target/rpm/libed301_eddsa_v1.so \
    ../target/rpm-package-modules/ed301_eddsa_v1.so

%cargo_build -f tls-experiment -- -p ed301-eddsa-provider
install -Dpm 0755 target/rpm/libed301_eddsa_v1.so \
    ../target/rpm-package-modules/ed301_eddsa_v1_tls_test.so

pushd crates/ed301-eddsa-provider
%cargo_license_summary
%{cargo_license} > ../../../LICENSE.dependencies
popd
%cargo_vendor_manifest
sed -i '\| (/|d' cargo-vendor.txt
popd

%install
install -Dpm 0755 target/rpm-package-modules/ed301_eddsa_v1.so \
    %{buildroot}%{provider_modulesdir}/ed301_eddsa_v1.so
install -Dpm 0755 target/rpm-package-modules/ed301_eddsa_v1_tls_test.so \
    %{buildroot}%{provider_modulesdir}/ed301_eddsa_v1_tls_test.so
install -Dpm 0644 %{SOURCE1} \
    %{buildroot}%{_sysconfdir}/pki/tls/openssl.d/ed301-tls-experiment.conf

%check
%if %{with tests}
env CARGO_HOME=.cargo CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 \
    RUSTFLAGS='%{build_rustflags}' \
    /usr/bin/cargo test --release --locked --offline --workspace

test_dir=target/rpm-package-tests
mkdir -p "$test_dir"
python3 -I -B provider-tests/gen_vectors.py . \
    "$test_dir/vectors.h" "$test_dir/policy_vectors_data.rs"
rustfmt --edition 2024 "$test_dir/policy_vectors_data.rs"
cmp "$test_dir/policy_vectors_data.rs" \
    provider/crates/ed301-eddsa-provider/src/policy_vectors_data.rs

%{__cc} %{build_cflags} -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror \
    -I%{_includedir} \
    -Iprovider/crates/ed301-eddsa-provider/c \
    -I"$test_dir" -Iprovider-tests \
    -o "$test_dir/provider_signature" \
    provider-tests/provider_signature.c %{build_ldflags} \
    -lcrypto -lssl -lpthread -ldl
for module in \
        target/rpm-package-modules/ed301_eddsa_v1.so \
        target/rpm-package-modules/ed301_eddsa_v1_tls_test.so; do
    test "$(nm -D --defined-only "$module" \
        | awk '$2 == "T" { count++ } END { print count + 0 }')" -eq 1
    nm -D --defined-only "$module" | grep -E ' T OSSL_provider_init$' >/dev/null
    if readelf -d "$module" | grep -Eq '\((RPATH|RUNPATH)\)'; then
        echo "provider module contains an RPATH or RUNPATH: $module" >&2
        exit 1
    fi
done

mkdir -p "$test_dir/openssl-prefix"
ln -s %{_libdir} "$test_dir/openssl-prefix/lib"

env OPENSSL_CONF=/dev/null \
    OPENSSL_MODULES="$PWD/target/rpm-package-modules" \
    ED301V1_EXPECT_OPENSSL_PREFIX="$test_dir/openssl-prefix" \
    "$test_dir/provider_signature"
env OPENSSL_CONF=/dev/null \
    OPENSSL_MODULES="$PWD/target/rpm-package-modules" \
    openssl list -provider default -provider ed301_eddsa_v1 \
    -signature-algorithms | grep -F Ed301-EdDSA-v1 >/dev/null
env OPENSSL_CONF=/dev/null \
    OPENSSL_MODULES="$PWD/target/rpm-package-modules" \
    openssl list -provider default -provider ed301_eddsa_v1_tls_test \
    -signature-algorithms | grep -F Ed301-EdDSA-v1 >/dev/null
env OPENSSL_CONF=/dev/null \
    OPENSSL_MODULES="$PWD/target/rpm-package-modules" \
    openssl genpkey -provider default -provider ed301_eddsa_v1_tls_test \
    -algorithm Ed301-EdDSA-v1 -out "$test_dir/ed301-pkcs8.pem"
env OPENSSL_CONF=/dev/null \
    OPENSSL_MODULES="$PWD/target/rpm-package-modules" \
    openssl pkey -provider default -provider ed301_eddsa_v1_tls_test \
    -in "$test_dir/ed301-pkcs8.pem" -check -noout
env OPENSSL_CONF=/dev/null \
    OPENSSL_MODULES="$PWD/target/rpm-package-modules" \
    openssl pkey -provider default -provider ed301_eddsa_v1_tls_test \
    -in "$test_dir/ed301-pkcs8.pem" -text -noout \
    > "$test_dir/ed301-key-text.txt"
grep -F 'Ed301-EdDSA-v1 Private-Key:' \
    "$test_dir/ed301-key-text.txt" >/dev/null
grep -F 'priv:' "$test_dir/ed301-key-text.txt" >/dev/null
grep -F 'pub:' "$test_dir/ed301-key-text.txt" >/dev/null
%endif

%files
%license LICENSE
%license LICENSE.dependencies
%license provider/cargo-vendor.txt
%doc README.md
%doc THIRD_PARTY_NOTICES.md
%{provider_modulesdir}/ed301_eddsa_v1.so

%files policy
%doc README.crypto-policy opensslcnf-zz-ed301.config.example
%config(noreplace) %{_sysconfdir}/pki/tls/openssl.d/ed301-tls-experiment.conf
%{provider_modulesdir}/ed301_eddsa_v1_tls_test.so

%posttrans
echo 'WARNING: Ed301-EdDSA-v1 is experimental, non-standardized and not FIPS validated.'
echo 'The ordinary provider is installed but not activated globally; load it explicitly.'
exit 0

%posttrans policy
if ! %{_bindir}/update-crypto-policies; then
    echo 'error: failed to remove a previous Ed301 policy overlay' >&2
    exit 1
fi
echo 'WARNING: The private-use Ed301 TLS experiment is active for laboratory review.'
echo 'Fedora crypto-policy preferences were not changed.'
exit 0

%changelog
* Fri Sep 04 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.10.20260904git69b30b6
- Add Ed25519/Ed448-style private and public key text output

* Wed Sep 02 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.9.20260902git96e6b86
- Enable fresh-process Ed301 X.509 verification

* Wed Sep 02 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.8.20260902git14b402f
- Include PKCS#8 decoding and malformed-input ownership regressions
- Pin the rebuilt OpenSSL review fork

* Tue Sep 01 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.7.20260901gita6c23cf
- Limit the Ed301 policy package to the TLS signature experiment

* Tue Sep 01 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.6.20260901gita6c23cf
- Require the exact X301 provider used by the laboratory group overlay

* Tue Sep 01 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.5.20260901gita6c23cf
- Add the explicit laboratory OpenSSL group and signature overlay
- Regenerate crypto-policies after policy installation and final removal

* Tue Sep 01 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.4.20260901gita6c23cf
- Keep the ordinary provider explicitly loadable but globally inactive
- Activate only the separately named TLS experiment from the policy package

* Tue Sep 01 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.3.20260901gita6c23cf
- Pin the reviewed Ed301 source and OpenSSL fork
- Split the private-use TLS experiment into the optional policy package
