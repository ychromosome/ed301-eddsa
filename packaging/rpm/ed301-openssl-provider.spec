%bcond_without tests

%global commit 14b402f4a5b17996ef29687e1248842a4f092854
%global shortcommit 14b402f
%global snapshot 20260902
%global source_manifest_sha256 42e2a66958db825a9047f05205d0e2c9c587a21abfd82a13d99fe275133328ce
%global provider_modulesdir %{_libdir}/ossl-modules
%global __provides_exclude_from ^%{provider_modulesdir}/.*\.so$

Name:           ed301-openssl-provider
Version:        0.1.0
Release:        0.3.%{snapshot}git%{shortcommit}%{?dist}
Summary:        Experimental Ed301-EdDSA provider for OpenSSL
License:        Apache-2.0
URL:            https://github.com/ychromosome/ed301-eddsa
Source0:        %{url}/archive/%{commit}/ed301-eddsa-%{commit}.tar.gz
Source1:        ed301-provider.conf
Patch0:         0001-Allow-standard-RPM-native-build-flags.patch

BuildRequires:  cargo-rpm-macros
BuildRequires:  cargo >= 1.91
BuildRequires:  rust >= 1.91
BuildRequires:  gcc
BuildRequires:  binutils
BuildRequires:  pkgconfig(openssl) >= 3.5.7
%if %{with tests}
BuildRequires:  openssl
BuildRequires:  python3
BuildRequires:  rustfmt
%endif

Requires:       openssl-libs%{?_isa} >= 1:3.5.7

# crypto-bigint is a source-bound path dependency and is therefore not emitted
# by the cargo vendor manifest generator.
Provides:       bundled(crate(crypto-bigint)) = 0.7.5

%description
Ed301-EdDSA-v1 is an experimental signature algorithm. Installing this package
activates its OpenSSL provider system-wide. The algorithm is not standardized
or FIPS validated.

%prep
%setup -q -n ed301-eddsa-%{commit}
test "$(sha256sum SOURCE_MANIFEST.sha256 | awk '{ print $1 }')" = \
    %{source_manifest_sha256}
sha256sum --strict --quiet -c SOURCE_MANIFEST.sha256
%autopatch -p1
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

pushd crates/ed301-eddsa-provider
%cargo_license_summary
%{cargo_license} > ../../../LICENSE.dependencies
popd
%cargo_vendor_manifest
# Fedora 43 cargo2rpm includes workspace path packages in this file although
# the bundled-crate generator accepts registry entries only.
sed -i '\| (/|d' cargo-vendor.txt
popd

%install
install -Dpm 0755 \
    provider/target/rpm/libed301_eddsa_v1.so \
    %{buildroot}%{provider_modulesdir}/ed301_eddsa_v1.so
install -Dpm 0644 %{SOURCE1} \
    %{buildroot}%{_sysconfdir}/pki/tls/openssl.d/ed301-provider.conf

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

module=%{buildroot}%{provider_modulesdir}/ed301_eddsa_v1.so
test -f "$module"
test "$(nm -D --defined-only "$module" \
    | awk '$2 == "T" { count++ } END { print count + 0 }')" -eq 1
nm -D --defined-only "$module" | grep -E ' T OSSL_provider_init$' >/dev/null
if readelf -d "$module" | grep -Eq '\((RPATH|RUNPATH)\)'; then
    echo 'provider module contains an RPATH or RUNPATH' >&2
    exit 1
fi

mkdir -p "$test_dir/openssl-prefix"
ln -s %{_libdir} "$test_dir/openssl-prefix/lib"

env OPENSSL_CONF=/dev/null \
    OPENSSL_MODULES=%{buildroot}%{provider_modulesdir} \
    ED301V1_EXPECT_OPENSSL_PREFIX="$test_dir/openssl-prefix" \
    "$test_dir/provider_signature"
openssl list -provider-path %{buildroot}%{provider_modulesdir} \
    -provider default -provider ed301_eddsa_v1 \
    -signature-algorithms | grep -F Ed301-EdDSA-v1 >/dev/null
%endif

%files
%license LICENSE
%license LICENSE.dependencies
%license provider/cargo-vendor.txt
%doc README.md
%doc THIRD_PARTY_NOTICES.md
%config(noreplace) %{_sysconfdir}/pki/tls/openssl.d/ed301-provider.conf
%{provider_modulesdir}/ed301_eddsa_v1.so

%posttrans
echo 'WARNING: Ed301-EdDSA-v1 is experimental, non-standardized and not FIPS validated.'
echo 'The provider is active system-wide for newly started OpenSSL applications.'
echo 'Restart long-running OpenSSL consumers before relying on the new provider.'
exit 0

%changelog
* Wed Sep 02 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.3.20260902git14b402f
- Include strict Ed301 PKCS#8 decoding and malformed-input ownership fixes

* Tue Sep 01 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.2.20260901gite15f0aa
- Include EdDSA NULL-key reinitialization parity with Ed25519 and Ed448

* Tue Sep 01 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.1.20260831git8a1db67
- Initial split Ed301 provider package
