%global openssl_fork_evr 1:4.1.0~dev.1-0.3.git7d9c89d%{?dist}

Name:           ed301-four-component-review
Version:        0.1.0
Release:        0.8%{?dist}
Summary:        Four-component Ed301 laboratory review environment
License:        Apache-2.0
URL:            https://github.com/ychromosome/ed301-eddsa
BuildArch:      noarch

Requires:       openssl = %{openssl_fork_evr}
Requires:       openssl-libs%{?_isa} = %{openssl_fork_evr}
Requires:       ed301-openssl-provider = 0.1.0-0.10.20260904git69b30b6%{?dist}
Requires:       ed301-openssl-provider-policy = 0.1.0-0.10.20260904git69b30b6%{?dist}
Requires:       x301-openssl-provider = 0.1.0-0.8.20260902git73b30af%{?dist}
Requires:       x301-openssl-provider-policy = 0.1.0-0.8.20260902git73b30af%{?dist}
Requires:       g301-openssl-provider = 0.1.0-0.5.20260902git07da4c8%{?dist}
Requires:       g301-openssl-provider-policy = 0.1.0-0.5.20260902git07da4c8%{?dist}

%description
This package contains no files. It installs the exact RPM set used by the
Fedora 45 four-component laboratory review.

%prep

%build

%install
mkdir -p %{buildroot}%{_datadir}

%check
test "%{openssl_fork_evr}" = \
    "1:4.1.0~dev.1-0.3.git7d9c89d%{?dist}"

%files

%changelog
* Fri Sep 04 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.8
- Require Ed301 key text encoding

* Wed Sep 02 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.7
- Require the fresh-process Ed301 X.509 fix

* Wed Sep 02 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.6
- Pin the repaired OpenSSL, Ed301, X301 and G301 package set

* Tue Sep 01 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.5
- Require separate Ed301, X301 and G301 policy packages

* Tue Sep 01 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.4
- Require Ed301 provider and policy release 0.6

* Tue Sep 01 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.3
- Require the Ed301 laboratory TLS and OpenSSL-overlay policy package

* Tue Sep 01 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.2
- Require the globally inactive ordinary Ed301 provider package

* Tue Sep 01 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.1
- Pin the Fedora 45 four-component review package set
