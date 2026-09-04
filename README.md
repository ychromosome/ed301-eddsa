# Ed301-EdDSA

Experimental Rust implementation of `Ed301-EdDSA-v1` over the ED301
elliptic curve.

- `no_std`
- safe Rust
- one-shot signing and verification with an optional 0--255-byte context
- locked, vendored and offline builds
- v1 vectors and frozen draft-00 rejection boundaries

## Curve provenance

`evidence/curve-provenance/` contains the complete manifest-bound 2026-07-31
technical archive: original search programs, all worker outputs, parameters,
certificates, independent verifiers and a curve-only reproduction runner. It
also records the unavoidable historical limit: no public pre-search commitment
exists, so the evidence is reproducible after-the-fact provenance rather than
a retroactive nothing-up-my-sleeve proof.

## Test

Authoritative gates run only from a caller-created, read-only source snapshot.
The caller must authenticate the enclosing archive and pass the expected
manifest digest explicitly:

```sh
scripts/run-authoritative-gate.sh archive <trusted-sha256> check
```

The launcher clears inherited startup and tool-control variables before the
gate shell starts. It also exposes `check-downstream`, `check-secret-taint`,
`review-tests`, `build-openssl-provider-lane`,
`verify-openssl-provider-lane`, and `test-provider`. Calling the underlying
scripts directly does not produce authoritative evidence. The manifest inside
an unauthenticated archive is not its own trust anchor. Git mode exists only
for exact source verification:

```sh
scripts/run-authoritative-gate.sh git <trusted-manifest-sha256> \
    <trusted-commit> verify-source-tree
```

The host kernel, dynamic loader, and process that starts the launcher are
trusted. The caller must clear loader controls before `exec`; a process cannot
clear controls that executed before it began. CI supplies empty loader-control
values at the runner boundary before starting its clean shell.

Repository CI derives its manifest digest and commit from the checked-out
revision. It checks internal consistency and regressions; it is not an external
trust anchor and does not produce release evidence. Release evidence requires
an independently authenticated archive and manifest digest.

`review-tests/run.sh` adds the independent v1 transcript/OID oracle, wire
mutation matrix, public-signature taint test, external-consumer taint test and
header-version contract. The provider matrix also runs its OpenSSL context
contract against each lane.

## Experimental OpenSSL provider

The `provider-experiment` branch contains a signature-only provider. OpenSSL
must first be built into a sealed lane from a pinned public release tarball.
The externally recorded digest of that lane's evidence manifest is then an
input to the provider gate:

```sh
scripts/run-authoritative-gate.sh archive <trusted-manifest-sha256> \
    build-openssl-provider-lane 3.5.8 /trusted/upstream /private/lane-root
scripts/run-authoritative-gate.sh archive <trusted-manifest-sha256> \
    test-provider /private/lane-root 3.5.8 \
    <trusted-evidence-manifest-sha256>
```

Repeat with `4.0.2` for OpenSSL 4. The ordinary module exposes only `KEYMGMT`
and `SIGNATURE`: no OID alias, encoder, decoder, PKI registration, or TLS
capability. PKI encoders and the private-use TLS proof are separately named,
disabled-by-default test artifacts. The TLS integration module registers and
checks its OID and digestless SIGID before publishing its dispatch table.
See `docs/PROVIDER_USAGE.md` for commands and supported formats.

The provider lane also runs the dudect-based timing check. A separate pinned
performance receipt is produced with:

```sh
scripts/run-authoritative-gate.sh archive <trusted-manifest-sha256> \
    performance-receipt /private/lane-root/inst/3.5.8 2 /tmp/ed301-performance
```

Timing and benchmark results apply only to the recorded CPU, binaries and
toolchain.

The compatibility minima remain OpenSSL 3.5.7 for ABI major 3 and OpenSSL
4.0.1 for ABI major 4. The authoritative matrix uses the current security
patch releases. Later releases in the same major are accepted; earlier
releases are not supported merely because they share that major.

The provider matrix requires Rust with Cargo, rustfmt, Clippy and rustdoc,
plus GCC, Clang/scan-build, binutils, make, Perl, Python 3, pkg-config,
Valgrind, `jq`, curl, tar and xz. The final-binary codegen gate accepts both
legacy and v0 Rust demangler spellings, but it does not relax the reviewed
instruction counts, branch rules or exact helper-call closures.

The optional PKI integration uses the internally assigned Adiumentum OID
`1.3.6.1.4.1.66282.301.4` for this exact Ed301-EdDSA key/signature profile.
The historical `.301.3` assignment remains frozen for the incompatible
domainless draft-00 transcript. This private-enterprise allocation is not a
standards or IANA TLS registration. See `docs/OID_REGISTRY.md` for the
allocation and immutability rules.

The provider is an integration candidate, not a release.  See
`PROVIDER_STATUS.md`.

## Status

Research and review candidate. Not production-ready.

See `STATUS.md` and `ZEROIZATION_AND_CT_BOUNDARY.md` for the current assurance
boundary.

## License

Apache-2.0. Vendored dependencies retain their own licenses.
