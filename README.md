# Ed301-EdDSA

Experimental Rust implementation of `Ed301-EdDSA-draft-00` over the ED301
elliptic curve.

- `no_std`
- safe Rust
- context-free one-shot signing and verification
- locked, vendored and offline builds
- draft vectors and edge cases included

## Test

Authoritative gates run only from a caller-created, read-only source snapshot.
The caller must authenticate the enclosing archive and pass the expected
manifest digest explicitly:

```sh
ED301_SOURCE_MODE=archive \
ED301_VERIFIED_SNAPSHOT=1 \
ED301_EXPECTED_SOURCE_MANIFEST_SHA256=<trusted-sha256> \
    sh scripts/check.sh
```

The same three variables are required by `scripts/check-downstream.sh`,
`scripts/check-secret-taint.sh`, and `scripts/test-provider.sh`. The manifest
inside an unauthenticated archive is not its own trust anchor. Git mode exists
only as a source-verification primitive and additionally requires an external
exact commit; authoritative build gates do not accept it.

## Experimental OpenSSL provider

The `provider-experiment` branch contains a signature-only provider. OpenSSL
must first be built into a sealed lane from a pinned public release tarball.
The externally recorded digest of that lane's evidence manifest is then an
input to the provider gate:

```sh
scripts/build-openssl-provider-lane.sh 3.5.7 /trusted/upstream /private/lane-root
scripts/test-provider.sh /private/lane-root 3.5.7 <trusted-evidence-manifest-sha256>
```

Repeat with `4.0.1` for OpenSSL 4. The ordinary module exposes only `KEYMGMT`
and `SIGNATURE`: no OID alias, encoder, decoder, PKI registration, or TLS
capability. PKI encoders and the private-use TLS proof are separately named,
disabled-by-default test artifacts whose registry setup belongs to the host
harness.

The provider matrix requires Rust with Cargo, rustfmt, Clippy and rustdoc,
plus GCC, Clang/scan-build, binutils, make, Perl, Python 3, pkg-config,
Valgrind, `jq`, curl, tar and xz. The final-binary codegen gate accepts both
legacy and v0 Rust demangler spellings, but it does not relax the reviewed
instruction counts, branch rules or exact helper-call closures.

The optional PKI integration uses the internally assigned Adiumentum OID
`1.3.6.1.4.1.66282.301.3` for this exact Ed301-EdDSA key/signature profile.
This private-enterprise allocation is not a standards or IANA TLS
registration. See `docs/OID_REGISTRY.md` for the allocation and immutability
rules.

The provider is an integration candidate, not a release.  See
`PROVIDER_STATUS.md`.

## Status

Round-2 post-finding-repair candidate awaiting a fresh full-scope deep scan.
Not production-ready.

See `STATUS.md` and `ZEROIZATION_AND_CT_BOUNDARY.md` for the current assurance
boundary.

## License

Apache-2.0. Vendored dependencies retain their own licenses.
