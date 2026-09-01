# Provider status

This branch contains an experimental, signature-only OpenSSL provider for
`Ed301-EdDSA-v1`. It is not a release.

## Contract

- Keys are 38 bytes. Signatures are 76 bytes.
- The native context is an opaque 0--255-byte string. The empty context is
  still domain-bound.
- Nonce and challenge use
  `"SigEd301-v1" || 0x00 || octet(len(context)) || context`.
- The project OID is `1.3.6.1.4.1.66282.301.4`. It is not an IANA algorithm
  registration.
- The private-use TLS test code point is `0xFE84`. The ordinary module exports
  no `TLS-SIGALG` capability.
- OpenSSL ABI major 3 requires source and runtime version 3.5.7 or newer.
  ABI major 4 requires 4.0.1 or newer.
- Authoritative provider evidence uses current patch releases 3.5.8 and 4.0.2.

The ordinary module does not mutate the host OID registry and has no decoder.
Test-artifact surfaces are separate:

| Artifact | Additional surface |
| --- | --- |
| PKI | PKCS#8/SPKI DER and PEM encoders; no decoder |
| TLS integration | PKI encoders, TLS-SIGALG, and strict DER decoders for PKCS#8 PrivateKeyInfo and SPKI |
| TLS collider | PKI encoders, TLS-SIGALG collision fixture, and SPKI decoder; no private decoder |
| Failpoint | injected provider-owned failure paths only |

PEM and EncryptedPrivateKeyInfo input use OpenSSL's generic decoder chain.

## Required gates

Release evidence MUST come from a read-only source snapshot authenticated by
`SOURCE_MANIFEST.sha256`. It MUST identify the manifest digest, compiler,
OpenSSL lane, final provider digest and evidence-manifest digest.
The repository CI uses a digest derived from its own checkout and therefore
provides consistency evidence only.

The required matrix is:

- `scripts/check.sh`;
- `review-tests/run.sh`;
- provider matrices for OpenSSL 3.5.8 and 4.0.2;
- final-DSO code-generation checks in both lanes;
- byte-identical provider rebuilds from a manifest-derived source root;
- the EVP secret-taint matrix;
- ASan, UBSan, static analysis and Valgrind paths in `scripts/test-provider.sh`.

The final-codegen checker accepts a bounded set of x86-64 per-symbol shapes
observed under Rust 1.97.1 and Fedora Rust 1.98.0. This is not a whole-toolchain
allowlist. A separate `multiply_wide` symbol, when emitted, is checked
independently. Every compiler change requires fresh disassembly and taint
evidence.

This file does not certify that a gate passed. Only revision-bound logs and
digests do.

## Limits

- The generic group-security estimate is approximately 149.3 bits, not a
  strict 150-bit claim.
- Secret owners are cleared on normal return and panic unwinding. Compiler
  copies and arithmetic temporaries have no forensic erasure guarantee.
- `crypto-bigint 0.7.5` and `cpufeatures 0.3.0` are project-maintained
  security forks. Their local changes and update gates are documented in
  `vendor/crypto-bigint/ED301_PATCHES.md` and
  `vendor/cpufeatures/ED301_PATCHES.md`.
- Native AArch64 provider/DSO codegen, a fresh full-repository deep scan and
  an independent cryptography/FFI/side-channel audit remain open.
- Required checks, branch protection and signed release tags remain external
  release gates; this branch does not enforce them by itself.
