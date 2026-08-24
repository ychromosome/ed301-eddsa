# Changelog

## Unreleased

- Assigned `1.3.6.1.4.1.66282.301.3` to the fixed Ed301-EdDSA profile,
  retained `.301.1` as the retired Ed301-Sig-v1 identity, and left X301 on
  `.301.2`.
- Added OpenSSL whole-message signature dispatch, rejected raw/prehashed
  signing modes, preserved the required verify `1`/`0`/negative result split,
  and added native OpenSSL EVP test vectors for both supported ABI majors.
- Hardened provider key generation, secret ownership, and child-library-context teardown.
- Reduced the ordinary provider to `KEYMGMT` and `SIGNATURE`; isolated optional PKI/TLS integration and limited TLS decoding to a transactional SPKI-only test boundary.
- Enforced strict serialization and PKI validation at the host boundary.
- Made Rust and OpenSSL builds reproducible, externally sealed, and resistant to environment, path, configuration, and source-integrity injection.
- Added regression coverage for the repaired provider, lifecycle, randomness, collision, parser, and build-integrity cases.
- Added reusable expanded signing state and prepared verification-key tables;
  replaced generic group arithmetic with a differentially tested 5x64 field
  backend, constant-time fixed-base radix-16 multiplication, public
  wNAF/Straus verification, affine tables, and a verified square-root-ratio
  decoder. The ordinary provider follows the standard EdDSA signing path;
  optional full post-signature verification remains available through the
  `sign-self-verify` feature.
- Split compile-time table arithmetic from runtime secret arithmetic so every
  runtime conditional field correction crosses the `CtAssign`/`cmov` barrier;
  the secret-taint key-derivation and signing reproducer no longer observes the
  compiler-generated secret-dependent branch from the initial optimized build.
- Increased the cached public verification table to the largest wNAF width
  representable by its `i8` digits and made that width limit a release-build
  invariant; wider experimental tables were rejected by the algebra and
  torsion regression matrix.
- Kept the declared Rust 1.85 MSRV honest by replacing five provider-only
  post-1.85 `let`-chain expressions with equivalent stable control flow; the
  core and provider are covered by an offline Rust 1.85.1 compatibility gate.
