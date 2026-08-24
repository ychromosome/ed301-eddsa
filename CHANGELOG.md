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
  current core and ordinary provider are covered by an offline Rust 1.85.1
  compatibility gate.
- Applied the performance review's four low-risk repairs: internally derived
  public points bypass hostile-input decoding and subgroup multiplication;
  external public keys gained a fixed sparse `[L]P` reference schedule that is
  retained as the differential oracle for the later shared-table wNAF path;
  expanded signing state no longer embeds the 10-KiB verification table; and
  immutable signing and verification state is shared across provider keys and
  contexts with fallible allocation and last-owner destruction.
- Added 2,048-case differential tests for both the internal public-key path
  and the sparse subgroup schedule, including identity, order-2, order-4 and
  mixed-torsion cases, plus provider allocation- and reference-lifetime tests.
- Replaced the portable field reducer's subtract-and-borrow folds with an
  addition-only multiply-accumulate fold using the positive constant
  `2^99 - 947`. The fixed-schedule Safe Rust implementation is checked against
  the independent Montgomery oracle over all 602 reachable one-hot inputs,
  named boundaries and randomized wide values.
- Reused the public verification key's odd-multiples table for a fixed
  width-8 wNAF multiplication by the public group order during external key
  import. The hardcoded schedule reconstructs `L`, performs 299 doublings and
  17 mixed additions, constructs no `VerifyingKey` before validation, and is
  differentially checked against the retained 299-doubling/63-addition sparse
  reference across the complete order-4 torsion classes.
- Kept `#![forbid(unsafe_code)]` on the public cryptographic core. The separate
  BMI2 arithmetic spike was not integrated; no runtime CPU dispatch,
  architecture intrinsic or new arithmetic unsafe boundary was added. The
  provider continues to confine native pointers and its shared-state owner to
  the existing FFI unsafe boundary.
