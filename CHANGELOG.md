# Changelog

## Unreleased

- Replaced the ABI-major-only OpenSSL compatibility claim with explicit
  source/API and runtime minima: 3.5.7 for ABI major 3 and 4.0.1 for ABI major
  4. Earlier same-major releases are rejected; each claimed minimum remains
  subject to its real build/load/sign/verify lane.
- Introduced the incompatible `Ed301-EdDSA-v1` transcript under OID
  `1.3.6.1.4.1.66282.301.4`. Following the Ed448 `dom4` shape, both nonce and
  challenge hashes now begin with `"SigEd301-v1" || 0x00 || len(C) || C` for
  an opaque 0--255-byte context. The flag is fixed to the pure instance, the
  empty context remains explicitly domain-bound, and no prehash variant is
  defined. The domainless `.301.3` profile remains frozen and incompatible.
- Reduced the public `Signature` to its exact 76-byte wire value. Decoded
  commitment and response state is now private and operation-local; the normal
  byte and provider verification paths still decode once, while the taint gate
  checks the complete returned object rather than only a serialized projection.
- Made final-provider symbol matching independent of Rust's legacy versus v0
  demangler spelling while retaining the exact instruction-shape and call-
  graph policies, and documented `jq` among the provider-matrix prerequisites.
- Integrated the independently produced Package-A Python implementation as a
  hash-bound, immutable test oracle after its 109/109 Package-B blind result.
  A narrow adapter accepts only immutable byte strings and exposes no raw
  point helpers, closing the two recorded LOW API findings without changing
  the frozen source. Deterministic Python and Rust differential gates bind
  public keys, byte-exact signatures and invalid-input decisions.
- Translated the relevant OpenSSL Ed25519/Ed448 SIGNATURE, KEYMGMT, decoder,
  RAND/library-context, PKI and lifecycle contracts into a numbered Ed301
  matrix for both normative OpenSSL lanes.  The new cases cover pure-only
  one-shot semantics, raw-key and validation discipline, strict DER,
  deterministic RAND separation, mixed-algorithm X.509 chains, context
  duplication, parallel shared-key use and repeated provider load/unload;
  deliberate profile deviations are recorded separately.
- Repeated the complete post-integration provider, secret-taint and final
  code-generation gates on OpenSSL 3.5.7 and 4.0.1, and closed a complete
  security diff review of all 16 source-like changes without a reportable
  finding. Fresh single-KAT and equal-weight four-KAT EVP benchmarks document
  both short-message throughput and message-length sensitivity without
  treating either batch measurement as single-call latency.
- Historically assigned `1.3.6.1.4.1.66282.301.3` to the now-frozen,
  domainless draft-00 profile, retained `.301.1` as the retired
  Ed301-Sig-v1 identity, and left X301 on `.301.2`.
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
- Recorded the successful offline Rust-1.85.1 run as historical compatibility
  evidence rather than an MSRV or continuing support promise. Regular gates
  use the current Fedora Rust toolchain and record its exact identity; newer
  language, library or dependency features are accepted only for a concrete
  security, performance or maintenance benefit.
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
- Restored OpenSSL's documented NULL-key DigestSign/DigestVerify reinit
  contract without adding another key owner, and made the provider verify
  boundary explicitly return `1` for acceptance, `0` only for signature
  invalidity, and a negative value for operational failures. Regression tests
  cover the Rust FFI, registered provider dispatch, both EVP lanes and the
  built-in Ed25519 lifecycle control. A rejected NULL-key mode request leaves
  the matching immutable operation untouched, while a callback failure or a
  rejected reinitialization carrying a new key now clears the old operation
  fail-closed; direct sign and verify shim tests bind both sides of that rule.
- Replaced the scalar reducer's five- and ten-word base-`2^64` Horner loops
  with one direct 304-bit Montgomery conversion for pruned scalars and a
  natural 304+304-bit split for 608-bit hash outputs. The production path uses
  no wide division or new unsafe code; an independently reproduced
  `2^304 mod L` literal, split-boundary cases, all 608 one-hot inputs and the
  wide-division test oracle bind the shorter schedule.
- Replaced the runtime field backend's custom bitwise borrow expansion with
  the safe standard `u64::borrowing_sub` chain available to the current Fedora
  compiler and stabilized in Rust 1.91. Compile-time table construction
  retains the explicit constant-evaluable identity. This deliberately newer
  API removes work rather than adding an architecture backend, preserves
  `#![forbid(unsafe_code)]`, and is accepted only with fresh codegen,
  secret-taint and end-to-end evidence. The manifests declare Rust 1.91 as
  the minimum build toolchain; constant-time and code-generation claims remain
  specific to each tested compiler and final artifact.
- Made that compiler-sensitive replacement a permanent gate on both final
  Thin-LTO provider modules: named field, point, scalar-reduction and
  basepoint-selection symbols must retain the reviewed branchless SBB/CMOV
  shape and the reviewed helper-call closure, the checker has a same-binary
  conditional-branch negative control, and a separate instrumented module
  first verifies the seed's Valgrind V-bits before exercising undefined seed
  material through the complete EVP-to-Rust signing path. Added a concise
  arithmetic implementation register so the historical reason and mandatory
  compiler-retest duty are not lost.
- Added a direct safegcd-versus-Fermat inversion differential and consolidated
  duplicated deterministic test helpers.
- Added a provider implementation register for the local fallible `Shared<T>`
  and `try_box` helpers, including their stable-Rust replacement triggers and
  mandatory lifecycle evidence.
