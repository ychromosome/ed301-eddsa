# Status

- Scope: Rust implementation candidate for `Ed301-EdDSA-draft-00`.
- Protocol input: the manifest-bound Round-4 draft and vector files.
- Runtime dependencies: `crypto-bigint`, `shake` and `zeroize`, exactly pinned.
- API: context-free one-shot key derivation, signing and verification.
- Review state: the 2026-08-23 mixed-revision scan found two build-assurance
  defects at current HEAD. Both have focused repairs and local regression
  evidence; a fresh exact-revision, full-scope deep scan is the next gate.
- Toolchain policy: regular builds use the newest stable Rust supplied by the
  host OS when it is at least 1.85; exact tool versions are recorded with
  results.
- Recorded local regression toolchain: rustc 1.97.1 (8bab26f4f; Fedora
  1.97.1-1.fc43), cargo 1.97.1 (c980f4866), rustfmt 1.9.0, clippy 0.1.97.
- MSRV: manifests declare Rust 1.85 as a minimum. The current Safe-Rust A+B
  core and ordinary provider pass an offline Rust-1.85.1 compatibility gate,
  including format/lint, core tests, provider units and loaded OpenSSL
  key-management/signature harnesses. This single-host lane is not a
  multi-platform MSRV guarantee.
- Round-2 review surface: unwind-safe named secret owners, a compile-time
  `panic=unwind` requirement, isolated Cargo-home checks, a closed-world and
  externally anchored source inventory, effective release-profile enforcement,
  a downstream profile fixture, a differentially checked specialized field
  backend, fixed-exponent square-root-ratio decoding, fixed-base secret
  multiplication, and explicitly public variable-time verification tables.
- Performance state: the Safe-Rust positive MAC field fold and fixed public
  width-8 wNAF import schedule are integrated and locally validated. Prepared
  EVP signing measures about 35.3--35.4 microseconds and verification about
  108.7--108.8 microseconds on the two supported OpenSSL lanes. The core still
  has `#![forbid(unsafe_code)]`; the separate BMI2 spike and its runtime
  dispatch/fallback burden remain deferred research artifacts.
- Current scan boundary: scan `0b7ec637-7435-486b-b36c-c01502374d58`
  formally targeted an older revision and excluded the provider, although its
  two retained findings were validated against then-current HEAD
  `8433dab892e4d8ca370d4751d64b309e559b5881`. It is discovery evidence, not
  the required final full-repository scan.
- Publication state: public experimental source checkpoint for reproducibility
  and review; not a release or production-ready crate.
- Secret cleanup: named logical owners are RAII-cleared on ordinary return and
  panic unwinding; compiler-generated and by-value arithmetic copies do not
  carry a forensic erasure guarantee.
- Outside this round: an external TLS SignatureScheme allocation, G301 wiring,
  production use and standards claims. The project-assigned ASN.1 OID,
  experimental provider, PKI and test-only TLS surfaces are included in the
  next full scan.
- No production, constant-time-completion, standards or release claim is made.
