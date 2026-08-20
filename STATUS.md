# Status

- Scope: Rust implementation candidate for `Ed301-EdDSA-draft-00`.
- Protocol input: the manifest-bound Round-4 draft and vector files.
- Runtime dependencies: `crypto-bigint`, `shake` and `zeroize`, exactly pinned.
- API: context-free one-shot key derivation, signing and verification.
- Review state: internal pre-deep-scan static and functional checks found no
  remaining Round-2 code blocker; independent external review remains open.
- Toolchain policy: regular builds use the newest stable Rust supplied by the
  host OS when it is at least 1.85; exact tool versions are recorded with
  results.
- Recorded local regression toolchain: rustc 1.97.1 (8bab26f4f; Fedora
  1.97.1-1.fc43), cargo 1.97.1 (c980f4866), rustfmt 1.9.0, clippy 0.1.97.
- MSRV: manifests declare Rust 1.85 as a minimum; a full Rust-1.85 test run
  remains an explicit closing gate. Current local regression evidence uses
  Rust 1.97.1 and is not Rust-1.85 MSRV proof.
- Round-2 review surface: unwind-safe named secret owners, isolated Cargo-home
  checks, a top-level downstream profile fixture, and library-backed bounded
  square-root exponentiation.
- Deferred gate: the requested deep scan is deliberately reserved for the
  later full-budget run.
- Publication state: public experimental source checkpoint for reproducibility
  and review; not a release or production-ready crate.
- Secret cleanup: named logical owners are RAII-cleared on ordinary return and
  panic unwinding; compiler-generated and by-value arithmetic copies do not
  carry a forensic erasure guarantee.
- Outside this round: OpenSSL provider, ASN.1/OID, PKI, TLS and G301 wiring.
- No production, constant-time-completion, standards or release claim is made.
