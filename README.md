# Ed301-EdDSA Rust

This is a standalone Rust implementation candidate for the exact
`Ed301-EdDSA-draft-00` byte contract. It is intentionally separate from the
historical `Ed301-Sig-v1` implementation and from OpenSSL, PKI, TLS and G301
integration work.

The public repository currently tracks the Round-2 pre-deep-scan candidate.
It is published for reproducibility and review, not as a production release,
standard, externally audited implementation, or recommendation for real keys.

The normative inputs copied under `inputs/round4/` are hash-bound by
`inputs/round4/SHA256SUMS`. The original Round-4 source manifest is included as
provenance, not as a manifest over this smaller directory.

The public crate is `no_std`, forbids unsafe Rust, owns and zeroizes its seed,
and exposes only context-free one-shot signing and verification. Named secret
intermediates use unwind-safe RAII owners. In particular there is no context,
prehash, randomized-signing or streaming-signature API. The exact cleanup and
constant-time assurance boundary is documented in
`ZEROIZATION_AND_CT_BOUNDARY.md`.

Run the ordinary offline checks from this directory with:

```sh
sh scripts/check.sh
```

The repository includes a hash-bound Cargo configuration and vendor tree. The
ordinary gate creates fresh `CARGO_HOME` and `CARGO_TARGET_DIR` directories and
runs locked and offline. A checkout without those files may opt into an
explicitly nonisolated local Cargo home with both
`ED301_USE_CALLER_CARGO_HOME=1` and an explicit `CARGO_HOME`; that mode is not
equivalent review evidence.
Reusing a caller target directory likewise requires both
`ED301_USE_CALLER_CARGO_TARGET_DIR=1` and an explicit `CARGO_TARGET_DIR` and is
also not equivalent review evidence.

The ordinary gate also builds and runs the separate workspace under
`integration/downstream-workspace/`. That workspace repeats the required
`crypto-bigint` package-profile override and verifies the effective release
compiler flags before running a known-answer check.

Run the separate Valgrind secret-taint check with:

```sh
sh scripts/check-secret-taint.sh
```

Cargo profiles are not transitive. Every actual top-level product or provider
workspace must repeat the package override from the downstream fixture for its
active production profile, then recheck the effective compiler flags and final
machine code. This candidate has not undergone the deferred deep security
scan. It is not a production release, a standards claim, or an
organisationally independent implementation because it reuses pre-existing
ED301 field and group primitives.
