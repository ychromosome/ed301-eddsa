# Ed301 patch provenance

`src/aarch64.rs` requires every Linux/Android HWCAP bit implied by a Rust
target feature. Upstream `cpufeatures 0.3.0` used an any-bit mask check.
[RustCrypto/utils#395](https://github.com/RustCrypto/utils/issues/395) and
merged [PR #456](https://github.com/RustCrypto/utils/pull/456) define the
composite target-feature mapping; upstream 0.3.0 and current master still use
the any-bit test.

The upstream `.cargo-checksum.json` SHA-256 is
`c84c85962075940aa217a9300b73f4e0af1b61fd6682f042614b8cb6f40ed8ab`.
The active checksum map records the patched source and test hashes; the
registry package checksum remains unchanged as provenance metadata.
`UPSTREAM_SHA256SUMS` records every file hash from the crates.io archive.

No Ed301 upstream PR has been submitted as of 2026-08-31. Recheck upstream on
every dependency update. Run the native AArch64 tests, the core/provider
matrices, secret taint and final codegen gates before replacing this fork.
