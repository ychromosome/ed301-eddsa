# Local patch

`src/aarch64.rs` requires every Linux/Android HWCAP bit implied by a Rust
target feature. Upstream `cpufeatures 0.3.0` used an any-bit mask check.

The upstream `.cargo-checksum.json` SHA-256 is
`c84c85962075940aa217a9300b73f4e0af1b61fd6682f042614b8cb6f40ed8ab`.
The active checksum map records the patched source and test hashes; the
registry package checksum remains unchanged as provenance metadata.
