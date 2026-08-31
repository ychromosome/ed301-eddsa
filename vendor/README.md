# Vendored Rust dependencies

This directory was produced offline with `cargo vendor --locked --offline`
from `source/ed301-eddsa-rust/Cargo.lock`. The bundle-level
`.cargo/config.toml` replaces crates.io with this directory and disables Cargo
network access.

`VENDOR_INVENTORY.tsv` records the 32 registry packages, declared license
expressions and Cargo.lock checksums. Vendored packages retain their licenses
and Cargo metadata. Local changes are listed in the affected package's
`ED301_PATCHES.md`; its active `.cargo-checksum.json` records those bytes.

`SHA256SUMS` covers every other regular file in this directory exactly once.
From the bundle root, verify it with:

```sh
(cd vendor && sha256sum --strict --quiet -c SHA256SUMS)
```
