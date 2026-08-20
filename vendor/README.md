# Vendored Rust dependencies

This directory was produced offline with `cargo vendor --locked --offline`
from `source/ed301-eddsa-rust/Cargo.lock`. The bundle-level
`.cargo/config.toml` replaces crates.io with this directory and disables Cargo
network access.

`VENDOR_INVENTORY.tsv` records the 32 registry packages, declared license
expressions and Cargo.lock checksums. Every vendored package retains its
original Cargo metadata, license files and `.cargo-checksum.json`. The project
license does not relicense these files.

`SHA256SUMS` covers every other regular file in this directory exactly once.
From the bundle root, verify it with:

```sh
(cd vendor && sha256sum --strict --quiet -c SHA256SUMS)
```
