# Third-party notices

The Rust crate uses exactly pinned crates from crates.io. Their original
license files, Cargo metadata and `.cargo-checksum.json` files are preserved in
the vendored dependency tree supplied to reviewers.

The direct dependencies declare:

- `crypto-bigint 0.7.5`: Apache-2.0 OR MIT
- `shake 0.1.0`: MIT OR Apache-2.0
- `zeroize 1.9.0`: Apache-2.0 OR MIT
- test-only `serde_json 1.0.150`: MIT OR Apache-2.0
- test-only build dependency `cc 1.2.66`: MIT OR Apache-2.0

Transitive packages retain their own notices and terms. The project license
does not relicense third-party code, standards or imported provenance inputs.
