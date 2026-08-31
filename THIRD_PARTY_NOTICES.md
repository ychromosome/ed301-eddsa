# Third-party notices

The Rust crate uses exactly pinned third-party sources. Registry crates retain
their license, Cargo metadata and registry checksum files. The source-bound
`crypto-bigint` fork retains the upstream checksum separately, preserves its
VCS metadata and documents local changes in
`vendor/crypto-bigint/ED301_PATCHES.md`.

The direct dependencies declare:

- source-bound fork of `crypto-bigint 0.7.5`: Apache-2.0 OR MIT
- `shake 0.1.0`: MIT OR Apache-2.0
- `zeroize 1.9.0`: Apache-2.0 OR MIT
- provider dependency `getrandom 0.4.3`: MIT OR Apache-2.0
- provider transitive dependency `r-efi 6.0.0`: MIT OR Apache-2.0 OR
  LGPL-2.1-or-later
- test-only `serde_json 1.0.150`: MIT OR Apache-2.0
- test-only build dependency `cc 1.2.66`: MIT OR Apache-2.0

Transitive packages retain their own notices and terms. The project license
does not relicense third-party code, standards or imported provenance inputs.
The local `cpufeatures 0.3.0` HWCAP-mask correction is documented under that
package and remains under its Apache-2.0 OR MIT license.
