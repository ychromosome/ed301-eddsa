# Status

- Scope: experimental Rust core and OpenSSL provider for `Ed301-EdDSA-v1`.
- Parameters and vectors: `inputs/v1/`; `inputs/round4/` remains frozen
  historical draft-00 input.
- Wire sizes: 38-byte public/private keys and 76-byte signatures.
- Context: opaque 0--255 bytes; the empty context remains domain-bound.
- OID: project assignment `1.3.6.1.4.1.66282.301.4`.
- OpenSSL compatibility minima: 3.5.7 for ABI major 3 and 4.0.1 for ABI
  major 4. Current security lanes: 3.5.8 and 4.0.2.
- Rust minimum: 1.91 because runtime subtraction uses
  `u64::borrowing_sub`. Current local validation uses Fedora Rust 1.98.0.
- Dependencies: pinned `shake` and `zeroize`; source-bound security forks of
  `crypto-bigint 0.7.5` and `cpufeatures 0.3.0`.
- Secret cleanup: named owners are cleared; compiler-generated copies and
  arithmetic temporaries are outside the erasure guarantee.
- Publication: research and review candidate; not production-ready.

Required verification and current open gates are listed in
`PROVIDER_STATUS.md`. Status prose is not test evidence.
