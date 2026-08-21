# Provider test receipt

Date: 2026-08-21

Source branch: `provider-experiment`, based on public-core commit
`505d6f7228d71d39b5dad6d84fbdce14399207e1`.

## Environment

- Rust: 1.97.1, LLVM 21.1.8
- GCC: system `/usr/bin/gcc`
- Clang/scan-build: 21
- Target: x86_64 Linux

## OpenSSL lanes

| lane | OpenSSL CLI SHA-256 | libcrypto SHA-256 | libssl SHA-256 | result |
|---|---|---|---|---|
| 3.5.7 | `6eda175fd1586ae349b03be70747dec2b9ee51da6ac82c5545ff59ec782adf15` | `5fe6ce3092e88f9f1f13c0b15ef6650735f1eef98b73f27e1f844881ec2b6a79` | `7bf0c92ecdb2e67f77ee5c00202cd75cb16e10139627e9a668cbf3afe5561c9d` | PASS |
| 4.0.1 | `ae675e7f3c4e02d8a50293c38755f3626185297edeb97e09f7b861cfe4943696` | `c94847b627099329b03963ef1b3c4709202ed8509f892699f53926082490d781` | `0cbccd8e5e0a8cab7338876e71f94b6ce6c5d1b49517a1f58a6f716576430515` | PASS |

The provider modules were compiled separately against the headers and
libraries of each lane.  Crossed or system runtime-library binding is an
explicit negative control.

## Executed gates

- frozen Round-4 input hashes and generated-vector consistency;
- Cargo metadata, rustfmt, debug/release Clippy, rustdoc and provider tests;
- observed release flags: `crypto-bigint` overflow checks effectively off,
  ED301 core/provider overflow checks on, `panic=unwind`, optimization level
  3 and one codegen unit;
- provider export surface and absence of failpoint strings in the ordinary
  module;
- loading, unloading, repeated and parallel first load;
- KEYMGMT, SIGNATURE, EVP and CLI key/signature operations;
- positive vectors, point/scalar policies, 22 verification edges, 77 negative
  mutations, malleability and deliberately inverted-policy control;
- PKCS#8, encrypted PKCS#8, SPKI, CSR, CA/leaf PKI and chain validation;
- TLS 1.3 server authentication and mutual TLS, with exact CertificateVerify
  observation under the private-use `0xFE84` test scheme;
- OID/SIGID and private-use codepoint collision controls;
- targeted ASan/UBSan, Valgrind, GCC `-fanalyzer` and scan-build;
- OpenSSL and Rust allocation-failure and panic fail-closed paths.

Provider-module SHA-256:

- OpenSSL 3.5.7:
  `cd3bc5be19166b02cc091b573316d87782c0634f7bfdeb37bf7b7c9196ba1ba0`
- OpenSSL 4.0.1:
  `3a1f20f7db19378e5f2392a5f43fbc76097846f29ae0b88e1fd96b01831dd41f`

Core regression gates also passed after integration: Debug 32/32, Release
32/32, downstream KAT 1/1, and all four Secret-Taint/Valgrind cases.

## Boundary

This is functional and targeted hardening evidence for one x86_64 environment,
not a Deep Security Scan, general constant-time proof, complete zeroization
claim, permanent identifier assignment, production approval or release.
