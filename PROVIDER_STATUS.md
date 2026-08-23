# Provider status

The `provider-experiment` branch contains an experimental,
signature-only OpenSSL provider for `Ed301-EdDSA-draft-00`.

The provider and its evidence boundary were repaired on 2026-08-23 after an
18-finding deep scan. Fresh exact-revision builds against OpenSSL 3.5.7 and
4.0.1 are required before this candidate can be handed to the next reviewer.
The intended matrix covers:

- provider loading/unloading and parallel host-owned test registration;
- `KEYMGMT`, `SIGNATURE`, EVP key generation, signing and verification;
- the four positive vectors, edge matrices and 77 negative mutations;
- PKCS#8, SPKI, CSR, CA/leaf certificates and chain validation;
- TLS 1.3 server authentication and mutual TLS with a private-use test
  SignatureScheme;
- negative digest, context, streaming, parser, collision and malformed-input
  cases;
- targeted ASan/UBSan, Valgrind, GCC analyzer and allocation-failure gates.

Before any Cargo command, the provider runner requires a read-only,
caller-authenticated source snapshot. It verifies the complete regular-file
and directory inventory, rejects extra source, symlinks and special files,
and re-verifies the snapshot after the matrix. Cargo runs from `/` with an
explicit repository configuration, a minimal environment, canonical tools,
private homes and targets, and complete per-invocation profile receipts.
Generated files, modules and executable harnesses are sealed before first
execution and checked again afterward.

The repaired integration boundary is:

- key generation obtains its 38-byte seed from `RAND_priv_bytes_ex()` in a
  provider child `OSSL_LIB_CTX`; a host-selected deterministic RAND and a
  forced RAND failure are both covered by regression tests;
- the ordinary module has no OID alias and performs no OID/SIGID mutation.
  Optional PKI/TLS setup is serialized and verified by the host harness
  against its own `libcrypto` registry before loading the test artifact;
- one module is compiled per OpenSSL ABI major. Major 3 requires 3.5 or later;
  major 4 requires 4.0 or later. Patch equality is not required;
- the ordinary and PKI artifacts expose no decoder. Supported private-key
  imports use the exact, complete-buffer host parser. The TLS-only artifact
  has one fixed-size SPKI decoder for peer certificates: it refuses partial
  input before reading and rewinds every pre-OID mismatch. Optional fixed PKI
  encoders remain confined to separately named test artifacts; and
- the ordinary provider has no `TLS-SIGALG` dispatch. The private-use TLS
  proof and a second full Ed301 collision provider are separately named,
  disabled-by-default test artifacts.

The tests use the ephemeral OID
`2.25.195456677253783758411179833219689607856` and private-use TLS
SignatureScheme `0xFE84`. The codepoint appears only in the TLS test
artifacts. Neither identifier is registered or suitable for deployment.

Open gates include both fresh OpenSSL-lane acceptance runs for this exact
revision, the fresh full-scope Deep Security Scan, independent external
review, AArch64, coverage-guided fuzzing, QEMU/container lanes, final
constant-time and zeroization review, permanent identifiers, and the closing
Rust-1.85 run. No production, standardization or release claim is made.
