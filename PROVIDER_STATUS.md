# Provider status

The `provider-experiment` branch contains an experimental,
signature-only OpenSSL provider for `Ed301-EdDSA-draft-00`.

Fresh local builds on 2026-08-22 passed the same source-driven matrix against
unmodified OpenSSL 3.5.7 and 4.0.1:

- provider loading, unloading and parallel first registration;
- `KEYMGMT`, `SIGNATURE`, EVP key generation, signing and verification;
- the four positive vectors, edge matrices and 77 negative mutations;
- PKCS#8, SPKI, CSR, CA/leaf certificates and chain validation;
- TLS 1.3 server authentication and mutual TLS with a private-use test
  SignatureScheme;
- negative digest, context, streaming, parser, collision and malformed-input
  cases;
- targeted ASan/UBSan, Valgrind, GCC analyzer and allocation-failure gates.

The repaired integration boundary is:

- key generation obtains its 38-byte seed from `RAND_priv_bytes_ex()` in a
  provider child `OSSL_LIB_CTX`; a host-selected deterministic RAND and a
  forced RAND failure are both covered by regression tests;
- OID/SIGID registration uses only Core upcalls. Exact collision checks and
  their portable `CRYPTO_THREAD` serialization live in the host test helper,
  against the registry belonging to the loading `libcrypto`;
- one module is compiled per OpenSSL ABI major. Major 3 requires 3.5 or later;
  major 4 requires 4.0 or later. Patch equality is not required;
- fixed, strict DER remains provider-owned, while PEM armor uses OpenSSL and
  the bespoke private text/hex encoder is absent; and
- the ordinary provider has no `TLS-SIGALG` dispatch. The private-use TLS
  proof and a second full Ed301 collision provider are separately named,
  disabled-by-default test artifacts.

The tests use the ephemeral OID
`2.25.195456677253783758411179833219689607856` and private-use TLS
SignatureScheme `0xFE84`. The codepoint appears only in the TLS test
artifacts. Neither identifier is registered or suitable for deployment.

Open gates remain the deferred Deep Security Scan, independent external
review, AArch64, coverage-guided fuzzing, QEMU/container lanes, final
constant-time and zeroization review, permanent identifiers, and the closing
Rust-1.85 run.  No production, standardization or release claim is made.
