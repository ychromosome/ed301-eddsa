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

The optional PKI tests use project-assigned OID
`1.3.6.1.4.1.66282.301.3` beneath the Adiumentum GmbH private-enterprise arc.
It identifies the exact Ed301-EdDSA key/signature profile but is not an IANA
TLS registration or a standards claim. Private-use TLS SignatureScheme
`0xFE84` appears only in the TLS test artifacts and remains nonregistrable and
unsuitable for deployment.

The ordinary provider caches expanded secret state and the validated public
verification table in each key object. Its default signing path follows the
usual EdDSA construction without performing a second complete verification of
its own output; a separately selected `sign-self-verify` build retains that
additional fault-detection check. Neither choice changes the draft transcript,
wire encoding, curve, verification equation, or acceptance language.

Five CPU-pinned local runs on this development host for each supported OpenSSL
line observed the following median ranges: 39.1--39.2 microseconds per
prepared EVP signature, 126.1--126.6 microseconds per prepared EVP
verification, 40.0--40.1 and 127.3--127.6 microseconds for the corresponding
full fetch/context paths, and 244.3--244.6 microseconds for public-key import.
The same harness measured OpenSSL Ed25519 at 22.6--22.8/75.9--76.5
microseconds and Ed448 at 143.9--144.3/152.4--152.7 microseconds for prepared
sign/verify. Earlier 31--33/93--95 microsecond Ed301 figures came from the
rejected build in which the compiler had introduced a secret-dependent
field-reduction branch; they are not retained performance claims. These values
are comparative development evidence, not a portable performance guarantee or
an acceptance gate.

Local pre-push gates completed on 2026-08-24 include the complete provider
matrix against OpenSSL 3.5.7 and 4.0.1, the core/provider compatibility gate
with Rust 1.85.1, and the secret-taint lane. They remain local evidence and do
not replace independent reproduction. Open gates include the fresh full-scope
Deep Security Scan, independent external security and performance review,
AArch64, coverage-guided fuzzing, QEMU/container lanes, final disassembly,
timing and zeroization review, and an external TLS SignatureScheme allocation.
No production, standardization or release claim is made.
