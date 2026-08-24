# Provider status

The `provider-experiment` branch contains an experimental,
signature-only OpenSSL provider for `Ed301-EdDSA-draft-00`.

The provider and its evidence boundary were repaired on 2026-08-23 after an
18-finding deep scan. The 2026-08-24 performance-review revision keeps the
same acceptance boundary: only fresh exact-revision builds against OpenSSL
3.5.7 and 4.0.1 support a reviewer handoff. The matrix covers:

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

The ordinary provider keeps expanded secret state and the validated public
verification table in separate, immutable, fallibly allocated reference-counted
objects. Signature contexts and context duplicates retain only the object they
need instead of copying roughly 10 KiB of prepared state. A public-only key
duplicate cannot retain the expanded signing secret, and each object is
destroyed only after its final owner releases it. The default signing path
follows the usual EdDSA construction without performing a second complete
verification of its own output; a separately selected `sign-self-verify` build
retains that additional fault-detection check. Neither choice changes the draft
transcript, wire encoding, curve, verification equation, or acceptance
language.

The integrated Safe-Rust performance step replaces the portable field
reducer's borrow-heavy folding schedule with a positive
multiply-accumulate fold and reuses the already required public
odd-multiples table for external-key subgroup validation. The latter follows
a fixed public width-8 wNAF encoding of `L` with 299 doublings and 17 mixed
additions; the previous sparse 299-doubling/63-addition implementation remains
a differential reference. Both changes preserve the curve, transcript, byte
contract, canonicality and factor-4 verification language. The public core
continues to forbid unsafe code. The experimental BMI2 backend was
deliberately not integrated.

Five CPU-2-pinned local runs on this development host observed the following
medians after the first low-risk performance repairs and before the subsequent
MAC-fold/wNAF step:

| OpenSSL | Prepared sign | Prepared verify | Seed import | Public import |
| --- | ---: | ---: | ---: | ---: |
| 3.5.7 | 39.245 us | 127.492 us | 77.488 us | 164.490 us |
| 4.0.1 | 39.291 us | 128.139 us | 77.198 us | 164.120 us |

Five CPU-15-pinned exact-revision EVP runs after the MAC-fold/wNAF integration
observed these medians:

| OpenSSL | Prepared sign | Prepared verify | Seed import | Public import |
| --- | ---: | ---: | ---: | ---: |
| 3.5.7 | 35.447 us | 108.664 us | 67.820 us | 123.954 us |
| 4.0.1 | 35.291 us | 108.773 us | 67.657 us | 124.146 us |

Relative to the immediately preceding table, prepared signing improved by
about 10%, prepared verification by about 15%, seed import by about 12%, and
public import by about 24--25%. On the same runs the Ed25519/Ed448 prepared
midpoints were approximately 84 microseconds for signing and 115 microseconds
for verification, so Ed301 is faster than the stated midpoint target on this
host. These measurements remain development evidence, not a portable
performance guarantee.

The exact parent revision measured 287.826/286.317 microseconds for seed
import and 248.430/248.421 microseconds for public import on the two lanes.
The repairs therefore reduce those medians by about 73% and 34% respectively,
while prepared sign and verify remain within roughly 1% of the parent, as
expected. The same harness continues to place Ed301 prepared signing between
OpenSSL Ed25519 and Ed448. Earlier 31--33/93--95 microsecond Ed301 figures came
from the rejected build in which the compiler had introduced a
secret-dependent field-reduction branch; they are not retained performance
claims. These values are comparative development evidence, not a portable
performance guarantee or an acceptance gate.

Symbol profiles found the wide scalar reducer and field inversion at only
single-digit percentages of the measured signing and import paths. A measured
fixed-`p-2` inversion prototype regressed prepared signing from about 39 to 48
microseconds and seed import from about 77 to 95 microseconds, so it was
discarded. A lazy verification table remains workload-dependent and was not
added: it would shift rather than remove work and would introduce first-use
synchronization. The accepted positive field fold is portable Safe Rust; no
assembly, architecture intrinsic, native-CPU flag, secret-indexed table or new
arithmetic unsafe boundary is part of this revision. The provider's manual
shared-state owner remains inside the existing native FFI unsafe boundary.

Local pre-push gates completed on 2026-08-24 include the complete provider
matrix against OpenSSL 3.5.7 and 4.0.1 under Rust 1.97.1, the secret-taint
lane, and a current-code Rust 1.85.1 compatibility lane. The latter covers
formatting, Clippy, 42 core tests in debug/release and `sign-self-verify`, 11
provider unit tests, and loaded OpenSSL 3.5.7 load/key-management/signature
harnesses with 20/36/226 checks. These remain local evidence and do not replace
independent reproduction. Open gates include the fresh full-scope Deep
Security Scan, independent external security and performance review, AArch64,
coverage-guided fuzzing, QEMU/container lanes, final disassembly, timing and
zeroization review, and an external TLS SignatureScheme allocation. No
production, standardization or release claim is made.
