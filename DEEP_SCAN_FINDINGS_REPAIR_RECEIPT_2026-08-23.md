# Deep-scan findings repair receipt — 2026-08-23

## Scope and disposition

This receipt covers the two medium-severity findings retained by Codex
Security scan `0b7ec637-7435-486b-b36c-c01502374d58` against reviewed HEAD
`8433dab892e4d8ca370d4751d64b309e559b5881`.

| Rule | Finding | Disposition |
| --- | --- | --- |
| `source-integrity.open-world-cargo-target-discovery` | `csf_56d4b070d812a8dde4c05223` | repaired and locally verified |
| `build-profile-attestation.missing-panic-strategy` | `csf_69424c931873f3135ffa594f` | repaired and locally verified |

This is a local repair result, not a production-readiness or independent
review claim. A fresh full-repository Deep Security Scan is the next gate.

## Finding 1: open-world executable source discovery

The vulnerable path was an attacker-added, unlisted Cargo source path such as
`crates/ed301-eddsa/build.rs`, followed by a list-only
`sha256sum -c SOURCE_MANIFEST.sha256`, then Cargo auto-discovery and execution.
The invariant is now: an independently anchored manifest must describe the
exact set of regular files and all derived directories before any Cargo
command can run.

The shared `scripts/verify-source-tree.sh` now:

- binds the manifest either to Git `HEAD` or a caller-supplied trusted SHA-256;
- validates manifest syntax, path safety and strict ordering;
- rejects extra or missing files and directories, symlinks and special files;
- validates every listed file hash; and
- is called before Cargo by the root, downstream, secret-taint and provider
  gates and again after the provider matrix.

All project Cargo packages also disable unused automatic build-script, test,
example, bench and binary discovery; intended targets and required build
scripts are explicit. Generated provider vectors now live below the pruned
build directory instead of beside source files.

Before repair, adding an unlisted `crates/ed301-eddsa/build.rs` left the old
list-only checksum command successful. After repair,
`scripts/test-source-tree-gate.sh` rejects fourteen cases before its fake
Cargo sentinel can run: unlisted build script, tests, examples, benches,
ordinary and reserved-build-path symlinks, a regular file at a reserved build
path, FIFO, empty directory, missing file, altered manifest, and malicious
inputs to each of the three standalone Cargo gates.

## Finding 2: incomplete effective release-profile attestation

The vulnerable path was inherited Cargo/rustc configuration entering a
release build while the old downstream wrapper recorded only a partial
overflow state and no effective panic strategy; the secret-taint path had no
equivalent attestation. The required invariant is now: every relevant actual
`rustc` invocation has the reviewed overflow policy, `panic=unwind`,
optimization level 3, one codegen unit and debug assertions off.

One shared `scripts/rustc-profile-guard.sh` now:

- parses split and joined `-C` forms, every accepted overflow boolean alias
  and repeated options with last-option-wins semantics;
- rejects explicit conflicting or unknown values;
- appends all reviewed security-relevant values to the real compiler command,
  including defaults Cargo may otherwise omit;
- records the full final invocation and exact Rust toolchain identity; and
- is used by the root, downstream, secret-taint and provider release gates.

`scripts/check-rust-build-environment.sh` rejects inherited Rust compiler,
wrapper, target-rustflags and release-profile overrides. The core crate and
provider additionally fail compilation unless `cfg(panic = "unwind")` holds.

Before repair, the old wrapper accepted an invocation with both overflow and
panic state absent and emitted an `absent` marker. After repair,
`scripts/test-rustc-profile-guard.sh` covers 19 parser cases and 14 inherited
environment overrides. Explicit `panic=abort`, wrong overflow state, invalid
aliases, wrong optimization/codegen values and enabled debug assertions are
rejected; omitted safe defaults are explicitly enforced on the compiler
command.

## Local verification

All authoritative runs used a manifest-only fresh extraction and externally
supplied trusted manifest digest on Fedora 43 with rustc/cargo 1.97.1.

- `sh scripts/check.sh`: PASS; closed-world cases 14/14, profile parser cases
  19/19, environment overrides 14/14, core tests 32/32 in debug and release,
  downstream test 1/1, formatting, Clippy and rustdoc clean.
- `sh scripts/check-secret-taint.sh`: PASS; effective profiles attested and all
  four defined/tainted public/sign Valgrind cases passed.
- `scripts/test-provider.sh <OpenSSL-3.5.7-prefix> 3.5.7`: PASS, including
  functional, PKI/OID, RAND, test-only TLS, collision/race, failpoint,
  ASan/UBSan, Valgrind, GCC analyzer and Clang scan-build lanes.
- `scripts/test-provider.sh <OpenSSL-4.0.1-prefix> 4.0.1`: PASS with the same
  matrix.
- Both provider lanes finished with a second complete source-tree verification.

Legitimate behavior remains intact: deterministic vectors and all parsing and
verification edge matrices are unchanged; debug and release signing tests,
the downstream KAT, secret-taint paths, EVP key generation/sign/verify,
PKCS#8/SPKI/CSR/X.509, RAND-policy tests and test-only TLS 1.3 handshakes all
passed on both OpenSSL majors.

## Remaining uncertainty

The scan that discovered these findings had a formal requested-revision/current-
HEAD mismatch and excluded the provider from its declared scope. The repair
therefore requires the planned fresh exact-commit full-repository scan. The
Rust-1.85 closing run, independent mathematical validation, AArch64 and final
multi-architecture constant-time/codegen review also remain open. No
production key use is authorized.
