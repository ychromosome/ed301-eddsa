# Arithmetic implementation register

This register records deliberately local arithmetic code whose rationale can
become stale as compilers and libraries change. Revisit every entry whenever
the canonical Fedora Rust toolchain changes.

| Area | Current implementation | Why it exists | Permanent evidence |
| --- | --- | --- | --- |
| Runtime field borrow | Safe `u64::borrowing_sub` chain | Replaces the larger Hacker's-Delight expansion after Rust 1.97.1 lowered every reviewed final-provider use site to branchless SBB/CMOV code. The expansion originally repaired a real secret-dependent `overflowing_sub` lowering under older compilers. | Full core differential/KAT tests, four core taint cases, EVP-provider taint, and `scripts/check-final-provider-codegen.sh` on each OpenSSL-lane module. |
| Compile-time field borrow | Local Hacker's-Delight identity | `u64::borrowing_sub` is not const-stable. This path constructs public immutable tables and is not executed on secrets at runtime. | Table reconstruction and field differential tests. |
| Field wide reduction | Positive `high * (2^99 - 947)` MAC fold | Exploits the fixed pseudo-Mersenne modulus while removing borrow-heavy work. | Montgomery differential oracle, reachable one-hot/boundary/random cases, taint and final codegen gate. |
| Scalar wide reduction | Natural 304+304 split and fixed `2^304 mod L` | Reuses constant-time `crypto-bigint` Montgomery operations and removes the ten-word Horner loop. | Independently reproduced radix, block-boundary/all-one-hot/random division-oracle tests, taint and final codegen gate. |
| Bounded dependency arithmetic | Source-bound `crypto-bigint 0.7.5` fork with four `wrapping_add`, two `wrapping_neg` and four fixed-schedule `wrapping_sub` sites | Cargo profiles are not transitive. Explicit wrapping semantics remove secret-dependent arithmetic guards and unreachable fixed-schedule underflow guards without requiring a downstream package override. | Upstream checksum and exact patch register, external consumer with overflow checks on, four Valgrind taint cases and final provider codegen gate. |

The final codegen gate is intentionally compiler-specific. Passing it under one
compiler is not a promise about another compiler, architecture, build profile,
or future inlining decision.
