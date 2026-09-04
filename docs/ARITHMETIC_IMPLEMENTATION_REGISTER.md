# Arithmetic implementation register

This register records deliberately local arithmetic code whose rationale can
become stale as compilers and libraries change. Revisit every entry whenever
the canonical Fedora Rust toolchain changes.

| Area | Current implementation | Why it exists | Permanent evidence |
| --- | --- | --- | --- |
| Runtime field borrow | Safe `u64::borrowing_sub` chain | Replaces the larger Hacker's-Delight expansion. Rust 1.97.1 and 1.98.0 produced two reviewed branchless SBB/CMOV profiles; older `overflowing_sub` code had produced a secret-dependent branch. | Full core differential/KAT tests, four core taint cases, EVP-provider taint, and `scripts/check-final-provider-codegen.sh` on each OpenSSL-lane module. |
| Compile-time field borrow | Local Hacker's-Delight identity | `u64::borrowing_sub` is not const-stable. This path constructs public immutable tables and is not executed on secrets at runtime. | Table reconstruction and field differential tests. |
| Field wide reduction | Positive `high * (2^99 - 947)` MAC fold | Exploits the fixed pseudo-Mersenne modulus while removing borrow-heavy work. | Montgomery differential oracle, reachable one-hot/boundary/random cases, taint and final codegen gate. |
| Scalar wide reduction | Natural 304+304 split and fixed `2^304 mod L` | Reuses constant-time `crypto-bigint` Montgomery operations and removes the ten-word Horner loop. | Independently reproduced radix, block-boundary/all-one-hot/random division-oracle tests, taint and final codegen gate. |
| Field helper inlining | `#[inline(always)]` on the five-limb product, square, small-product and reduction helpers | A Rust 1.98.0 Ryzen-5950X comparison found the forced form 5.3--9.1% faster than no forced inlining with 6.5% more provider `.text`. Ordinary `#[inline]` saved 1.2% `.text` but lost up to 2.3%; removing only nested-helper attributes was no smaller or faster. The forced form is retained with a 10% same-build `.text` budget against the no-force variant. | The final codegen gate accepts emitted or inlined product, square and reduction helpers. `scripts/run-performance-receipt.sh` records future host-specific results. |
| Lazy reduction inside the group formulas | Private `Fe301Lazy` (`[0, 2p)`) and `Fe301LazyLinear` (`[0, 4p)`) types; `double`, `add` and `add_affine` canonicalize only returned coordinates | Operands below `4p < 2^303` produce wide products below `2^606`; two fixed folds return a value below `2p`. Protocol encodings and canonical public values are unchanged. | Independent full-domain products, squares, small products, all reducer bits through 605, 5,000-point formula differential, taint, timing and final codegen gates. |
| Bounded dependency arithmetic | Source-bound `crypto-bigint 0.7.5` fork with four `wrapping_add`, two `wrapping_neg` and four fixed-schedule `wrapping_sub` sites | Cargo profiles are not transitive. Explicit wrapping semantics remove secret-dependent arithmetic guards and unreachable fixed-schedule underflow guards without requiring a downstream package override. | Upstream checksum and exact patch register, external consumer with overflow checks on, four Valgrind taint cases and final provider codegen gate. |

The final codegen gate is intentionally compiler-specific. Passing it under one
compiler is not a promise about another compiler, architecture, build profile,
or future inlining decision.
