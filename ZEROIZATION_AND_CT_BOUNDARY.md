# Zeroization and constant-time boundary

This experimental candidate places the named logical owners of the seed,
expanded seed bytes, pruned and reduced secret scalar, prefix, deterministic
nonce, secret response term and response serialization buffer in RAII guards
from creation. Those guards clear their values on ordinary return, error
return and panic unwinding. The public crate is safe Rust and has no unsafe
block.

This is not a guarantee that every physical copy is erased. `Scalar`,
`FieldElement` and `EdwardsPoint` use by-value arithmetic, and Rust or LLVM may
create additional stack, register or ABI copies beyond the named owners. The
candidate therefore makes no forensic stack-remanence or every-copy
zeroization claim.

The provider seed-import boundary constructs the fixed-size seed directly
inside its non-`Copy`, zeroizing owner. It no longer creates a plain Rust
array and then copies that array into the owner. The C key-generation buffer
is cleared on every path after import. This removes the avoidable
source-level temporary but does not strengthen the physical-copy disclaimer.

Destructors do not run under `panic=abort`. The core crate and OpenSSL provider
therefore reject every non-unwinding panic strategy at compile time. The
checked release gates additionally append `panic=unwind` to the actual `rustc`
invocation for each security-relevant crate and record the complete invocation
and toolchain identity. Controlled tests exercise both the central zeroizing
guard and the actual expansion/signing scopes under `catch_unwind`. These
tests do not inspect freed stack memory and do not strengthen the every-copy
disclaimer.

The separate Valgrind harness marks the seed undefined and exercises public
key derivation and signing through explicit public-output boundaries. It is a
preliminary control-flow and memory check for one local build, not a proof of
constant-time execution, complete zeroization or fault resistance.

Secret fixed-base multiplication uses signed radix 16 with a fixed number of
digits. Every digit scans all eight entries in its table and selects with
constant-time masks. The specialized five-limb field backend uses fixed-size
loops, and each runtime conditional correction crosses the `CtAssign`/`cmov`
barrier. Separate `const` helpers exist only to construct immutable public
tables during compilation; runtime secret arithmetic cannot call them. Public
verification uses explicitly named variable-time wNAF/Straus recoding and
table indexing; its response, challenge, commitment and verification key are
public. Point decoding uses a public fixed-exponent square-root-ratio
calculation and always verifies the candidate before accepting it. These
source properties still require the fresh final-code disassembly, taint and
timing gates listed below.

The ordinary provider follows the standard EdDSA signing path and does not
perform a second complete verification of each signature. The optional
`sign-self-verify` feature retains that extra fault-detection check for a
separately selected build. This choice does not alter secret arithmetic,
transcript bytes or the verification language; it does change the additional
fault-detection boundary and must remain explicit in downstream build records.

Provider key generation requests 149 bits from the application-linked private
RAND path in a child `OSSL_LIB_CTX`. A thread that uses that RAND path calls
`OPENSSL_thread_stop_ex()` for the child context before provider teardown;
the cross-thread unload regression keeps the worker alive while the final
provider reference is released.

The deferred assurance work includes a fresh exact-revision full-scope source
security scan, disassembly and secret-dependent branch/address review,
multi-architecture timing and cache tests, fault injection, and a decision on
a stricter non-`Copy` secret-arithmetic ownership model. Until those gates are
complete, this candidate must not process production keys.

The release override for `crypto-bigint 0.7.5` is a top-level integration
requirement, because Cargo profiles are not transitive. The repository's
shared compiler wrapper enforces `crypto-bigint` overflow checks off, ED301
overflow checks on, `panic=unwind`, optimization level 3, one codegen unit and
disabled debug assertions on the actual compiler calls used by the root,
downstream, secret-taint and provider release gates. Inherited Rust/Cargo
compiler and release-profile overrides are rejected before Cargo runs. Each
external consuming product must still repeat the override for its real
production profile and revalidate its final machine code. The bundled
downstream workspace is an executable integration fixture, not a substitute
for that production-specific review.
