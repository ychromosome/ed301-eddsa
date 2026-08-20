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

Destructors do not run under `panic=abort`. The checked release profile uses
`panic=unwind`; controlled tests exercise both the central zeroizing guard and
the actual expansion/signing scopes under `catch_unwind`. These tests do not
inspect freed stack memory and do not strengthen the every-copy disclaimer.

The separate Valgrind harness marks the seed undefined and exercises public
key derivation and signing through explicit public-output boundaries. It is a
preliminary control-flow and memory check for one local build, not a proof of
constant-time execution, complete zeroization or fault resistance.

The deferred assurance work includes the full source security scan,
disassembly and secret-dependent branch/address review, multi-architecture
timing and cache tests, fault injection, and a decision on a stricter
non-`Copy` secret-arithmetic ownership model. Until those gates are complete,
this candidate must not process production keys.

The release override for `crypto-bigint 0.7.5` is a top-level integration
requirement, because Cargo profiles are not transitive. Each consuming product
or provider workspace must repeat that override for its real production
profile and revalidate the effective compiler flags and final machine code.
The bundled downstream workspace is an executable integration fixture, not a
substitute for that production-specific review.
