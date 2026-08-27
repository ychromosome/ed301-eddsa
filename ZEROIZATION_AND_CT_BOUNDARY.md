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

Provider keys and signature contexts share immutable expanded-signing and
prepared-verification objects through a narrow atomic reference-counted owner.
The owner is fallibly allocated, exposes no mutation, and destroys its value
after the last reference. The expanded signing object remains separate from
the public verification table: a public-only key or context therefore cannot
keep a private scalar or nonce prefix alive. Last-owner destruction runs the
existing zeroizing secret destructors; it does not strengthen the physical-copy
disclaimer above.

The owner necessarily uses raw-pointer operations and explicit `Send`/`Sync`
implementations inside the provider's pre-existing native FFI unsafe boundary.
Its ordering follows the standard immutable reference-count pattern: relaxed
increments, release decrements, an acquire fence before last-owner destruction,
and abort on reference-count overflow. It adds no unsafe code to the public
cryptographic core or its arithmetic, but it is still part of the provider FFI
surface that requires independent review and lifecycle stress testing.

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

The public `Signature` is a transparent owner of exactly the 76 canonical wire
bytes. Decoded commitment and response arithmetic exists only in a private,
operation-local parser result and is never retained in the returned value.
The taint harness checks the complete 76-byte object after signing and asserts
that its storage has no additional bytes; the provider FFI consequently holds
only that wire value after the Rust signing call returns. This removes the
avoidable nonce-correlated projective representation from the public and FFI
output boundary without strengthening the every-copy disclaimer for arithmetic
temporaries while signing is in progress.

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

The runtime wide-field reducer folds with the positive two-limb constant
`2^99 - 947`. Its multiply-accumulate and carry loops have compile-time-fixed
trip counts and end in the existing conditional-subtraction barrier. This
removes the former source-level borrow chains without introducing a new
unsafe block or architecture intrinsic. The source argument remains subject
to exact-build disassembly, taint and timing checks; Safe Rust alone is not a
constant-time proof.

The subgroup test for an externally supplied public key now reuses that public
point's odd-multiples verification table with a fixed width-8 wNAF encoding of
the public order `L`. Its 299 doublings, 17 signed mixed additions and table
indices depend only on the hardcoded public schedule, not on point data. The
identity is rejected before table construction and no `VerifyingKey` is
constructed before `[L]P = O`; decodable non-subgroup inputs nevertheless pay
one bounded public table construction before rejection. The former sparse,
input-independent 299-doubling/63-addition schedule remains the differential
reference. Internally derived public keys do not repeat either hostile-input
subgroup operation: `[s]B` is in the exact-order base-point subgroup by
construction, and pruning makes an identity scalar impossible in the selected
range. The ordinary build retains a cheap declassified identity fault check
and validates the resulting curve encoding; `sign-self-verify` also retains
the explicit subgroup and signature-equation fault checks. Canonical public
bytes and their unique affine point cross the public-output declassification
boundary, while the secret-correlated projective coordinate is discarded.

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

The source-bound `crypto-bigint 0.7.5` fork uses explicit wrapping operations
at six bounded arithmetic sites where workspace-wide overflow checks added
secret-dependent panic branches, and at four fixed public schedule
subtractions where the compiler retained unreachable panic branches. Every
crate, including the fork, is now built with overflow checks enabled; no
consumer-specific package-profile exception is accepted or required. The
shared compiler wrapper also enforces
`panic=unwind`, optimization level 3, one codegen unit and disabled debug
assertions on the root, downstream, secret-taint and provider release gates.
The external downstream workspace deliberately supplies no package override;
its Valgrind and final-binary gates remain artifact-specific evidence rather
than a promise about future compilers.
