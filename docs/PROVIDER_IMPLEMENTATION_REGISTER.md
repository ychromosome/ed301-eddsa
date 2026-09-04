# Provider implementation register

This register records deliberately local provider infrastructure whose
rationale can become stale as Rust or OpenSSL changes. Revisit affected
entries when either toolchain changes.

| Area | Current implementation | Why it exists | Replacement trigger | Permanent evidence |
| --- | --- | --- | --- | --- |
| Fallibly allocated shared state | Local immutable `Shared<T>` with atomic reference counting and last-owner destruction | Provider allocation failure must return an OpenSSL error instead of aborting. Stable `Arc::try_new` still requires the unstable `allocator_api` feature. | Replace with `Arc::try_new` once it is stable and preserves the fail-closed allocation contract. | Rust clone/drop/reference-count tests; provider duplicate/free/unload tests; allocation-failpoint and Valgrind lanes. |
| Fallible owned allocation | Local `try_box`/`try_box_at` over the global allocator | Stable `Box::try_new` still requires the unstable `allocator_api` feature. The helper also gives every externally reachable allocation site a deterministic test failpoint. | Replace the allocation core with stable `Box::try_new`; retain only the named test-failpoint wrapper if still needed. | Sized and zero-sized Rust tests; every named site exercised through the provider hardening harness; ordinary-module inert-control test. |
| Provider RAND instances | Two lazily created, locked OpenSSL `CTR-DRBG` instances parented by `RAND_get0_primary(child)`: one for private seeds and one for public salt/IV output | `RAND_priv_bytes_ex(child)` creates thread-local child-context state. The provider-owned instances preserve OpenSSL's private/public separation without a child thread-exit handler. Application `rand.seed` and `seed_strict` do not propagate to the child primary. | Replace if OpenSSL exposes a child-safe provider RAND route with equivalent policy, locking and teardown semantics. | Deterministic/failing RAND, warm-policy, Ed301-first, cross-thread keygen and encrypted-encoder teardown tests on both lanes and under Valgrind. |
| Child provider fallback | Load and immediately unload OpenSSL's `null` provider after child-context creation | This disables child-local default-provider fallback before RAND or cipher fetch. Providers subsequently loaded by the application remain mirrored into the child. | Remove if OpenSSL supplies an explicit child-fallback control. | Ed301-first keygen and PKI cipher-fetch failures followed by successful recovery after application default-provider load. |

Any replacement must retain fallible allocation, zeroizing destruction of
rejected secret values, the ordinary/test-artifact separation, and the full
provider lifecycle contract. It therefore requires both normative OpenSSL
lanes, the hardening and load/unload matrices, and the secret-taint lane.
