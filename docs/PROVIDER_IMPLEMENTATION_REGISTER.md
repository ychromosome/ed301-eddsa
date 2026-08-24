# Provider implementation register

This register records deliberately local provider infrastructure whose
rationale can become stale as stable Rust changes. Revisit every entry when
the canonical Fedora Rust toolchain changes.

| Area | Current implementation | Why it exists | Replacement trigger | Permanent evidence |
| --- | --- | --- | --- | --- |
| Fallibly allocated shared state | Local immutable `Shared<T>` with atomic reference counting and last-owner destruction | Provider allocation failure must return an OpenSSL error instead of aborting. Stable `Arc::try_new` still requires the unstable `allocator_api` feature. | Replace with `Arc::try_new` once it is stable and preserves the fail-closed allocation contract. | Rust clone/drop/reference-count tests; provider duplicate/free/unload tests; allocation-failpoint and Valgrind lanes. |
| Fallible owned allocation | Local `try_box`/`try_box_at` over the global allocator | Stable `Box::try_new` still requires the unstable `allocator_api` feature. The helper also gives every externally reachable allocation site a deterministic test failpoint. | Replace the allocation core with stable `Box::try_new`; retain only the named test-failpoint wrapper if still needed. | Sized and zero-sized Rust tests; every named site exercised through the provider hardening harness; ordinary-module inert-control test. |

Any replacement must retain fallible allocation, zeroizing destruction of
rejected secret values, the ordinary/test-artifact separation, and the full
provider lifecycle contract. It therefore requires both normative OpenSSL
lanes, the hardening and load/unload matrices, and the secret-taint lane.
