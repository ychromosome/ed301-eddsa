# Contributing

This is an experimental cryptographic implementation candidate. Small,
reviewable issues and pull requests are welcome, but no contribution should
expand its claims or silently change the active v1 byte contract. The
domainless draft-00 inputs remain immutable historical evidence.

Before proposing a change:

1. read `README.md`, `STATUS.md`, `ZEROIZATION_AND_CT_BOUNDARY.md`, the active
   profile under `inputs/v1/` and the immutable inputs under `inputs/round4/`;
2. preserve the Ed448-style v1 domain, one-shot API and exact encodings unless
   a new, incompatible profile and identity are explicitly proposed;
3. update tests and provenance for every behavioral change;
4. run `evidence/curve-provenance/run_curve_checks.sh --full` after any change
   to the curve evidence;
5. regenerate `SOURCE_MANIFEST.sha256`; and
6. run the `check`, `review-tests`, and `check-secret-taint` commands through
   `scripts/run-authoritative-gate.sh` from the verified archive snapshot
   described in `README.md`; and
7. run both provider lanes after provider or FFI changes.

Do not submit production-readiness, audit, constant-time-completion,
zeroization-completion or standards claims without corresponding independent
evidence.
