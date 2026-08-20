# Contributing

This is an experimental cryptographic implementation candidate. Small,
reviewable issues and pull requests are welcome, but no contribution should
expand its claims or silently change the draft-00 byte contract.

Before proposing a change:

1. read `README.md`, `STATUS.md`, `ZEROIZATION_AND_CT_BOUNDARY.md` and the
   immutable inputs under `inputs/round4/`;
2. preserve the context-free one-shot API and exact encodings unless a new,
   incompatible profile is explicitly proposed;
3. update tests and provenance for every behavioral change;
4. regenerate `SOURCE_MANIFEST.sha256`; and
5. run `sh scripts/check.sh` and, where Valgrind is available,
   `sh scripts/check-secret-taint.sh`.

Do not submit production-readiness, audit, constant-time-completion,
zeroization-completion or standards claims without corresponding independent
evidence.
