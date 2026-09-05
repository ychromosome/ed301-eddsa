# ED301 curve provenance

This directory publishes the complete manifest-bound technical package
preserved on 2026-07-31. It contains the original `c`-search programs, all 355
worker results, the combined search transcript, parameter inputs, point-count
and security scripts, prime certificates, independent verifiers and recorded
outputs. The archived package manifest has SHA-256
`cdaffd6b332681aaf6d944d39a1275610d42dbb3823b74d3a5e3cf446e6f6c50`.

The evidence establishes the recorded deterministic rule
`s = 947 + c`, `a = s^2 mod p`, complete recorded coverage through `c=50687`,
the first qualifying candidate at `c=44730`, and the final curve/twist
properties. `REPRODUCE.md` gives read-only verification and fresh-search
commands.

This is after-the-fact provenance. No independently timestamped public
commitment to the construction or predicate predates the search, and this
publication cannot create one retroactively. It also is not an external audit,
a standardization claim or production approval.

The archive includes historical signature and X301 material because those
bytes belong to its original manifest. They are nonnormative here. The active
Ed301-EdDSA-v1 contract is `../../inputs/v1/ED301-EdDSA-v1.md`.

Three earlier human-source documents were outside the archived technical
package and are authenticated only by `HISTORICAL_INPUT_HASHES.txt`. Their
contents are not required to recompute the curve. In particular, the
lore-bearing whitepaper remains outside the repository and is not relicensed.
