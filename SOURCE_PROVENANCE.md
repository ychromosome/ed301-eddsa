# Source provenance

## Curve inputs and historical signature profile

The ED301-v1 curve, key derivation, encodings and historical domainless
signature fixtures are copied byte-for-byte from the manifest-bound Round-4
source tree observed on 2026-08-15. Their portable hashes are recorded in
`inputs/round4/SHA256SUMS`. Those signature fixtures remain compatibility
evidence and are not the active signature profile.

The copied Round-4 source manifest has SHA-256
`bea39d24dd5f952d715c3cdd3db5c163a95cdb4645128b046e88d4c2db226da2`.
The Round-4 review recommendation and later execution logs are intentionally
not implementation inputs and are not included in this source tree.

The complete earlier curve-selection and verification archive is now retained
under `evidence/curve-provenance/archive/ed301_technischer_abschluss/`. Its
original 458-entry manifest has SHA-256
`cdaffd6b332681aaf6d944d39a1275610d42dbb3823b74d3a5e3cf446e6f6c50`.
It binds the original search programs, 355 worker files, combined transcript,
parameter JSON, certificates, mathematical checks, independent verifiers and
recorded outputs. A separate curve-only runner verifies those bytes without
promoting the archive's historical signature or X301 text into the active
contract. Three human-source inputs outside that archive remain hash-only and
are not relicensed. No pre-search public commitment is claimed.

## Active Ed301-EdDSA-v1 profile

`inputs/v1/ED301-EdDSA-v1.md` defines the incompatible active profile. It
keeps the curve, key derivation and wire sizes, but prefixes both signature
hash transcripts with the RFC 8032 Ed448-shaped native domain
`"SigEd301-v1" || 0x00 || octet(len(C)) || C`. OID `.301.4` is bound to this
profile; `.301.3` remains frozen for the historical domainless profile.

`tools/generate_ed301_eddsa_v1_vectors.py` derives the active vectors from the
sealed seeds, messages and structural edge cases. Its variable-time Python
oracle in `provider-tests/oracle/ed301_eddsa_v1/` implements the new transcript
independently of the Rust transcript while deliberately reusing the separately
tested Python curve arithmetic. `inputs/v1/SHA256SUMS` binds the profile,
oracle, generator and resulting vectors. Reproduction must write to a fresh
directory and compare both generated JSON files byte-for-byte.

## Reused Rust primitives

The implementation reused or consulted the following paths in commit
`2d0375b92292e37bf34ec595751671cb38fa483c` of the local
`ed301-openssl-provider` repository:

| origin path | relationship | Git blob | source SHA-256 |
|---|---|---|---|
| `Cargo.toml` | dependency and release-profile pattern | `661cc2254f79ad31999e10ef17430c479c28dce6` | `74490465bac3066134bb9c48960264cc2144b5502006d8cbc10af37bbd1b7e53` |
| `crates/ed301-core/Cargo.toml` | derived public-crate manifest | `152766d2469116b51c2c89eee28d8341f7be7753` | `753a4a7b9327f689af7908074ca49ad40ed4fb173af8a7dc454aaa58bb59903c` |
| `crates/ed301-core/src/lib.rs` | derived safe `no_std` crate boundary | `55d6c1eb41a2825b98f7467ef2c0aa7c581d6884` | `3d31272adf46fc97802e0fda5e059baadb023946aa64b1b5d7abb6fc570d905c` |
| `crates/ed301-core/src/parameters.rs` | derived sizes and curve constants; identifiers replaced | `ffee0825cda982dc95836057a4f63f0300d8ddc2` | `29d4c802412934cd5f32116ab6fda32732ff125d6c2a964524cfb368e83200ff` |
| `crates/ed301-core/src/field.rs` | derived field core | `b7d623352fe4af5ea13a2984491b45fbdaf3db8d` | `57c4cb8a885022d0291081559ca165eaf55a6a49a2e9e76dea90470ff4852ec6` |
| `crates/ed301-core/src/edwards.rs` | derived Edwards core | `98bd156cc10b99186c3175c024c96eebb96a9ba1` | `b77e01a59c2712425f9cdd38580e6cd9e5d047dfdf09ba926adddbc96d7e98d2` |
| `crates/ed301-core/src/scalar.rs` | adapted arithmetic; 64-byte reducer replaced by 76-byte reducer | `f6cac16efe845038559ba664a1da9cb349f95259` | `0ae75f2beaec78bbe7e7564f400bf2a319d998cc96a8b773b92003ff3a310689` |
| `crates/ed301-core/src/signature_hash.rs` | adapted SHAKE layer; transcript semantics rewritten | `b25331077be789ec67bcdaf72cc4b38f5023a18f` | `111535b567c15b6588a2cfc5814b1c6146ebf673a161ad4cdda1eeaad8c63e95` |
| `crates/ed301-core/src/signature.rs` | adapted ownership patterns; signature flow rewritten | `b0d948f7efee230fa5a063e02a5720972244b251` | `9f4c4c232b2e3750108b3c816ac5724b27a4cc3132185ef643c29ef21384e122` |
| `crates/ed301-core/src/secret_taint.rs` | adapted instrumentation seam | `b1d55320f287b4830875289d741f1003765938f3` | `af43b8938756562d97dc5df3a22e03b4774c9e145cf96d8e9d6766afb270900b` |
| `secret-taint/Cargo.toml` | derived harness manifest | `fe7d59576463a935b693ac86776c71b944fa7eba` | `23bc7e48be58edc62f663d4211f1a2772510811075208ca83ec812738a3dd430` |
| `secret-taint/src/main.rs` | derived harness flow | `ee393e7617bc60794c68ad8af3cbe52c35c6226a` | `5583c4df4eb9ba1889c38417e1d1235efd27218ad18582841eb1e536dfcccc90` |
| `secret-taint/valgrind-client/Cargo.toml` | byte-identical test helper | `d18083772eacef92a6acdbd972a90e24f1274210` | `4f28383153e1a4f8fba26a440439f0fd9edf307e89010e40530543895aae396d` |
| `secret-taint/valgrind-client/build.rs` | byte-identical test helper | `f022840773d0988fd3bf27861f1e65386c88720f` | `8309eaee52161a5e157ad5c3993f8816e68562ba2fc2d2402f90b810f75d0722` |
| `secret-taint/valgrind-client/c/valgrind_client.c` | byte-identical test helper | `6aaa953e1375e8bada6c462ecfedf28659491df0` | `df01647f67bb77f8cdd894aa67fe721f2ff1960acb2c4757a52e7ac25253db19` |
| `secret-taint/valgrind-client/src/lib.rs` | byte-identical test helper | `b99fda8a3a8e266a565d458b98b5e89e2cdca84d` | `704238f245a73618c8aae3911a22e91115f21b3f8324e6d5d8d30338bcf077c3` |

The candidate copies remove unrelated X301 helpers and narrow interfaces for
Ed301-EdDSA-v1. The scalar, transcript and signature layers adapt
implementation patterns but rewrite the incompatible byte-contract semantics;
the historical signature semantics are not reused. The
Valgrind client is test-only and remains outside the public crate's safe Rust
boundary. The square-root exponentiation delegates to the bounded,
constant-schedule Montgomery exponentiation supplied by the same pinned
`crypto-bigint 0.7.5` source. The source-bound fork at
`vendor/crypto-bigint/` replaces six bounded operations with explicit
wrapping forms so consumer-wide overflow checks cannot add secret-dependent
panic branches. Its upstream checksum, VCS identity, narrowed active manifest
and exact patch scope are recorded in that directory. The project-specific
76-byte scalar reducer remains explicit.

The Git blob identifiers and SHA-256 values above preserve the exact origin
mapping without making the historical repository part of this source tree.

## Safe-Rust performance repair input

The 2026-08-24 Safe-Rust MAC-fold and public-import wNAF changes were reviewed
from `ED301_EDDSA_PERFORMANCE_ROUND2_CLAUDE_RESPONSE_2026-08-24.zip`, SHA-256
`778557578b615e902753fe1e18227d4d7ecdd45b8b8f0d2148c2bccca3b8129c`.
Its combined prototype diff has SHA-256
`bd0f84f0dbc361ea046c49186ba1cbd2fdb84e04169efa9e344871d204aa518e`.

The response archive's outer manifest and patch bytes verified, but its nested
integrated source carried the unchanged parent `SOURCE_MANIFEST.sha256` and a
host-absolute sidecar. The nested source archive was therefore not adopted as
an authenticated checkpoint. The three code changes were instead applied to
the current authoritative worktree, compared byte-for-byte with the proposed
tree, documented here and placed behind a newly generated local source
manifest before authoritative gates.

The imported ideas change only the portable field reduction schedule and the
public external-key subgroup schedule. The BMI2 spike, architecture
intrinsics, runtime CPU dispatch and its proposed unsafe boundary were not
imported. The public cryptographic crate retains `#![forbid(unsafe_code)]`.

## Freeze boundary

Published checkpoints are identified by their Git commit and by
`SOURCE_MANIFEST.sha256`.  Review results apply only to the exact source
identity recorded with those results.

## Experimental provider donor

The provider experiment was reconstructed from the source-only portion of
`ED301_EDDSA_DRAFT00_PROVIDER_FABLE_PRE100_RESULT_20260818.zip`, SHA-256
`3547ee9f5e59dbe223e3c621132069afce61ee34c92895f164af8a5df1e9a5d2`.
Its internal content manifest was verified before any file was consulted.

Imported relationships:

| repository path | donor relationship |
|---|---|
| `provider/crates/ed301-eddsa-provider/` | adapted provider Rust/C source |
| `provider-tests/` | adapted C harnesses and vector generator |
| `scripts/provider-profile-guard.sh` | adapted profile-observation helper |
| `scripts/build-openssl-provider-lane.sh` | adapted public-release builder |

Old compiled modules, harness binaries, result logs and PASS receipts were not
imported.  The repository version binds the provider directly to the current
local `ed301-eddsa` crate, uses the repository's vendored dependencies,
generates active fixtures from `inputs/v1/`, replaces the donor orchestrator,
and records fresh local evidence.  The donor is design and source provenance,
not an independent security review.

## Provider repair references

The 2026-08-22 integration repair consulted the public OpenSSL 3.5.7 release
source for provider-facing interface patterns:

| OpenSSL path | relationship | source SHA-256 |
|---|---|---|
| `providers/legacyprov.c` | child `OSSL_LIB_CTX` and Core error-mark dispatch pattern | `59ba86bced50be12994c366e1d9805011da60ba0601ed320d3dee600f7aa9add` |
| `test/testutil/fake_random.c` | minimal test-only RAND dispatch shape | `33298fb660c10c89d486d2ffd5845512b845bd64914e3b0644061fd15a14e0fc` |

The implementation is not a copy of either provider. It narrows those public
Apache-2.0 interface patterns to the Ed301 child-context and deterministic
RAND regression tests.
