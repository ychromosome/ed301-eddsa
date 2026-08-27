# Ed301 patch provenance

This directory is a source-bound fork of crates.io `crypto-bigint 0.7.5`.
The upstream crate checksum is
`1a52aa3fcda4e6302a9f48734f234d35d4721b96f8fe07d073f07ce9df4f0271`;
the original registry checksum and VCS metadata are retained as
`UPSTREAM_CARGO_CHECKSUM.json` and `.cargo_vcs_info.json`.

The active `Cargo.toml` exposes only the dependency closure and empty feature
names needed by this source-bound build; `zeroize` is the only supported
optional feature. `Cargo.toml.orig` preserves the complete upstream manifest.

Ed301 also changes six operations whose mathematical ranges are already
bounded by the adjacent upstream comments:

- four additions in `src/modular/mul.rs` use `wrapping_add`;
- two negations in `src/modular/safegcd.rs` use `wrapping_neg`.

The values do not overflow on valid inputs. Explicit wrapping semantics prevent
workspace-wide overflow checks from adding secret-dependent panic branches.
No algorithm, Ed301-used API, modulus or output changes. This source-bound fork
is not a general-purpose replacement for every upstream feature.

Revalidate the fork whenever the Rust toolchain or upstream dependency changes:
run the external-consumer tests, the four Valgrind taint cases and the final
provider-binary code-generation gate. Apply upstream security fixes manually;
this fork does not claim automatic update compatibility.
