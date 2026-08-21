# Public OpenSSL lane evidence contract

`scripts/build-openssl-provider-lane.sh` consumes only a caller-staged
public release
tarball. It performs no clone, network fetch, private-fork lookup, packaging,
or release operation. The only accepted lanes are:

| lane | release name | public source URL | shared-library major |
|---|---|---|---|
| 3.5.7 | openssl-3.5.7 | https://www.openssl.org/source/openssl-3.5.7.tar.gz | 3 |
| 4.0.1 | openssl-4.0.1 | https://www.openssl.org/source/openssl-4.0.1.tar.gz | 4 |

The builder also pins the full SHA-256 digest of each accepted release
tarball: `a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8`
for 3.5.7 and
`2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09`
for 4.0.1. Both the sidecar value and the tarball bytes must match the
corresponding pinned value.

The URL is provenance metadata only. The helper does not fetch it; the
tarball and its `.sha256` sidecar must already exist in the supplied upstream
directory. The checksum sidecar must name exactly the selected tarball,
contain the pinned digest, and pass a strict `sha256sum -c` check. The
tar listing must contain one
top-level `openssl-<version>/` tree, no absolute or `..` member, and
`VERSION.dat`.

A release tarball has no verifiable Git object database. Consequently
`source_commit` and `source_tree` are explicitly
`NOT_AVAILABLE_FROM_RELEASE_TARBALL`; the lane seal does not infer a commit or
tree from the release name. `authenticated_git_tag` is recorded as
`NOT_VERIFIED_FROM_RELEASE_TARBALL`.

This lane verifies the pinned SHA-256 values but does not perform an OpenPGP
identity check. A separately authenticated OpenSSL signing-key/PGP check is
therefore an explicit provenance gate for any release use beyond this test
campaign.

## Required per-lane artifacts

Under the lane root, `logs/<version>/` contains:

- `builder_inputs.sha256` and `builder_identity.tsv`, binding the exact
  builder and this provenance document before and after the build;
- `toolchain_identity.tsv` and `build_environment.tsv`, recording executable
  paths/versions, OS/kernel/architecture, and relevant inherited variables;
- `tarball.sha256`, `tarball_checksum.sha256`, and `source_identity.tsv`;
- `source_manifest_pristine.sha256` and its `.seal`, made immediately after
  extraction plus the explicit `VERSION.dat` check, and before `Configure`;
- `source_manifest_post.sha256`, `source_change.tsv`, and the source file
  lists used by the post-build check;
- `linker_selection.tsv`, recording the selected `-L<lane>/lib` and
  `-Wl,-rpath,<lane>/lib` arguments;
- `openssl_modules_pre.tsv` (the explicit empty-prefix pre-state) and
  `openssl_modules_post.sha256`, covering the installed OpenSSL
  `lib/ossl-modules/*.so` files;
- `artifact_hashes.sha256`, covering the CLI, both shared libraries, the
  dereferenced contents at their unversioned symlink paths, and installed
  OpenSSL module DSOs; `library_symlinks.tsv` separately binds the link targets;
- `runtime_binding.ldd` and `runtime_binding.readelf`, produced under a clean
  environment and proving that the CLI
  `libcrypto` and `libssl` DSOs resolve under the exact selected prefix and
  that the only RPATH/RUNPATH is that prefix's `lib/`;
- `lane_identity.seal`, the machine-readable release/header/library/loader
  identity record; and
- `evidence_manifest.sha256` and its seal, hashing every preceding executable
  step's log and exit file plus the identity, provenance, source, loader, and
  artifact records. The manifest intentionally excludes its own log/exit, its
  subsequent verification step, and the final lane-status transition to avoid
  a self-referential hash. The final outer snapshot must bind those remaining
  files.

Every executable step has a sibling `<step>.exit` and captured stdout/stderr.
`LANE <version> OK` is written only after the evidence manifest is complete.
Any failed manifest, version, loader, linker, or hash check records
`LANE <version> FAILED` and a nonzero `lane_status.exit`; no later command can
overwrite it with `OK`.

The source manifest is a content/presence seal for all regular files present
after extraction and the version check. OpenSSL's in-tree build may add
generated files, so the
post-build check requires every pre-existing regular file to remain byte
identical and records added regular-file paths in `source_change.tsv`; it does
not falsely call the entire post-build directory pristine.

## Provider-module and sanitizer boundary

The OpenSSL lane helper does not build the Ed301 provider module and does not
claim to sanitize OpenSSL or the provider. The acceptance runner records
ordinary, failpoint, and collider provider-module hashes after the harness
build and again after the targeted execution gates, and compares them
byte-for-byte. Those hashes are separate from `openssl_modules_post.sha256`,
which covers only OpenSSL's installed module directory.

The runner's ASan/UBSan gate is targeted to
`provider_signature`, `provider_keymgmt`, `provider_serialization`,
`val01_decoder_bio`, `provider_load`, and `provider_tls`, with a separate
`provider_hardening` Rust-allocation-only run. Valgrind is targeted to
`provider_signature`, `provider_serialization`, `val01_decoder_bio`,
`provider_load`, and the same `provider_hardening` Rust-allocation-only run;
the GCC analyzer is targeted to `c/provider_shim.c`. These scopes are written
as evidence and reported as targeted checks. They do not instrument the
OpenSSL shared libraries, every harness, every provider entry path, or the
whole matrix, and they do not establish a general memory-safety claim.

No lane result should be promoted beyond public OpenSSL 3.5.7/4.0.1 tarball,
build, and runtime identity verified under this evidence contract.
