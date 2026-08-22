# Provider F1-F6 repair receipt

Date: 2026-08-22

Source branch: `provider-experiment`, repairing the provider state at
`5bbe63982169cd88afd657364c4c1ccc00eb731a`. This receipt belongs to the
commit that contains it.

## Finding dispositions

| finding | disposition | regression evidence |
|---|---|---|
| F1 | Repaired. Provider key generation uses `RAND_priv_bytes_ex()` with a child `OSSL_LIB_CTX`; Rust imports the generated seed and no longer obtains entropy independently. | Deterministic application RAND controls the exact key seed; forced RAND failure is fail-closed; recovery succeeds. |
| F2 | Repaired. Provider-side OID/SIGID registration and error marks use Core upcalls only; direct provider-side `OBJ_*` and `ERR_*` registry inspection is gone. | Host-side preflight and postflight inspect the registry belonging to the loading application and preserve the caller error queue. |
| F3 | Repaired. Builds are separated by ABI major; OpenSSL 3 requires minor 5 or later and OpenSSL 4 requires minor 0 or later. Patch equality is not required. | Shim unit tests cover exact, patch-skew, later-minor, malformed and wrong-major versions; both supported lanes pass. |
| F4 | Repaired. The provider PID/atomic spinlock, sleep/retry loop and process-global claim are gone. | A portable host `CRYPTO_THREAD` lock covers only the test helper's own preflight/load/postflight sequence; incomplete and conflicting registrations fail immediately and explicit retry is tested. |
| F5 | Repaired. Bespoke Base64, PEM armor, hex and private text formatting are gone. Strict fixed DER remains; PEM armor uses OpenSSL. | DER/PEM round trips, encrypted PKCS#8 CLI interop and absence of text/hex encoder selection pass. |
| F6 | Repaired. The ordinary provider contains no `TLS-SIGALG` capability. | Separately named, disabled-by-default TLS test and collision artifacts are both full Ed301 KEYMGMT/SIGNATURE providers; both load orders complete the private-use TLS handshake. |

## Environment

- Rust: 1.97.1, LLVM 21.1.8
- Cargo: 1.97.1
- Clang and scan-build: 21.1.8
- Valgrind: 3.27.1
- Target: x86_64 Fedora Linux

## OpenSSL lanes

| lane | OpenSSL CLI SHA-256 | libcrypto SHA-256 | libssl SHA-256 | result |
|---|---|---|---|---|
| 3.5.7 | `6eda175fd1586ae349b03be70747dec2b9ee51da6ac82c5545ff59ec782adf15` | `5fe6ce3092e88f9f1f13c0b15ef6650735f1eef98b73f27e1f844881ec2b6a79` | `7bf0c92ecdb2e67f77ee5c00202cd75cb16e10139627e9a668cbf3afe5561c9d` | PASS |
| 4.0.1 | `ae675e7f3c4e02d8a50293c38755f3626185297edeb97e09f7b861cfe4943696` | `c94847b627099329b03963ef1b3c4709202ed8509f892699f53926082490d781` | `0cbccd8e5e0a8cab7338876e71f94b6ce6c5d1b49517a1f58a6f716576430515` | PASS |

Each module was compiled against the headers and libraries of its own lane.
Runtime-library binding, provider exports and module identity are checked by
the acceptance runner.

## Provider artifacts

| lane | ordinary | failpoint | TLS test | full TLS collider |
|---|---|---|---|---|
| 3.5.7 | `5f28cd592341555ed1fa51ca36cfebc3aa1774ae7b2eb6e2493eb7303d052e3d` | `1c437985053b056a4331e39c41e68d471579b401e5755358c86f68eda7dab3b6` | `153de0b6a2dcbc95e2d9880f01fbe31be62768f1ec371bee601d6bdb7bc78161` | `35de2c145174e2ef97aa7d0ecac37402b361e9bb06da0b96a4b91acf4beb1918` |
| 4.0.1 | `700ca477716ee4157a12cee903a5e81494b764f02dd96bc1d5eb6e25b167e70a` | `067fa4425e4a0b858fcbc83457ffa0f475f42d937cf46b66c9d6e3fc60c79050` | `01c05c22b9db8e90f94753c902c1e43ecfe7144a0a74c5602c8b3527bc61915a` | `cb08a434e70db0a5ff728cf8acfe47b5ca2adbbcd3dae061d0319d1c42de88d1` |

The complete lane logs have SHA-256
`15ecf54ef20919b36c9d056f1898621ef4122d9b0a595dff70c92db04e7449b1`
for 3.5.7 and
`34f9762ef9d5c79e75e88e9cd6aa8f9a620a9c9b5d3d7e0e749e1a793f134428`
for 4.0.1.

## Executed provider gates

Both lanes completed the full source-driven acceptance runner, including:

- ordinary provider load/unload, exact operation surface and no TLS capability;
- KEYMGMT, SIGNATURE, positive vectors, negative and policy matrices;
- strict PKCS#8/SPKI, PEM, encrypted PKCS#8 and PKI/CSR/chain workflows;
- application-controlled RAND, RAND failure and recovery;
- private-use TLS server authentication and mutual TLS in the test artifact;
- full-provider private-use codepoint collision tests in both load orders;
- OID/SIGID free, exact and conflict states plus fresh parallel loads;
- ASan/UBSan, Valgrind, GCC `-fanalyzer`, scan-build, panic and allocation
  fail-closed checks.

The 3.5.7 runner ended with `PASS provider lane 3.5.7`; the 4.0.1 runner
ended with `PASS provider lane 4.0.1`.

The final isolated core gate also passed: source and Round-4 manifests, Cargo
metadata, rustfmt, Clippy with `-D warnings`, Debug 32/32, Release 32/32,
rustdoc with `-D warnings`, and downstream release KAT 1/1. The Secret-Taint
lane passed all four instrumented Valgrind cases: public/sign with defined and
tainted secret input.

## Boundary

This receipt establishes local functional and targeted hardening evidence for
the F1-F6 repair on one x86_64 environment. It is not a Deep Security Scan, a
general constant-time proof, a complete zeroization claim, a permanent OID or
TLS identifier assignment, production approval or release approval. The
private-use `0xFE84` path remains a separately built test artifact only.
