# OpenSSL pattern decisions and deviations

Date: 2026-08-27

This register records which OpenSSL Ed25519/Ed448 test patterns are adopted
for the optional Ed301 PKI integration and where the Ed301-EdDSA-v1 contract
deliberately differs.  OpenSSL test sources are structural precedents, not
normative Ed301 encodings.  The Ed301 v1 specification and provider contracts
remain authoritative.

Local comparison sources:

- `test/endecode_test.c`
- `test/evp_extra_test.c`
- `test/x509_req_test.c`
- `test/x509_test.c`
- `test/verify_extra_test.c`
- `providers/implementations/keymgmt/ecx_kmgmt.c`
- `providers/implementations/signature/eddsa_sig.c`
- `providers/implementations/encode_decode/decode_der2key.c`
- OpenSSL's generic PEM-to-DER and EncryptedPrivateKeyInfo decoders

## Serialization and decoder matrix

| ID | Decision and contract source | Enforcement |
| --- | --- | --- |
| D1 | Adopt the OpenSSL encoder/decoder round-trip pattern. The provider contract requires PKCS#8 and SPKI DER -> PEM -> DER to remain byte-identical. | `provider-tests/provider_serialization.c` tests both structures. |
| D2 | The project-owned complete-buffer boundary accepts exactly one DER object. One trailing octet is an error for both PKCS#8 and SPKI. | Both forms have explicit `DER + 1` rejection tests. |
| D3 | Adopt the truncation categories from `endecode_test.c`, specialized to the fixed Ed301 layouts. Empty input, every tag/length/value boundary, and the final short value reject. | Boundary tables in `provider_serialization.c`. |
| D4 | Follow the parameterless ECX AlgorithmIdentifier pattern. Encoders emit absent parameters; decoders reject `NULL` and every explicit parameter type. | Exact encoder bytes plus PKCS#8/SPKI parameter-negative tests. |
| D5 | The assigned Ed301 OID must be byte-exact and must map to the no-digest SIGID. Historical Ed301-Sig-v1, X301, and other OIDs are foreign. | Serialization OID negatives and the host-registry assertions in `provider_pki.c`. |
| D6 | **Deliberate deviation:** v1 accepts only PKCS#8 `PrivateKeyInfo` version 0. RFC 5958 `OneAsymmetricKey` version 1, with or without embedded public key, is rejected. The seed uniquely derives the public key and KEYMGMT validates that relation, so accepting a second embedded copy adds mismatch policy without a profile requirement. Revisit only if a later Ed301 PKI profile normatively adopts OneAsymmetricKey. | Explicit version-1 and canonical embedded-public-key rejection tests. No mismatch-acceptance path exists. |
| D7 | Ed301-EdDSA-v1 fixes the seed at 38 bytes. The nested private-key OCTET STRING accepts neither 37 nor 39 bytes. | Independently constructed DER objects carry 37- and 39-byte seeds in `provider_serialization.c`; both reject. |

The ordinary and PKI artifacts expose no decoder.  The private-use TLS
integration artifact follows OpenSSL's Ed25519/Ed448 decoder shape: separate
`PrivateKeyInfo` and `SubjectPublicKeyInfo` DER dispatches share one KEYMGMT
and reference-transfer path.  Ed301 differs only by enforcing its fixed
62-byte PKCS#8 and 58-byte SPKI encodings.  As in OpenSSL's ECX decoders, the
decoder dispatch names include the canonical key OID so generic DER chaining
can select them without an application-owned OID registry.  KEYMGMT and
SIGNATURE retain their existing name set; historical and X301 OIDs are not
aliases.  The collider remains SPKI-only.
OpenSSL's generic chain removes PEM and standard EncryptedPrivateKeyInfo
wrappers before the Ed301 DER decoder runs; the provider contains no PEM,
Base64, password or encryption parser.

## PKI matrix

| ID | Decision and contract source | Enforcement |
| --- | --- | --- |
| P1 | Adopt the public X.509 round-trip pattern: a self-signed Ed301 CA certificate is DER-reparsed and verified. | `provider-tests/provider_pki.c`. |
| P2 | The optional all-Ed301 profile supports a direct Ed301 CA -> Ed301 leaf chain through `X509_STORE`. | Strict profile and store verification test. |
| P3 | Mixed-algorithm interoperability is supported through generic OpenSSL X.509 validation in both directions: classic P-256 ECDSA CA -> Ed301 leaf, and Ed301 CA -> classic P-256 ECDSA leaf. Such certificates intentionally fail the all-Ed301 profile predicate where their signature algorithm or SPKI is classic. | Two public-API chain tests; no ASN.1 byte mutation. |
| P4 | Adopt the signed-TBS integrity pattern. A serial-number mutation through `X509_set_serialNumber()` after signing must invalidate verification. | Focused semantic TBS mutation test. |
| P5 | An Ed301 CSR must sign and verify, survive DER and PEM reparsing, retain exact SPKI/signature identifiers, and reject signature/SPKI mutations. | CSR matrix in `provider_pki.c`. |
| P6 | **Not supported in v1:** no Ed301 CRL-signing or OCSP-response profile is claimed. Their object identifiers, responder authorization, freshness and extension policies are not defined by the signature profile. Revisit only with a separate PKI profile and permanent identifiers; do not infer support merely because generic EVP signing could be wired to those containers. | Register-only negative scope decision; no synthetic CRL/OCSP test. |

## SIGNATURE decisions reserved by the same register

| ID | Decision and contract source | Enforcement |
| --- | --- | --- |
| S6 | Ed301-EdDSA-v1 adopts the Ed448 `dom4` structure with label `SigEd301-v1`, fixed `phflag=0`, one-octet context length and an opaque 0--255-byte context. The domain prefixes both nonce and challenge transcripts. Empty context is the default; oversize, duplicate and wrongly typed context parameters fail closed. DigestSign/DigestVerify reinitialization with a NULL key retains only a matching bound operation and applies new parameters atomically, as Ed25519 and Ed448 do. | Independent context KATs plus empty, binary, 255/256-byte, altered-context, duplicate, reinit, duplication and get/set tests in the Rust core and `provider_signature.c`. |
| S7 | Ed301-EdDSA-v1 has one fixed pure instance. `OSSL_SIGNATURE_PARAM_INSTANCE`, prehash mode, external digest selection and streaming/prehashed signing are rejected rather than reinterpreted. The Ed448-style `phflag` is always zero; no Ed301ph variant exists. | Existing pure-only, instance, digest, prehash and streaming rejection tests. |

## KEYMGMT decisions reserved by the same register

| ID | Decision and contract source | Enforcement |
| --- | --- | --- |
| K6 | Ed301 public-key import validates canonical encoding and prime-subgroup membership before an `EVP_PKEY` can materialize. Invalid torsion and mixed-order inputs therefore reject at the `EVP_PKEY_fromdata` API boundary; they are not retained as deferred-invalid objects for a later `EVP_PKEY_public_check`. This is deliberately stricter and more fail-closed than the deferred-check shape used by some ECX fixtures. | Existing invalid-point and mixed-order `fromdata` rejection tests; valid keys additionally pass `EVP_PKEY_check` and `EVP_PKEY_public_check`. |
| K7 | An imported private seed derives one unique Ed301 public key. If an import supplies both components, seed/public equality is checked atomically and a mismatch never materializes as an `EVP_PKEY`; no partially replaced key is observable. | Existing mismatched-pair and atomic-import rejection tests; valid complete keys additionally pass `EVP_PKEY_check` and `EVP_PKEY_pairwise_check`. |

## Lifecycle and failpoint decisions reserved by the same register

| ID | Decision and contract source | Enforcement |
| --- | --- | --- |
| L6 | Use real provider-owned failure boundaries only. The `provider_hardening` signature-duplicate failpoint and the `provider_rand` generate-failure path are retained. No product hook is added merely to simulate host RAND installation failure, `pthread` failure, or allocation inside OpenSSL PKI containers, because those operations are not provider-owned. Revisit only if a combined PKI-plus-failpoint provider is deliberately built and reviewed. | Existing hardening and RAND failure tests; host-owned failures remain outside the product failpoint surface. |

## Review rule

Every future OpenSSL or Rust toolchain update must preserve the decisions
above.  A new container form or PKI object class is a profile change, not a
test-only compatibility tweak, and requires a new dated register entry plus
positive and negative vectors.
