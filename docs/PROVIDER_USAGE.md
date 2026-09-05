# Ed301 OpenSSL provider usage

Ed301-EdDSA-v1 is experimental and not standardized or FIPS validated.
Keys are 38 bytes and signatures are 76 bytes.

## Provider modules

`ed301_eddsa_v1` exposes `KEYMGMT` and `SIGNATURE` for explicit EVP use.
It does not register an OID or provide file codecs.

`ed301_eddsa_v1_tls_test` adds the project OID, PKCS#8/SPKI codecs, text
output and the private-use TLS 1.3 signature capability. It registers and
checks the OID and digestless SIGID when loaded. The RPM policy subpackage
loads this module but does not alter Fedora's signature preference.

## Signatures

Ed301-EdDSA-v1 supports one-shot `EVP_DigestSign()` and
`EVP_DigestVerify()`. The digest name MUST be `NULL`. Streaming, external
digests, prehash instances and randomized signing are unsupported.

`context-string` is an optional opaque value of 0 through 255 bytes. Signer
and verifier MUST use identical context bytes. The empty context is still
included in the Ed301-v1 domain.

## Keys

Generate an unencrypted PKCS#8 key:

```sh
openssl genpkey -algorithm Ed301-EdDSA-v1 -out ed301.key
```

Inspect and validate it:

```sh
openssl pkey -in ed301.key -check -text -noout
```

Encrypt it directly:

```sh
openssl pkey -in ed301.key -aes-256-cbc \
  -out ed301-encrypted.key
```

The generic PKCS#8 command is also supported:

```sh
openssl pkcs8 -topk8 -in ed301.key -v2 aes-256-cbc \
  -out ed301-encrypted.key
```

Both commands request the passphrase interactively unless `-passout` is
specified. Loading an encrypted key uses `-passin`.

## Formats

The supported private format is PKCS#8 `PrivateKeyInfo` with version
`INTEGER 0`, absent AlgorithmIdentifier parameters and one nested 38-byte
seed. RFC 5958 `OneAsymmetricKey` version 1, attributes and an embedded public
key are rejected.

The public format is `SubjectPublicKeyInfo` with absent AlgorithmIdentifier
parameters and one 38-byte public key. DER and PEM are supported. Standard
`EncryptedPrivateKeyInfo` and PKCS#12 wrapping use OpenSSL implementations;
the provider implements no cipher, KDF, password parser or Base64 codec.

## PKI and TLS

The integration module supports X.509 certificates, PKCS#10 requests,
PKCS#12 bundles, Ed301 root/intermediate/leaf chains and X.509 CRLs. OCSP and
CMS are outside the v1 profile.

TLS support is limited to TLS 1.3 through private-use SignatureScheme
`0xFE84` in the matching OpenSSL review fork. TLS uses the empty Ed301 context.
TLS 1.2 and DTLS are unsupported.

The project OID is `1.3.6.1.4.1.66282.301.4`. It is a private-enterprise
assignment, not an IANA algorithm registration.
