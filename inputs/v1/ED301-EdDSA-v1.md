# Ed301-EdDSA-v1

Status: experimental review profile; not a standard or production release.

## Profile

Ed301-EdDSA-v1 is a project-defined PureEdDSA instance over the unchanged
ED301-v1 curve. It follows the generic construction in RFC 8032 section 3 and
the Ed448 domain-separation shape in RFC 8032 section 5.2.6. It is not a named
RFC, FIPS, IANA or CMVP algorithm.

The curve, base point, group order `L`, encodings, 38-byte seed, 38-byte public
key, SHAKE256/76 expansion and 76-byte signature are unchanged from the sealed
draft-00 inputs in `../round4/`. This document changes the signature transcript
and therefore defines an incompatible protocol identity.

## Native domain

For a context octet string `C` with `0 <= len(C) <= 255`, define

```text
dom301(C) = "SigEd301-v1" || octet(0) || octet(len(C)) || C
```

The first octet after the label is the Ed448-style `phflag`. It is fixed to
zero. Ed301-EdDSA-v1 defines no prehash or alternate instance. The second
octet is the unsigned one-octet context length. The default context is empty,
so its complete domain is:

```text
"SigEd301-v1" || 0x00 || 0x00
```

The context is opaque binary data; it is neither UTF-8 nor NUL terminated.
A context longer than 255 bytes is an error, not a truncated value.

## Key derivation

For an exact 38-byte seed:

```text
h = SHAKE256(seed, 76)
lower = h[0:38]
prefix = h[38:76]
lower[0] &= 0xfc
lower[37] = (lower[37] & 0x0f) | 0x10
s = LE_INTEGER(lower)
A = [s]B
public_key = ENC(A)
```

Key derivation has no domain prefix and is consequently byte-identical to the
sealed draft-00 profile. A key may be imported into either profile, but a
signature never crosses the protocol boundary.

## Signing

For message `M` and context `C`:

```text
r = LE_INTEGER(SHAKE256(dom301(C) || prefix || M, 76)) mod L
R = [r]B
Renc = ENC(R)
k = LE_INTEGER(
        SHAKE256(dom301(C) || Renc || public_key || M, 76)
    ) mod L
S = (r + k*s) mod L
signature = Renc || ENC_SCALAR(S)
```

The domain is present independently in both the nonce and challenge
transcripts. Signing is deterministic for a fixed seed, message and context.

## Verification

Public keys require canonical decoding, nonidentity and `[L]A = O`. A
signature is exactly 76 bytes `Renc || Senc`; `Renc` must decode canonically
and `Senc` must encode `0 <= S < L`. As in draft-00, `R` is not required to be
in the prime subgroup.

Compute

```text
k = LE_INTEGER(
        SHAKE256(dom301(C) || Renc || public_key || M, 76)
    ) mod L
```

and accept exactly when

```text
[4S]B = [4]R + [4k]A.
```

The context supplied to verification must be byte-identical to the signing
context. An absent context means the empty context.

## Identity and compatibility

The project OID for this exact profile is
`1.3.6.1.4.1.66282.301.4`, with absent `AlgorithmIdentifier` parameters.
The frozen `.301.3` OID remains assigned to the domainless draft-00 profile.
Neither identity may be reinterpreted.

Tests must prove both directions of incompatibility: v1 rejects sealed
draft-00 signatures, and the sealed draft-00 oracle rejects v1 signatures.
The historical `Ed301-Sig-v1` protocol and OID `.301.1` remain separately
retired and are not aliases for this profile.
