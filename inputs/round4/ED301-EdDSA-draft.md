# Ed301-EdDSA draft 00

Status: **experimental review draft; not frozen; not production suitable**.

## 1. Scope

This document defines one project-specific, context-free PureEdDSA parameter
choice over the frozen ED301-v1 twisted-Edwards curve.  It follows the generic
construction in RFC 8032 Section 3.  It is not Ed25519, Ed448, or a named RFC
8032 instance.

This draft defines no prehash mode, native context, streaming API, ASN.1
identifier, OID, TLS `SignatureScheme`, key-container format or legacy
compatibility rule.  Those are separate profiles and cannot silently change
the bytes defined here.

## 2. Eleven EdDSA parameters

| RFC parameter | Ed301 draft value |
| --- | --- |
| `p` | `2^301 - 2^99 + 947` |
| `b` | `304` |
| field encoding | canonical 303-bit little-endian field encoding |
| `H(X)` | first 76 octets (608 bits) of `SHAKE256(X)` |
| `c` | `2` |
| `n` | `300` |
| `d` | `301` |
| `a` | `2086388329 = 45677^2 mod p` |
| `B` | frozen ED301-v1 base point `G` |
| `L` | frozen prime `q`, with `#E = 4*L` |
| `PH` | identity, `PH(M)=M` |

To avoid collisions with historical variable names, prose SHOULD call the
curve coefficient `d_curve`, the RFC cofactor exponent `c_rfc=2`, the RFC
scalar-bit parameter `n_rfc=300`, the curve-selection counter `c_sel=44730`
and its square root `s_sel=45677`.

Exact decimal values and derivations are fixed by
`upstream/ed301-v1/ed301-v1.json`.

## 3. Encodings

All byte strings are octet strings.  Integers use unsigned little-endian
encoding.

### 3.1 Points

`ENC(x,y)` is 38 bytes:

- bits 0 through 300 contain canonical `y`;
- bits 301 and 302 are zero;
- bit 303 is the least significant bit of canonical `x`.

This is the RFC 8032 "negative" bit, not a different sign convention.  Since
`p` is odd, the canonical representatives `x` and `-x mod p` have opposite
least-significant bits.  In the fixed-width little-endian field encoding this
first differing bit makes the RFC lexicographic definition exactly equivalent
to `LSB(x)=1`.

Decoding separates bit 303, rejects nonzero bits 301 or 302 and requires
`0 <= y < p`.  It recovers

```text
x^2 = (1-y^2) / (a-d_curve*y^2) mod p.
```

The denominator must be invertible and the right side must be a square.  The
root with the encoded least-significant bit is selected.  `x=0` with sign bit
1 is invalid.  Re-encoding a decoded point must reproduce the input exactly.

The fixed base-point encoding is:

```text
6bf73f755a0c80653ce83fcf6d6ff7d7f347b1929224ac67552273419e6cf2c8a88a02d38898
```

### 3.2 Scalars

`ENC_SCALAR(S)` is the exact 38-byte little-endian representation.  Signature
parsing accepts `0 <= S < L`; it rejects `S >= L`.  In particular, zero and
`L-1` are syntactically permitted and `L` is not.

## 4. Key generation

The private key is exactly 38 uniformly random seed bytes.  Let

```text
h = SHAKE256(seed, 76)
lower = bytearray(h[0:38])
prefix = h[38:76]
lower[0]  &= 0xfc
lower[37]  = (lower[37] & 0x0f) | 0x10
s = LE_INTEGER(lower)
A = [s]B
public_key = ENC(A)
```

Thus `s` has bit 300 set, bits 0 and 1 clear, bits 301 through 303 clear,
and exactly 301 bits.  No retry, reduction of the seed or replacement public
key is permitted.  A signing API derives `public_key` from the seed itself or
verifies any cached public value against that derivation.

The pruning rule cannot produce an identity public key.  Every pruned scalar
satisfies

```text
2^300 <= s < 2^301  and  4 | s.
```

Here `L` is odd, `L < 2^300`, and `4L >= 2^301`.  If `s=mL`, oddness of `L`
and `4|s` would require `4|m`, while the two range bounds require `0<m<4`.
No such integer `m` exists.  Therefore `L` does not divide `s`, `[s]B` is not
the identity, and key generation needs no retry.

## 5. Signing

For an opaque message `M`:

```text
r = LE_INTEGER(SHAKE256(prefix || M, 76)) mod L
R = [r]B
Renc = ENC(R)
k = LE_INTEGER(SHAKE256(Renc || public_key || M, 76)) mod L
S = (r + k*s) mod L
signature = Renc || ENC_SCALAR(S)
```

RFC 8032 first interprets each 608-bit hash as a full integer.  Reducing `r`
and `k` modulo `L` at the points shown above is byte-equivalent: `B` has order
`L`, the derived public key lies in that subgroup, and `S` is reduced modulo
`L`.  An implementation may retain the full integers instead.

`r=0`, `R` equal to the identity and `S=0` do not cause retries.  There are no
retry counters, TLV frames, operation tags, embedded public key in the nonce
hash, project KDF or random per-message nonce.

## 6. Verification

Public-key validation and per-signature parsing are logically separate.
Before using a public key, decode `A` canonically and require both `A != O`
and `[L]A = O`.  An implementation may cache that fully validated point, but
verification must not omit either public-key condition.

For each signature, require an exact 76-byte input and split it as
`Renc || Senc`.  Decode `Renc` only as a canonical curve point.  There is no
`[L]R = O` requirement: `R = O`, a prime-subgroup `R`, and a mixed-torsion
`R` are all syntactically permitted.  Separately parse `Senc` as the exact
38-byte little-endian scalar from Section 3.2 and reject `S >= L`.

Compute

```text
k = LE_INTEGER(SHAKE256(Renc || public_key || M, 76)) mod L
```

and accept exactly when

```text
[4S]B = [4]R + [4k]A.
```

This cofactored equation is the only normative acceptance equation.  An
uncofactored equation is not an alternative conformance path: it would reject
some canonically encoded mixed-torsion commitments accepted above and would
therefore define a different signature language.

## 7. Context and prehash boundary

This draft retains context Option A and defines no new signature instance.  It
has no native context: `dom` is the empty string and the hash inputs above are
exact.  It also has no prehash mode.  A protocol requiring domain separation
must place an unambiguous protocol identifier and framing inside `M`.

Existing applications using an external Ed301 context parameter are not
automatically compatible.  A future native-context instance would require a
separate name/identifier, a frozen domain function and independent vectors.
It must not be emulated by silently ignoring a supplied context.

## 8. Security and implementation boundaries

- The reference implementation is variable-time and not suitable for keys.
- Production code requires constant-time field and scalar arithmetic,
  zeroization, fault handling and side-channel validation.
- Deterministic signing does not remove the need for a uniformly generated
  seed or protection against leakage and faults.
- Full nonidentity prime-subgroup validation applies to public keys.  A
  signature commitment `R` instead has only canonical point syntax plus the
  normative cofactored-equation check from Section 6.
- This is a classical signature and is not post-quantum secure.

## 9. Standards and claims

RFC 8032 is Informational and concretely specifies Ed25519/Ed448 families.  A
future reviewed implementation may be described as:

> A project-defined PureEdDSA instantiation following the generic
> construction in RFC 8032 Section 3 over ED301-v1, using SHAKE256.

It must not be described as RFC-standardized Ed301 or interoperable with a
named RFC 8032 instance.

FIPS 186-5 and SP 800-186 currently approve Edwards25519 and Edwards448 for
EdDSA, not ED301-v1.  SHAKE256 is standardized by FIPS 202, but that fact does
not make this parameter choice FIPS approved or CMVP validated.

## 10. Unresolved review gates

1. Independent review of `b=304`, `c=2`, `n=300` and SHAKE256/76.
2. Independent implementation and independently generated vectors.
3. Review that downstream protocols using Option A frame domain bytes
   unambiguously inside `M`.
4. New OID, ASN.1 profile and TLS private-use codepoint; old identifiers must
   not be silently redefined.
5. Constant-time production implementation and full assurance campaign.
