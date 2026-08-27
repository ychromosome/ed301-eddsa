# ED301 OID registry

The [IANA Private Enterprise Numbers registry](https://www.iana.org/assignments/enterprise-numbers/)
assigns number `66282` to Adiumentum GmbH. The ED301 project uses the subtree
`1.3.6.1.4.1.66282.301`.

| OID | Assignment | State |
| --- | --- | --- |
| `1.3.6.1.4.1.66282.301.1` | Ed301-Sig-v1 | Historical and retired; never reassign |
| `1.3.6.1.4.1.66282.301.2` | X301 | Existing assignment; unchanged |
| `1.3.6.1.4.1.66282.301.3` | Ed301-EdDSA-draft-00 | Historical and frozen; never reinterpret |
| `1.3.6.1.4.1.66282.301.4` | Ed301-EdDSA-v1 key and signature algorithm | Active experimental assignment |

The `.301.4` OID binds the exact manifest-defined Ed301-EdDSA-v1 byte profile,
including its Ed448-style native domain. It is used without
`AlgorithmIdentifier` parameters for both the key algorithm in SPKI/PKCS#8
and the signature algorithm in CSR and certificate objects. The fixed
encodings contain a 38-byte raw public key, a 38-byte private seed and a
76-byte signature. The canonical DER sizes are 58 bytes for SPKI and 62 bytes
for PKCS#8.

An incompatible change to the algorithm semantics or wire encoding requires
a new OID. In particular, the retired `.301.1` and frozen `.301.3` identities
must never be reused, even though neither was deployed as an official public
provider.

This private-enterprise allocation does not constitute an IANA TLS
SignatureScheme registration, an interoperability standard or a production
readiness claim. TLS test codepoint `0xFE84` remains a separate private-use,
nonregistrable identifier and is not derived from this OID.
