# Baseline results at `d1df208`

Environment:

- Ubuntu 24.04.3 x86-64;
- Rust 1.97.1;
- Valgrind 3.22.0;
- GCC 13.3.0;
- system OpenSSL headers 3.0.13;
- separately built OpenSSL 3.5.7 reference prefix.

## Results

| Gate | Result | Evidence |
|---|---:|---|
| Wire negative matrix | PASS | 1,136 exhaustive one-bit mutations and 20,000 deterministic arbitrary triples |
| Whole signature object | FAIL | generated object: 320 bytes, 206 marked bytes; parsed object: 320 bytes, 6 padding bytes |
| External release consumer | FAIL | Valgrind exit 99; 3,014 errors from 36 secret-labelled branch contexts in `crypto_bigint` without the root profile exception |
| OpenSSL 3.0.13 headers | FAIL | accidental undeclared `OSSL_FUNC_SIGNATURE_*_MESSAGE_INIT` identifiers rather than an intentional floor guard |
| OpenSSL 3.5.7 headers | PASS | complete C shim syntax check |
| Positive provider context contract | FAIL | 6 passed, 16 failed; the current draft/provider deliberately rejects every context |

The whole-object output was:

```text
signature_object_state label=signed size=320 undefined_bytes=206 ranges=[(0, 199), (314, 319)]
signature_object_state label=parsed size=320 undefined_bytes=6 ranges=[(314, 319)]
```

The header-floor output identified the actual missing APIs:

```text
OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT undeclared
OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT undeclared
```

The context contract was compiled and executed against the independently
built OpenSSL 3.5.7 prefix and the ordinary provider module from the pinned
source. Failures were the intended positive assertions: explicit empty,
`alpha`, `beta`, binary and 255-byte contexts; cross-context verification; and
agreement between message-sign and `DigestSign` paths.

## Gate sanity control

The signature-object gate was also run against a temporary diagnostic edit
which reduced `Signature` to one `[u8; 76]` field and reparsed it internally
for verification. That edit was not retained as a proposed product patch. The
gate then reported:

```text
signature_object_state label=signed size=76 undefined_bytes=0 ranges=[]
signature_object_state label=parsed size=76 undefined_bytes=0 ranges=[]
```

This control establishes that the gate can turn green after the intended
class of repair and does not merely fail every signing implementation.
