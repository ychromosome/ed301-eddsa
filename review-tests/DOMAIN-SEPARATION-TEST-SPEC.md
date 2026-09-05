# Domain-separation regression contract

The v1 domain block is:

```text
"SigEd301-v1" || 0x00 || octet(len(context)) || context
```

The context is an opaque 0--255-byte string. Omitted and explicit empty
contexts are identical. The domain block prefixes both nonce and challenge
transcripts. Ed301-EdDSA-v1 has one pure mode; it has no prehash instance.

`independent-v1-oracle.py` uses the sealed pre-v1 curve oracle and independently
checks every intermediate field in the seven published v1 KAT records. It also
checks all 256 context lengths and the four bidirectional draft-00/v1 rejection
boundaries.

The regression suite MUST prove:

1. Rust and the independent oracle reproduce every KAT byte.
2. A signature verifies only under its original context.
3. Changing a context byte or length changes nonce and challenge hashes.
4. Distinct contexts cannot share a domain encoding.
5. OpenSSL message-sign and `DigestSign` one-shot paths agree.
6. A rejected context update cannot fall back to a previous context.
7. Draft-00 and v1 signatures reject across profiles.

Intermediate scalars and hashes are test evidence, not production API.
