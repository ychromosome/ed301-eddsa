# Ed301-EdDSA

Experimental Rust implementation of `Ed301-EdDSA-draft-00` over the ED301
elliptic curve.

- `no_std`
- safe Rust
- context-free one-shot signing and verification
- locked, vendored and offline builds
- draft vectors and edge cases included

## Test

```sh
sh scripts/check.sh
sh scripts/check-secret-taint.sh
```

## Experimental OpenSSL provider

The `provider-experiment` branch contains a signature-only provider with
test-only identifiers.  Given an unmodified OpenSSL 3.5.7 or 4.0.1 prefix:

```sh
scripts/test-provider.sh /path/to/openssl-prefix 3.5.7
scripts/test-provider.sh /path/to/openssl-prefix 4.0.1
```

The provider is an integration candidate, not a release.  See
`PROVIDER_STATUS.md`.

## Status

Round-2 pre-deep-scan candidate. Not production-ready.

See `STATUS.md` and `ZEROIZATION_AND_CT_BOUNDARY.md` for the current assurance
boundary.

## License

Apache-2.0. Vendored dependencies retain their own licenses.
