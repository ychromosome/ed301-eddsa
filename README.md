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

## Status

Round-2 pre-deep-scan candidate. Not production-ready.

See `STATUS.md` and `ZEROIZATION_AND_CT_BOUNDARY.md` for the current assurance
boundary.

## License

Apache-2.0. Vendored dependencies retain their own licenses.
