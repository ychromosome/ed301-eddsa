# Ed301-EdDSA

Experimental Rust implementation of `Ed301-EdDSA-draft-00` over the ED301
elliptic curve.

- `no_std`
- safe Rust
- context-free one-shot signing and verification
- locked, vendored and offline builds
- draft vectors and edge cases included

## Test

In a Git checkout, the gates bind `SOURCE_MANIFEST.sha256` to `HEAD` and
reject every extra, missing, non-regular or changed source path before Cargo
runs:

```sh
sh scripts/check.sh
sh scripts/check-secret-taint.sh
```

For a source archive, first authenticate the enclosing archive and obtain the
manifest digest from that trusted handoff. Then pass it explicitly:

```sh
ED301_EXPECTED_SOURCE_MANIFEST_SHA256=<trusted-sha256> sh scripts/check.sh
```

The manifest inside an unauthenticated archive is not its own trust anchor.

## Experimental OpenSSL provider

The `provider-experiment` branch contains a signature-only provider with
test-only identifiers.  Given an unmodified OpenSSL 3.5.7 or 4.0.1 prefix:

```sh
scripts/test-provider.sh /path/to/openssl-prefix 3.5.7
scripts/test-provider.sh /path/to/openssl-prefix 4.0.1
```

The ordinary module exposes no TLS capability.  The runner builds the
private-use TLS proof and its full-provider collision fixture as separately
named, disabled-by-default test artifacts.

The provider is an integration candidate, not a release.  See
`PROVIDER_STATUS.md`.

## Status

Round-2 post-finding-repair candidate awaiting a fresh full-scope deep scan.
Not production-ready.

See `STATUS.md` and `ZEROIZATION_AND_CT_BOUNDARY.md` for the current assurance
boundary.

## License

Apache-2.0. Vendored dependencies retain their own licenses.
