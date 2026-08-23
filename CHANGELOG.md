# Changelog

## Unreleased

- Hardened provider key generation, secret ownership, and child-library-context teardown.
- Reduced the ordinary provider to `KEYMGMT` and `SIGNATURE`; isolated optional PKI/TLS integration and limited TLS decoding to a transactional SPKI-only test boundary.
- Enforced strict serialization and PKI validation at the host boundary.
- Made Rust and OpenSSL builds reproducible, externally sealed, and resistant to environment, path, configuration, and source-integrity injection.
- Added regression coverage for the repaired provider, lifecycle, randomness, collision, parser, and build-integrity cases.
