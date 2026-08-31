# Hostile regression gates

`run.sh` checks:

- the v1 OID and DER encodings with an independent encoder;
- all published v1 transcript intermediates and draft-00 rejection boundaries;
- signature length, mutation and arbitrary-input behavior;
- the 76-byte public `Signature` representation;
- external release-profile secret taint;
- intentional rejection of unsupported OpenSSL headers; and
- the OpenSSL context contract when `OPENSSL_PREFIX` and
  `ED301_MODULE_DIR` are set.

The two taint gates require Valgrind. The provider context gate requires
`ed301_eddsa_v1.so` built against the supplied OpenSSL prefix.

```sh
scripts/run-authoritative-gate.sh archive <trusted-sha256> review-tests

scripts/run-authoritative-gate.sh archive <trusted-sha256> review-tests \
    /absolute/prefix /absolute/module-directory
```

`BASELINE-d1df208.md` records the original failures. The current source tree
must pass these gates; the baseline is not current status.
