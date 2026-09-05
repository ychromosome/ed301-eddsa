# Ed301-EdDSA v1 core review step

This first review commit contains the experimental Ed301-EdDSA-v1 Rust core,
its frozen inputs, curve evidence, vendored dependencies and portable test
sources. The next commit adds the complete OpenSSL provider, integration,
packaging, authoritative gate launcher and final user documentation.

The active signature profile is `inputs/v1/`; `inputs/round4/` remains
immutable historical draft-00 evidence. No wire format is changed by this
history condensation. The full development history is retained on
`provider-experiment` at commit
`5c688206a15f6ab88a50d53fe503665a302cec4d`.

The root Cargo workspace is independently buildable with locked, vendored,
offline dependencies. Its unit-test configurations are debug and release,
each with and without `sign-self-verify`. Release overflow checks remain
enabled for both the owned code and the repository's patched crypto-bigint.
The profile guard and marker checker are included unchanged.

These intermediate unit checks are not the final authoritative integration
gate. This is a research and review candidate, not a production release,
completed audit or universal constant-time or zeroization claim.

Apache-2.0; vendored dependencies retain their original licenses and notices.
