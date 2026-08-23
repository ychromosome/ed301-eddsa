#!/bin/sh
set -eu

for name in \
        RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC RUSTC_WRAPPER \
        RUSTC_WORKSPACE_WRAPPER ED301_PROFILE_MARKER_DIR \
        ED301_PROFILE_EXPECTATIONS; do
    if env | grep -q "^${name}="; then
        echo "inherited Rust build override is forbidden: $name" >&2
        exit 1
    fi
done

if env | grep -Eq \
        '^(CARGO_PROFILE_RELEASE(_[A-Za-z0-9_]+)?|CARGO_TARGET_[A-Za-z0-9_]+_RUSTFLAGS|CARGO_BUILD_RUSTFLAGS|CARGO_BUILD_RUSTC|CARGO_BUILD_RUSTC_WRAPPER|CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER)='; then
    echo "inherited Cargo profile or compiler override is forbidden" >&2
    env | LC_ALL=C sort | grep -E \
        '^(CARGO_PROFILE_RELEASE(_[A-Za-z0-9_]+)?|CARGO_TARGET_[A-Za-z0-9_]+_RUSTFLAGS|CARGO_BUILD_RUSTFLAGS|CARGO_BUILD_RUSTC|CARGO_BUILD_RUSTC_WRAPPER|CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER)=' \
        | sed 's/=.*$/=<redacted>/' >&2
    exit 1
fi

printf 'rust_build_environment=PASS\n'
