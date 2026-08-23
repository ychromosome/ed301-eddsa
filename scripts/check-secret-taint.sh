#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
sh "$ROOT/scripts/require-verified-snapshot.sh"
sh "$ROOT/scripts/check-rust-build-environment.sh"
case "$ROOT" in
    *"'"*) echo "source snapshot path may not contain an apostrophe" >&2; exit 2 ;;
esac
test -x /usr/bin/valgrind || {
    echo "missing canonical valgrind" >&2
    exit 127
}

WORK=$(mktemp -d /tmp/ed301-secret-taint.XXXXXX)
HOME_DIR=$WORK/home
CARGO_HOME_DIR=$WORK/cargo-home
TARGET_DIR=$WORK/target
MARKERS=$WORK/profile-markers
mkdir -m 700 "$HOME_DIR" "$CARGO_HOME_DIR" "$TARGET_DIR" "$MARKERS"
{
    printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' \
        '' '[source.vendored-sources]'
    printf "directory = '%s'\n" "$ROOT/vendor"
    printf '%s\n' '' '[net]' 'offline = true'
} >"$CARGO_HOME_DIR/config.toml"
chmod 600 "$CARGO_HOME_DIR/config.toml"
printf 'cargo_config_sha256=%s\n' \
    "$(sha256sum "$CARGO_HOME_DIR/config.toml" | awk '{print $1}')"
cleanup() {
    rm -rf -- "$WORK"
}
trap cleanup EXIT HUP INT TERM

env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    /usr/bin/rustc --version --verbose >"$MARKERS/toolchain.txt"
(cd / && env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    CARGO_HOME="$CARGO_HOME_DIR" CARGO_TARGET_DIR="$TARGET_DIR" \
    CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CCACHE_DISABLE=1 \
    CC=/usr/bin/gcc AR=/usr/bin/ar ED301_HERMETIC_NATIVE_BUILD=1 \
    ED301_PROFILE_MARKER_DIR="$MARKERS" \
    ED301_PROFILE_EXCEPTIONS=crypto_bigint=off \
    RUSTC_WRAPPER="$ROOT/scripts/rustc-profile-guard.sh" \
    /usr/bin/cargo build \
        --manifest-path "$ROOT/secret-taint/Cargo.toml" \
        --locked --offline --release)
sh "$ROOT/scripts/check-profile-markers.sh" "$MARKERS" \
    crypto_bigint=off ed301_eddsa=on ed301_valgrind_client=on \
    ed301_eddsa_secret_taint=on

SECRET=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425
PUBLIC=8cad07b4f9a308523a8df9bee22a721b8ff5e597c1ce47e39df67f97a475fd018013fc188890
SIGNATURE=2964a4e22d5ed6e41ad5d5bbfdf4d518bb067b8982f3f8f5900d074a6bee97567b95810336944dfdce74dd889ee9d9db3c10bd1f9da0799bad501c8f3e9260020ad64fa6b02a8c27ce837d00

for mode in defined tainted; do
    for case_name in public sign; do
        env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
            ED301_CT_SECRET_HEX="$SECRET" \
            ED301_CT_EXPECTED_PUBLIC_HEX="$PUBLIC" \
            ED301_CT_EXPECTED_SIGNATURE_HEX="$SIGNATURE" \
            /usr/bin/valgrind --tool=memcheck --vgdb=no \
                --error-exitcode=99 --track-origins=yes \
                --undef-value-errors=yes --leak-check=full \
                --errors-for-leak-kinds=definite,indirect,possible \
                --quiet "$TARGET_DIR/release/ed301-eddsa-secret-taint" \
                "--case=$case_name" "--mode=$mode"
    done
done

sh "$ROOT/scripts/require-verified-snapshot.sh"
