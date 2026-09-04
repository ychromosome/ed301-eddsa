#!/bin/bash
set -Eeuo pipefail

PATH=/usr/bin:/bin
export PATH LC_ALL=C
umask 077

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
sh "$ROOT/scripts/check-rust-build-environment.sh"
sh "$ROOT/scripts/require-verified-snapshot.sh"
if (( $# < 3 || $# > 4 )); then
    printf 'usage: %s <openssl-prefix> <cpu> <new-output-dir> [repetitions]\n' "$0" >&2
    exit 2
fi
PREFIX=$(readlink -f -- "$1")
CPU=$2
OUTPUT=$3
REPETITIONS=${4:-7}
case "$CPU:$REPETITIONS" in
    *[!0-9:]*|:*|*:0)
        echo "cpu and repetitions must be positive integers" >&2
        exit 2
        ;;
esac
if [[ ${ED301_BENCH_PINNED:-0} != 1 ]]; then
    exec env ED301_BENCH_PINNED=1 taskset -c "$CPU" "$0" "$@"
fi
[[ ! -e $OUTPUT && ! -L $OUTPUT ]]
mkdir -m 700 -p -- "$OUTPUT/inputs" "$OUTPUT/logs" \
    "$OUTPUT/cargo-home" "$OUTPUT/target" "$OUTPUT/lib"
OUTPUT=$(readlink -f -- "$OUTPUT")
LIBCRYPTO=$(readlink -f -- "$PREFIX/lib/libcrypto.so")
SONAME=$(readelf -d "$LIBCRYPTO" \
    | sed -n 's/.*(SONAME).*\[\([^]]*\)\].*/\1/p')
test -n "$SONAME"
cp -- "$LIBCRYPTO" "$OUTPUT/lib/$SONAME"
/usr/bin/python3 -I -B "$ROOT/scripts/write-cargo-config.py" \
    "$OUTPUT/cargo-home/config.toml" "$ROOT/vendor"

env -i PATH=/usr/bin:/bin HOME="$OUTPUT" LC_ALL=C \
    CARGO_HOME="$OUTPUT/cargo-home" CARGO_TARGET_DIR="$OUTPUT/target" \
    CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CCACHE_DISABLE=1 \
    /usr/bin/cargo build --manifest-path \
        "$ROOT/performance/ed301-bench/Cargo.toml" --release --locked --offline
RUST_BENCH=$OUTPUT/target/release/ed301-benchmark
C_BENCH=$OUTPUT/openssl-signature-benchmark
/usr/bin/cc -O3 -Wall -Wextra -Werror -std=c11 \
    -I"$PREFIX/include" "$ROOT/performance/openssl_signature_bench.c" \
    -L"$PREFIX/lib" -Wl,-rpath,"$OUTPUT/lib" -lcrypto -o "$C_BENCH"

{
    printf 'format=ed301-performance-receipt-v1\n'
    printf 'timestamp_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'source_manifest_sha256=%s\n' \
        "$ED301_EXPECTED_SOURCE_MANIFEST_SHA256"
    printf 'cpu=%s\naffinity=%s\nrepetitions=%s\n' \
        "$CPU" "$(taskset -pc $$ | sed 's/^[^:]*: //')" "$REPETITIONS"
    printf 'cpu_model=%s\n' "$(sed -n '/^model name[[:space:]]*: / { s/^model name[[:space:]]*: //; p; q; }' /proc/cpuinfo)"
    printf 'kernel=%s\n' "$(uname -srvmo)"
    printf 'loadavg_before=%s\n' "$(sed -n '1p' /proc/loadavg)"
    printf 'rust_bench_sha256=%s\n' "$(sha256sum "$RUST_BENCH" | awk '{ print $1 }')"
    printf 'control_bench_sha256=%s\n' "$(sha256sum "$C_BENCH" | awk '{ print $1 }')"
    printf 'libcrypto_sha256=%s\n' "$(sha256sum "$OUTPUT/lib/$SONAME" | awk '{ print $1 }')"
    printf 'rustc=%s\n' "$(rustc --version)"
    printf 'cargo=%s\n' "$(cargo --version)"
    printf 'cc=%s\n' "$(cc --version | sed -n '1p')"
    "$PREFIX/bin/openssl" version -a
} >"$OUTPUT/RUN_IDENTITY.txt" 2>&1

printf 'round\tposition\talgorithm\toperation\tcount\tmean_ns\tlog\n' \
    >"$OUTPUT/raw.tsv"
sequence=0
run_rust() {
    round=$1
    position=$2
    operation=$3
    count=$4
    sequence=$((sequence + 1))
    log=$OUTPUT/logs/$(printf '%03d-ed301-%s.log' "$sequence" "$operation")
    "$RUST_BENCH" "$operation" "$count" >"$log"
    mean=$(sed -n 's/.*mean_ns=\([0-9.]*\).*/\1/p' "$log")
    test -n "$mean"
    printf '%s\t%s\tEd301\t%s\t%s\t%s\t%s\n' \
        "$round" "$position" "$operation" "$count" "$mean" \
        "${log#"$OUTPUT/"}" >>"$OUTPUT/raw.tsv"
}
run_control() {
    round=$1
    position=$2
    algorithm=$3
    operation=$4
    count=$5
    sequence=$((sequence + 1))
    log=$OUTPUT/logs/$(printf '%03d-%s-%s.log' \
        "$sequence" "$algorithm" "$operation")
    env LD_LIBRARY_PATH="$OUTPUT/lib" "$C_BENCH" "$operation" \
        "$algorithm" - - - "$count" >"$log"
    mean=$(sed -n 's/.*mean_ns=\([0-9.]*\).*/\1/p' "$log")
    test -n "$mean"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$round" "$position" "$algorithm" "$operation" "$count" \
        "$mean" "${log#"$OUTPUT/"}" >>"$OUTPUT/raw.tsv"
}

for ((round = 1; round <= REPETITIONS; round++)); do
    if (( round % 2 == 1 )); then
        controls=(ED25519 ED448)
    else
        controls=(ED448 ED25519)
    fi
    for algorithm in "${controls[@]}"; do
        run_control "$round" pre "$algorithm" keygen 1000
        run_control "$round" pre "$algorithm" sign 2000
        run_control "$round" pre "$algorithm" verify 1000
    done
    run_rust "$round" target expand 5000
    run_rust "$round" target sign 10000
    run_rust "$round" target verify 3000
    run_rust "$round" target import 3000
done

/usr/bin/python3 -I -B "$ROOT/performance/summarize.py" \
    "$OUTPUT/raw.tsv" >"$OUTPUT/SUMMARY.txt"
printf 'loadavg_after=%s\n' "$(sed -n '1p' /proc/loadavg)" \
    >>"$OUTPUT/RUN_IDENTITY.txt"
cp -- "$ROOT/performance/ed301-bench/src/main.rs" \
    "$ROOT/performance/ed301-bench/Cargo.toml" \
    "$ROOT/performance/ed301-bench/Cargo.lock" \
    "$ROOT/performance/openssl_signature_bench.c" \
    "$ROOT/performance/summarize.py" \
    "$ROOT/scripts/run-performance-receipt.sh" "$OUTPUT/inputs/"
(cd "$OUTPUT" && \
    find . -type f ! -name SHA256SUMS -print0 \
        | sort -z | xargs -0 sha256sum >SHA256SUMS && \
    sha256sum --strict --quiet -c SHA256SUMS)
sh "$ROOT/scripts/require-verified-snapshot.sh"
cat "$OUTPUT/SUMMARY.txt"
printf 'ed301_performance_receipt=PASS output=%s\n' "$OUTPUT"
