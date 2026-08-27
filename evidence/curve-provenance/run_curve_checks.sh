#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
ARCHIVE=$ROOT/archive
PACKAGE=$ARCHIVE/ed301_technischer_abschluss
MODE=${1:---quick}

case "$MODE" in
    --quick|--full) ;;
    *) printf 'usage: %s [--quick|--full]\n' "$0" >&2; exit 2 ;;
esac

for tool in grep gp mktemp python3 sha256sum tee; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing required tool: %s\n' "$tool" >&2
        exit 127
    }
done

tmp_files=()
cleanup() {
    if ((${#tmp_files[@]} != 0)); then
        rm -f -- "${tmp_files[@]}"
    fi
}
trap cleanup EXIT HUP INT TERM

run_gp_expect() {
    local script=$1 marker=$2 output

    output=$(mktemp)
    tmp_files+=("$output")
    (cd "$ARCHIVE" && gp -q -f "$script") | tee "$output"
    grep -Fqx -- "$marker" "$output"
}

(cd "$ROOT" && sha256sum --strict --quiet -c ORIGINAL_MANIFEST.sha256)
(cd "$PACKAGE" && sha256sum --strict --quiet -c SHA256SUMS)
python3 "$PACKAGE/scripts/verify_search_transcript.py" --json

if [[ $MODE == --full ]]; then
    run_gp_expect \
        ed301_technischer_abschluss/scripts/audit_c44730_full_reproducibility.gp \
        audit_pass=1
fi

run_gp_expect \
    ed301_technischer_abschluss/scripts/audit_c44730_prime_certificates.gp \
    certificate_audit_pass=1

python3 "$PACKAGE/scripts/verify_c44730_ecpp_independent.py" \
    "$PACKAGE/zertifikate/p_ecpp_internal.pari"
python3 "$PACKAGE/scripts/verify_c44730_ecpp_independent.py" \
    "$PACKAGE/zertifikate/c44730_q_ecpp_internal.pari"
python3 "$PACKAGE/scripts/verify_c44730_ecpp_independent.py" \
    "$PACKAGE/zertifikate/c44730_q_twist_ecpp_internal.pari"
python3 "$PACKAGE/scripts/verify_c44730_nminus1_bls_independent.py" \
    "$PACKAGE/zertifikate/c44730_q_nminus1_bls_internal.pari"
python3 "$PACKAGE/scripts/verify_c44730_nminus1_bls_independent.py" \
    "$PACKAGE/zertifikate/c44730_q_twist_nminus1_bls_internal.pari"
python3 "$PACKAGE/scripts/audit_candidate_c44730_order_witness.py"
python3 "$PACKAGE/scripts/derive_c44730_basepoint.py"
run_gp_expect \
    ed301_technischer_abschluss/scripts/verify_c44730_basepoint_pari.gp \
    pari_basepoint_crosscheck_pass=1

printf 'curve_provenance_checks=PASS mode=%s\n' "$MODE"
