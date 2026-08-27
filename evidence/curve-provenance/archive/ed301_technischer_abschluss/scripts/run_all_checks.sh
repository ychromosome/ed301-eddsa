#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
WORKSPACE_ROOT="$(cd -- "${PACKAGE_ROOT}/.." && pwd)"

mode=full
if [[ ${1-} == "--quick" ]]; then
    mode=quick
    shift
elif [[ ${1-} == "--full" ]]; then
    shift
fi
if (( $# != 0 )); then
    printf 'Verwendung: %s [--quick|--full]\n' "$0" >&2
    exit 2
fi

for command_name in python3 gp node npm sha256sum grep tee mktemp; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'Fehlendes Programm: %s\n' "$command_name" >&2
        exit 127
    fi
done

tmp_files=()
cleanup() {
    if (( ${#tmp_files[@]} )); then
        rm -f -- "${tmp_files[@]}"
    fi
}
trap cleanup EXIT

run_gp_expect() {
    local script_rel=$1
    local marker=$2
    local tmp
    tmp=$(mktemp)
    tmp_files+=("$tmp")
    (
        cd -- "$WORKSPACE_ROOT"
        gp -q -f "$script_rel"
    ) | tee "$tmp"
    if ! grep -Fqx -- "$marker" "$tmp"; then
        printf 'PARI-Endmarke fehlt: %s (%s)\n' "$marker" "$script_rel" >&2
        exit 1
    fi
}

cd -- "$PACKAGE_ROOT"

printf '[ED301] Modus: %s\n' "$mode"
printf '[ED301] Python: %s\n' "$(python3 --version 2>&1)"
printf '[ED301] Node: %s\n' "$(node --version)"

sha256sum --quiet -c SOURCE_SHA256SUMS
if [[ -f SHA256SUMS ]]; then
    sha256sum --quiet -c SHA256SUMS
fi

python3 scripts/verify_search_transcript.py

if [[ $mode == full ]]; then
    run_gp_expect \
        ed301_technischer_abschluss/scripts/audit_c44730_full_reproducibility.gp \
        audit_pass=1
fi

run_gp_expect \
    ed301_technischer_abschluss/scripts/audit_c44730_prime_certificates.gp \
    certificate_audit_pass=1

python3 scripts/verify_c44730_ecpp_independent.py \
    zertifikate/p_ecpp_internal.pari
python3 scripts/verify_c44730_ecpp_independent.py \
    zertifikate/c44730_q_ecpp_internal.pari
python3 scripts/verify_c44730_ecpp_independent.py \
    zertifikate/c44730_q_twist_ecpp_internal.pari
python3 scripts/verify_c44730_nminus1_bls_independent.py \
    zertifikate/c44730_q_nminus1_bls_internal.pari
python3 scripts/verify_c44730_nminus1_bls_independent.py \
    zertifikate/c44730_q_twist_nminus1_bls_internal.pari

python3 scripts/audit_candidate_c44730_order_witness.py
python3 scripts/derive_c44730_basepoint.py
run_gp_expect \
    ed301_technischer_abschluss/scripts/verify_c44730_basepoint_pari.gp \
    pari_basepoint_crosscheck_pass=1

python3 -m unittest discover -s tests -v

(
    cd -- gegenpruefung
    npm test
    npm run vectors
    node --check ed301.js
    node --check test_independent.js
    node --check run_vectors.js
)

(
    cd -- gegenpruefung/x301
    npm test
    npm run vectors
    node --check x301.js
    node --check test_independent.js
    node --check run_vectors.js
)

printf '[ED301] ALL_CHECKS_PASS mode=%s\n' "$mode"
