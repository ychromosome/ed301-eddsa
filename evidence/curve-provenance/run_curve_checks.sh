#!/usr/bin/env -S -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C /usr/bin/bash
set -euo pipefail

PATH=/usr/bin:/bin
HOME=/nonexistent
LC_ALL=C
export PATH HOME LC_ALL

ROOT=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")" && /bin/pwd -P)
ARCHIVE=$ROOT/archive
PACKAGE=$ARCHIVE/ed301_technischer_abschluss
MODE=${1:---quick}

case "$MODE" in
    --quick|--full) ;;
    *) printf 'usage: %s [--quick|--full]\n' "$0" >&2; exit 2 ;;
esac

for tool in /usr/bin/grep /usr/bin/gp /usr/bin/mktemp /usr/bin/python3 \
        /usr/bin/sha256sum /usr/bin/tee; do
    test -x "$tool" || {
        printf 'missing required tool: %s\n' "$tool" >&2
        exit 127
    }
done

tmp_files=()
cleanup() {
    if ((${#tmp_files[@]} != 0)); then
        /usr/bin/rm -f -- "${tmp_files[@]}"
    fi
}
trap cleanup EXIT HUP INT TERM

run_gp_expect() {
    local script=$1 marker=$2 output

    output=$(/usr/bin/mktemp)
    tmp_files+=("$output")
    (cd "$ARCHIVE" && /usr/bin/gp -q -f "$script") \
        | /usr/bin/tee "$output"
    /usr/bin/grep -Fqx -- "$marker" "$output"
}

run_python_expect() {
    local script=$1 marker=$2 output
    shift 2
    output=$(/usr/bin/mktemp)
    tmp_files+=("$output")
    /usr/bin/python3 -I -B "$script" "$@" | /usr/bin/tee "$output"
    /usr/bin/grep -Fqx -- "$marker" "$output"
}

/usr/bin/python3 -I -B -c \
    'import sys; sys.exit(1) if sys.flags.optimize else None'
(cd "$ROOT" && /usr/bin/sha256sum --strict --quiet \
    -c ORIGINAL_MANIFEST.sha256)
(cd "$PACKAGE" && /usr/bin/sha256sum --strict --quiet -c SHA256SUMS)
/usr/bin/python3 -I -B "$PACKAGE/scripts/verify_search_transcript.py" --json

if [[ $MODE == --full ]]; then
    run_gp_expect \
        ed301_technischer_abschluss/scripts/audit_c44730_full_reproducibility.gp \
        audit_pass=1
fi

run_gp_expect \
    ed301_technischer_abschluss/scripts/audit_c44730_prime_certificates.gp \
    certificate_audit_pass=1

/usr/bin/python3 -I -B "$PACKAGE/scripts/verify_c44730_ecpp_independent.py" \
    "$PACKAGE/zertifikate/p_ecpp_internal.pari"
/usr/bin/python3 -I -B "$PACKAGE/scripts/verify_c44730_ecpp_independent.py" \
    "$PACKAGE/zertifikate/c44730_q_ecpp_internal.pari"
/usr/bin/python3 -I -B "$PACKAGE/scripts/verify_c44730_ecpp_independent.py" \
    "$PACKAGE/zertifikate/c44730_q_twist_ecpp_internal.pari"
/usr/bin/python3 -I -B "$PACKAGE/scripts/verify_c44730_nminus1_bls_independent.py" \
    "$PACKAGE/zertifikate/c44730_q_nminus1_bls_internal.pari"
/usr/bin/python3 -I -B "$PACKAGE/scripts/verify_c44730_nminus1_bls_independent.py" \
    "$PACKAGE/zertifikate/c44730_q_twist_nminus1_bls_internal.pari"
run_python_expect \
    "$PACKAGE/scripts/audit_candidate_c44730_order_witness.py" \
    independent_order_verification=pass
/usr/bin/python3 -I -B "$PACKAGE/scripts/derive_c44730_basepoint.py"
run_gp_expect \
    ed301_technischer_abschluss/scripts/verify_c44730_basepoint_pari.gp \
    pari_basepoint_crosscheck_pass=1

printf 'curve_provenance_checks=PASS mode=%s\n' "$MODE"
