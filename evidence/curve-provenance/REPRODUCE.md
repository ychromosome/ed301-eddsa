# Reproduction

Prerequisites for the curve-only checks are Python 3, PARI/GP with SEA data,
and standard POSIX utilities. From the repository root:

```sh
evidence/curve-provenance/run_curve_checks.sh --quick
```

Invoke the executable directly. It starts Bash with a reduced environment and
uses fixed tool paths. The archived order-witness script is accepted only when
run by this wrapper with unoptimized isolated Python and its exact final
marker; direct or `python -O` execution is not evidence.

The quick path verifies all 458 archived files, validates the complete search
transcript, checks the stored ECPP and N-1 certificates with PARI and separate
Python verifiers, proves the curve and twist orders from independent points,
and regenerates and cross-checks the base point.

The full path additionally recomputes the main and twist point counts,
factorizations, group structures, CM data and embedding degrees:

```sh
evidence/curve-provenance/run_curve_checks.sh --full
```

To rerun the complete candidate search, use a disposable copy because the
historical worker writes result files:

```sh
tmp=$(mktemp -d)
cp -a evidence/curve-provenance/archive/. "$tmp/"
find "$tmp/ed301_technischer_abschluss/rohresultate" \
  -name 'search_*_worker_*.txt' -delete
cd "$tmp"
python3 ed301_technischer_abschluss/scripts/search_a_continuous.py \
  --start 0 --maximum 44730 --workers 16 --chunk-size 256
python3 ed301_technischer_abschluss/scripts/search_a_continuous.py \
  --start 44731 --maximum 50687 --workers 16 --chunk-size 256
python3 ed301_technischer_abschluss/scripts/verify_search_transcript.py \
  --expected-first-hit 44730 --require-coverage-through 50687
```

The two ranges are deliberate: the original orchestrator stops assigning new
work after a hit. Ending the first run at 44730 proves minimality; the second
run completes the retained post-hit coverage without changing the predicate.
Recorded timing is not part of the mathematical result.
