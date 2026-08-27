#!/usr/bin/env python3
"""Read-only verifier for the persisted ED301 ``a``-search transcript.

Only Python's standard library is used.  The verifier does not rerun SEA or
primality tests; it proves what the stored worker transcript records: valid
completed ranges, gap-free coverage, and the position and identity of every
recorded hit.  It intentionally treats overlapping historical campaigns as
duplicate evidence rather than adding their tested counters twice.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import pathlib
import re
import sys
from dataclasses import dataclass
from typing import Iterable, Sequence


ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_RAW_DIRECTORY = ROOT / "ed301_technischer_abschluss" / "rohresultate"
FILE_GLOB = "search_*_worker_*.txt"
FILE_RE = re.compile(r"search_(\d+)_(\d+)_worker_(\d+)\.txt\Z")
INTEGER_RE = re.compile(r"-?(?:0|[1-9]\d*)\Z")
EXPECTED_KEYS = {
    "worker_id",
    "counter_start",
    "counter_end",
    "tested",
    "elapsed_ms",
    "hits",
}

P = (1 << 301) - (1 << 99) + 947
D = 301
HIT_FIELD_NAMES = (
    "c",
    "s",
    "a",
    "montgomery_A",
    "montgomery_B",
    "curve_order_N",
    "subgroup_order_q",
    "twist_order_N",
    "twist_subgroup_order_q",
    "frobenius_trace",
    "fundamental_discriminant",
)


class TranscriptError(ValueError):
    """A worker file or the combined transcript is not self-consistent."""


@dataclass(frozen=True)
class Hit:
    values: tuple[int, ...]

    @property
    def counter(self) -> int:
        return self.values[0]

    @property
    def identity(self) -> str:
        canonical = ",".join(str(value) for value in self.values).encode("ascii")
        return hashlib.sha256(canonical).hexdigest()

    def named_decimal_values(self) -> dict[str, str]:
        return {
            name: str(value) for name, value in zip(HIT_FIELD_NAMES, self.values)
        }


@dataclass(frozen=True)
class Block:
    path: pathlib.Path
    worker_id: int
    start: int
    end: int
    tested: int
    elapsed_ms: int
    hits: tuple[Hit, ...]


def _parse_integer(text: str, *, field: str, path: pathlib.Path) -> int:
    if not INTEGER_RE.fullmatch(text):
        raise TranscriptError(f"{path.name}: {field} is not a canonical decimal integer")
    return int(text, 10)


def _validate_hit(values: object, *, path: pathlib.Path, start: int, end: int) -> Hit:
    if not isinstance(values, list) or len(values) != len(HIT_FIELD_NAMES):
        raise TranscriptError(
            f"{path.name}: every hit must be a {len(HIT_FIELD_NAMES)}-integer list"
        )
    if any(type(value) is not int for value in values):
        raise TranscriptError(f"{path.name}: hit fields must all be integers")
    hit = Hit(tuple(values))
    c, s, a, montgomery_a, montgomery_b, n, q, nt, qt, trace, discriminant = hit.values
    if not start <= c <= end:
        raise TranscriptError(f"{path.name}: hit c={c} lies outside its worker range")
    if s != 947 + c:
        raise TranscriptError(f"{path.name}: hit c={c} has inconsistent s")
    if a != pow(s, 2, P):
        raise TranscriptError(f"{path.name}: hit c={c} has inconsistent a")
    denominator = (a - D) % P
    if denominator == 0:
        raise TranscriptError(f"{path.name}: hit c={c} has a=d")
    inverse = pow(denominator, P - 2, P)
    if montgomery_a != (2 * (a + D) * inverse) % P:
        raise TranscriptError(f"{path.name}: hit c={c} has inconsistent Montgomery A")
    if montgomery_b != (4 * inverse) % P:
        raise TranscriptError(f"{path.name}: hit c={c} has inconsistent Montgomery B")
    if q <= 0 or qt <= 0 or n != 4 * q or nt != 4 * qt:
        raise TranscriptError(f"{path.name}: hit c={c} has inconsistent 4*q orders")
    if n + nt != 2 * P + 2:
        raise TranscriptError(f"{path.name}: hit c={c} violates curve/twist order sum")
    if trace != P + 1 - n:
        raise TranscriptError(f"{path.name}: hit c={c} has inconsistent trace")
    frobenius_discriminant = trace * trace - 4 * P
    if discriminant >= 0 or frobenius_discriminant >= 0:
        raise TranscriptError(f"{path.name}: hit c={c} has nonnegative discriminant")
    if frobenius_discriminant % discriminant != 0:
        raise TranscriptError(f"{path.name}: hit c={c} has unrelated core discriminant")
    conductor_square = frobenius_discriminant // discriminant
    conductor = math.isqrt(conductor_square)
    if conductor <= 0 or conductor * conductor != conductor_square:
        raise TranscriptError(f"{path.name}: hit c={c} has nonsquare conductor quotient")
    if discriminant % 4 not in (0, 1):
        raise TranscriptError(f"{path.name}: hit c={c} is not a quadratic discriminant")
    return hit


def parse_block(path: pathlib.Path) -> Block:
    """Parse and validate one worker result, including filename metadata."""

    match = FILE_RE.fullmatch(path.name)
    if match is None:
        raise TranscriptError(f"{path.name}: filename does not match the worker convention")
    filename_start, filename_end, filename_worker = map(int, match.groups())
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise TranscriptError(f"{path.name}: cannot read UTF-8 worker result: {exc}") from exc
    if "***" in text or re.search(r"(?im)^\s*(?:error|fatal)(?:\b|:)", text):
        raise TranscriptError(f"{path.name}: stored error/fatal diagnostic found")

    fields: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        if "=" not in line:
            raise TranscriptError(f"{path.name}:{line_number}: malformed line")
        key, value = (part.strip() for part in line.split("=", 1))
        if key not in EXPECTED_KEYS:
            raise TranscriptError(f"{path.name}:{line_number}: unknown field {key!r}")
        if key in fields:
            raise TranscriptError(f"{path.name}:{line_number}: duplicate field {key!r}")
        fields[key] = value
    missing = EXPECTED_KEYS - fields.keys()
    if missing:
        raise TranscriptError(f"{path.name}: missing fields {sorted(missing)}")

    worker = _parse_integer(fields["worker_id"], field="worker_id", path=path)
    start = _parse_integer(fields["counter_start"], field="counter_start", path=path)
    end = _parse_integer(fields["counter_end"], field="counter_end", path=path)
    tested = _parse_integer(fields["tested"], field="tested", path=path)
    elapsed = _parse_integer(fields["elapsed_ms"], field="elapsed_ms", path=path)
    if worker < 0 or start < 0 or end < start or tested < 1 or elapsed < 0:
        raise TranscriptError(f"{path.name}: invalid negative or reversed metadata")
    if (start, end, worker) != (filename_start, filename_end, filename_worker):
        raise TranscriptError(f"{path.name}: filename and embedded range/worker disagree")
    if tested != end - start + 1:
        raise TranscriptError(
            f"{path.name}: tested={tested}, expected {end - start + 1}"
        )

    try:
        raw_hits = ast.literal_eval(fields["hits"])
    except (SyntaxError, ValueError) as exc:
        raise TranscriptError(f"{path.name}: hits is not a literal integer-list") from exc
    if not isinstance(raw_hits, list):
        raise TranscriptError(f"{path.name}: hits must be a list")
    hits = tuple(
        _validate_hit(item, path=path, start=start, end=end) for item in raw_hits
    )
    counters = [hit.counter for hit in hits]
    if len(counters) != len(set(counters)):
        raise TranscriptError(f"{path.name}: duplicate hit counter within one block")
    return Block(path, worker, start, end, tested, elapsed, hits)


def _merge_ranges(ranges: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _relative_or_absolute(path: pathlib.Path, base: pathlib.Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def analyze_blocks(
    blocks: Sequence[Block],
    *,
    expected_first_hit: int,
    require_coverage_through: int,
    display_base: pathlib.Path | None = None,
) -> dict[str, object]:
    """Combine successful blocks and prove coverage/first-hit properties."""

    if not blocks:
        raise TranscriptError("no worker result files found")
    if expected_first_hit < 0 or require_coverage_through < expected_first_hit:
        raise TranscriptError("invalid requested first-hit/coverage bounds")
    base = display_base or pathlib.Path.cwd()

    # Per-counter observations make overlapping historical campaigns explicit.
    observations: dict[int, list[tuple[Block, bool]]] = {}
    for block in blocks:
        hit_counters = {hit.counter for hit in block.hits}
        for counter in range(block.start, block.end + 1):
            observations.setdefault(counter, []).append((block, counter in hit_counters))
    conflicts = []
    for counter, counter_observations in observations.items():
        states = {state for _, state in counter_observations}
        if len(states) > 1:
            files = sorted(item.path.name for item, _ in counter_observations)
            conflicts.append(f"c={counter}: contradictory HIT states in {files}")
    if conflicts:
        raise TranscriptError("overlapping campaigns conflict: " + "; ".join(conflicts))

    merged = _merge_ranges((block.start, block.end) for block in blocks)
    if not merged or merged[0][0] != 0:
        raise TranscriptError("successful coverage does not start at c=0")
    contiguous_through = merged[0][1]
    if contiguous_through < require_coverage_through:
        raise TranscriptError(
            f"coverage stops at c={contiguous_through}, required {require_coverage_through}"
        )

    occurrences: list[tuple[Block, Hit]] = [
        (block, hit) for block in blocks for hit in block.hits
    ]
    if not occurrences:
        raise TranscriptError("transcript contains no HIT")
    first_recorded = min(hit.counter for _, hit in occurrences)
    if first_recorded != expected_first_hit:
        raise TranscriptError(
            f"first recorded HIT is c={first_recorded}, expected c={expected_first_hit}"
        )
    if expected_first_hit not in observations:
        raise TranscriptError(f"c={expected_first_hit} is not covered")

    by_counter: dict[int, set[tuple[int, ...]]] = {}
    by_identity: dict[tuple[int, ...], list[Block]] = {}
    for block, hit in occurrences:
        by_counter.setdefault(hit.counter, set()).add(hit.values)
        by_identity.setdefault(hit.values, []).append(block)
    ambiguous = {counter: values for counter, values in by_counter.items() if len(values) > 1}
    if ambiguous:
        raise TranscriptError(f"same hit counter has conflicting candidate identities: {ambiguous}")

    hit_reports = []
    for values, hit_blocks in sorted(by_identity.items(), key=lambda item: item[0]):
        hit = Hit(values)
        hit_reports.append(
            {
                "counter_decimal": str(hit.counter),
                "candidate_identity_sha256": hit.identity,
                "candidate_fields_decimal": hit.named_decimal_values(),
                "occurrence_count": len(hit_blocks),
                "occurrences": [
                    {
                        "file": _relative_or_absolute(block.path, base),
                        "worker_id": block.worker_id,
                        "range": [block.start, block.end],
                    }
                    for block in sorted(hit_blocks, key=lambda item: item.path.name)
                ],
            }
        )

    declared_tests = sum(block.tested for block in blocks)
    unique_counters = len(observations)
    duplicate_claims = declared_tests - unique_counters
    multiply_covered = sum(len(items) > 1 for items in observations.values())
    return {
        "status": "PASS",
        "worker_file_count": len(blocks),
        "worker_ids": sorted({block.worker_id for block in blocks}),
        "declared_test_count_including_historical_duplicates": declared_tests,
        "unique_counter_count": unique_counters,
        "duplicate_coverage_claims": duplicate_claims,
        "multiply_covered_counter_count": multiply_covered,
        "merged_successful_ranges": [[start, end] for start, end in merged],
        "contiguous_coverage_start": 0,
        "contiguous_coverage_through": contiguous_through,
        "required_coverage_through": require_coverage_through,
        "expected_first_hit": expected_first_hit,
        "first_recorded_hit": first_recorded,
        "no_hit_before_expected_first": all(
            hit.counter >= expected_first_hit for _, hit in occurrences
        ),
        "hit_occurrence_count": len(occurrences),
        "unique_hit_identity_count": len(by_identity),
        "hits": hit_reports,
    }


def verify_directory(
    directory: pathlib.Path,
    *,
    expected_first_hit: int = 44730,
    require_coverage_through: int = 50687,
) -> dict[str, object]:
    """Parse every matching file and return a JSON-serializable proof report."""

    directory = directory.resolve()
    paths = sorted(directory.glob(FILE_GLOB))
    if not paths:
        raise TranscriptError(f"{directory}: no {FILE_GLOB} files found")
    blocks: list[Block] = []
    errors: list[str] = []
    for path in paths:
        try:
            blocks.append(parse_block(path))
        except TranscriptError as exc:
            errors.append(str(exc))
    if errors:
        raise TranscriptError(
            f"{len(errors)} invalid worker result(s):\n- " + "\n- ".join(errors)
        )
    return analyze_blocks(
        blocks,
        expected_first_hit=expected_first_hit,
        require_coverage_through=require_coverage_through,
        display_base=directory,
    )


def _print_human(report: dict[str, object]) -> None:
    print("ED301 SEARCH TRANSCRIPT: PASS")
    print(
        "blocks={worker_file_count} declared_tests={declared_test_count_including_historical_duplicates} "
        "unique_counters={unique_counter_count} duplicate_claims={duplicate_coverage_claims}".format(
            **report
        )
    )
    print(
        "coverage=0..{contiguous_coverage_through} required_through={required_coverage_through} "
        "first_hit={first_recorded_hit}".format(**report)
    )
    print(
        "hit_occurrences={hit_occurrence_count} unique_hit_identities={unique_hit_identity_count}".format(
            **report
        )
    )
    for hit in report["hits"]:  # type: ignore[union-attr]
        fields = hit["candidate_fields_decimal"]
        print(
            f"HIT c={hit['counter_decimal']} identity_sha256={hit['candidate_identity_sha256']} "
            f"occurrences={hit['occurrence_count']}"
        )
        print("candidate=" + json.dumps(fields, sort_keys=True, separators=(",", ":")))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--raw-directory", type=pathlib.Path, default=DEFAULT_RAW_DIRECTORY
    )
    parser.add_argument("--expected-first-hit", type=int, default=44730)
    parser.add_argument("--require-coverage-through", type=int, default=50687)
    parser.add_argument("--json", action="store_true", help="emit the proof report as JSON")
    args = parser.parse_args(argv)
    try:
        report = verify_directory(
            args.raw_directory,
            expected_first_hit=args.expected_first_hit,
            require_coverage_through=args.require_coverage_through,
        )
    except TranscriptError as exc:
        print(f"ED301 SEARCH TRANSCRIPT: FAIL\n{exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
