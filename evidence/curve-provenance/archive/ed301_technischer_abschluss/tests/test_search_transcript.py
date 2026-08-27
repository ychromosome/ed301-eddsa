#!/usr/bin/env python3
"""Tests for the read-only ED301 search-transcript verifier."""

from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import verify_search_transcript as transcript  # noqa: E402


def candidate(counter: int) -> list[int]:
    s = 947 + counter
    a = pow(s, 2, transcript.P)
    inverse = pow((a - transcript.D) % transcript.P, transcript.P - 2, transcript.P)
    montgomery_a = (2 * (a + transcript.D) * inverse) % transcript.P
    montgomery_b = (4 * inverse) % transcript.P
    trace = 4
    n = transcript.P + 1 - trace
    q = n // 4
    nt = 2 * transcript.P + 2 - n
    qt = nt // 4
    discriminant = trace * trace - 4 * transcript.P
    return [
        counter,
        s,
        a,
        montgomery_a,
        montgomery_b,
        n,
        q,
        nt,
        qt,
        trace,
        discriminant,
    ]


def write_block(
    directory: pathlib.Path,
    start: int,
    end: int,
    worker: int,
    hits: list[list[int]],
    *,
    tested: int | None = None,
) -> pathlib.Path:
    if tested is None:
        tested = end - start + 1
    path = directory / f"search_{start}_{end}_worker_{worker}.txt"
    path.write_text(
        "\n".join(
            (
                f"worker_id={worker}",
                f"counter_start={start}",
                f"counter_end={end}",
                f"tested={tested}",
                "elapsed_ms=1",
                f"hits={hits!r}",
                "",
            )
        ),
        encoding="utf-8",
    )
    return path


class MiniTranscriptTests(unittest.TestCase):
    def test_gap_free_first_hit_and_historical_duplicate(self):
        with tempfile.TemporaryDirectory() as name:
            directory = pathlib.Path(name)
            write_block(directory, 0, 2, 0, [])
            write_block(directory, 3, 5, 1, [candidate(3)])
            # A prior one-candidate campaign overlaps c=0 consistently.
            write_block(directory, 0, 0, 7, [])
            report = transcript.verify_directory(
                directory, expected_first_hit=3, require_coverage_through=5
            )
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["worker_file_count"], 3)
            self.assertEqual(report["declared_test_count_including_historical_duplicates"], 7)
            self.assertEqual(report["unique_counter_count"], 6)
            self.assertEqual(report["duplicate_coverage_claims"], 1)
            self.assertEqual(report["multiply_covered_counter_count"], 1)
            self.assertEqual(report["contiguous_coverage_through"], 5)
            self.assertEqual(report["first_recorded_hit"], 3)
            self.assertTrue(report["no_hit_before_expected_first"])
            self.assertEqual(report["hit_occurrence_count"], 1)
            self.assertEqual(report["unique_hit_identity_count"], 1)

    def test_tested_count_and_filename_metadata_are_enforced(self):
        with tempfile.TemporaryDirectory() as name:
            directory = pathlib.Path(name)
            bad_count = write_block(directory, 0, 2, 0, [], tested=2)
            with self.assertRaisesRegex(transcript.TranscriptError, "tested=2"):
                transcript.parse_block(bad_count)

            bad_count.unlink()
            path = write_block(directory, 0, 2, 0, [])
            path.write_text(
                path.read_text(encoding="utf-8").replace("worker_id=0", "worker_id=1"),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(transcript.TranscriptError, "disagree"):
                transcript.parse_block(path)

    def test_overlap_with_conflicting_hit_state_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            directory = pathlib.Path(name)
            write_block(directory, 0, 3, 0, [candidate(3)])
            write_block(directory, 3, 5, 1, [])
            blocks = [transcript.parse_block(path) for path in sorted(directory.glob("*.txt"))]
            with self.assertRaisesRegex(transcript.TranscriptError, "campaigns conflict"):
                transcript.analyze_blocks(
                    blocks, expected_first_hit=3, require_coverage_through=5
                )

    def test_gap_and_wrong_first_hit_are_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            directory = pathlib.Path(name)
            write_block(directory, 0, 1, 0, [])
            write_block(directory, 3, 4, 1, [candidate(3)])
            blocks = [transcript.parse_block(path) for path in sorted(directory.glob("*.txt"))]
            with self.assertRaisesRegex(transcript.TranscriptError, "coverage stops"):
                transcript.analyze_blocks(
                    blocks, expected_first_hit=3, require_coverage_through=4
                )

            write_block(directory, 2, 2, 2, [])
            blocks = [transcript.parse_block(path) for path in sorted(directory.glob("*.txt"))]
            with self.assertRaisesRegex(transcript.TranscriptError, "expected c=4"):
                transcript.analyze_blocks(
                    blocks, expected_first_hit=4, require_coverage_through=4
                )


class RealTranscriptTests(unittest.TestCase):
    def test_persisted_search_is_gap_free_and_first_hit_is_44730(self):
        report = transcript.verify_directory(transcript.DEFAULT_RAW_DIRECTORY)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["worker_file_count"], 355)
        self.assertEqual(report["declared_test_count_including_historical_duplicates"], 50689)
        self.assertEqual(report["unique_counter_count"], 50688)
        self.assertEqual(report["duplicate_coverage_claims"], 1)
        self.assertEqual(report["multiply_covered_counter_count"], 1)
        self.assertEqual(report["merged_successful_ranges"], [[0, 50687]])
        self.assertEqual(report["contiguous_coverage_through"], 50687)
        self.assertEqual(report["first_recorded_hit"], 44730)
        self.assertTrue(report["no_hit_before_expected_first"])
        self.assertEqual(report["hit_occurrence_count"], 1)
        self.assertEqual(report["unique_hit_identity_count"], 1)
        self.assertEqual(report["hits"][0]["counter_decimal"], "44730")
        fields = report["hits"][0]["candidate_fields_decimal"]
        self.assertEqual(fields["s"], "45677")
        self.assertEqual(fields["a"], "2086388329")


if __name__ == "__main__":
    unittest.main(verbosity=2)
