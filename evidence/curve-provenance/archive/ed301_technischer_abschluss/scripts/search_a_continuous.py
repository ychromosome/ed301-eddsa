#!/usr/bin/env python3
"""Haelt 16 unabhaengige PARI-Suchworker mit lueckenlosen Bloecken aktiv."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import re
import subprocess
import time


ROOT = Path(__file__).resolve().parents[2]
GP_SCRIPT = ROOT / "ed301_technischer_abschluss" / "scripts" / "search_a_worker.gp"
RAW_DIR = ROOT / "ed301_technischer_abschluss" / "rohresultate"
HIT_RE = re.compile(r"^HIT=(.*)$", re.MULTILINE)


def run_chunk(worker_id: int, start: int, end: int) -> dict[str, object]:
    env = os.environ.copy()
    env.update(
        {
            "ED301_COUNTER_START": str(start),
            "ED301_COUNTER_END": str(end),
            "ED301_WORKER_ID": str(worker_id),
        }
    )
    started = time.monotonic()
    process = subprocess.run(
        ["gp", "-q", "-f", str(GP_SCRIPT)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    elapsed = time.monotonic() - started
    output = process.stdout + process.stderr
    errors = [
        line
        for line in output.splitlines()
        if "***" in line and "Warning:" not in line
    ]
    raw_path = RAW_DIR / f"search_{start}_{end}_worker_{worker_id}.txt"
    return {
        "worker_id": worker_id,
        "start": start,
        "end": end,
        "elapsed_seconds": elapsed,
        "returncode": process.returncode,
        "hits": HIT_RE.findall(output),
        "errors": errors,
        "raw_path": str(raw_path.relative_to(ROOT)),
        "raw_exists": raw_path.is_file(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", type=int, required=True)
    parser.add_argument("--maximum", type=int, default=100_000)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--chunk-size", type=int, default=256)
    args = parser.parse_args()
    if args.start < 0 or args.maximum < args.start:
        parser.error("ungueltiger Suchbereich")
    if args.workers < 1 or args.chunk_size < 1:
        parser.error("workers und chunk-size muessen positiv sein")

    log_path = RAW_DIR / "search_continuous.jsonl"
    summary_path = RAW_DIR / "search_continuous_summary.json"
    next_start = args.start
    hits: list[dict[str, object]] = []
    completed_ranges: list[tuple[int, int]] = []
    fatal_errors: list[dict[str, object]] = []
    assigned_through = args.start - 1

    def next_job(worker_id: int) -> tuple[int, int, int] | None:
        nonlocal next_start, assigned_through
        if next_start > args.maximum:
            return None
        start = next_start
        end = min(start + args.chunk_size - 1, args.maximum)
        next_start = end + 1
        assigned_through = end
        return worker_id, start, end

    with log_path.open("w", encoding="utf-8") as log_file:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            pending: dict[concurrent.futures.Future[dict[str, object]], tuple[int, int, int]] = {}
            for worker_id in range(args.workers):
                job = next_job(worker_id)
                if job is None:
                    break
                _, start, end = job
                pending[pool.submit(run_chunk, worker_id, start, end)] = job

            stop_assigning = False
            while pending:
                done, _ = concurrent.futures.wait(
                    pending, return_when=concurrent.futures.FIRST_COMPLETED
                )
                freed_workers: list[int] = []
                for future in done:
                    worker_id, start, end = pending.pop(future)
                    result = future.result()
                    completed_ranges.append((start, end))
                    log_file.write(json.dumps(result, sort_keys=True) + "\n")
                    log_file.flush()
                    if (
                        result["returncode"] != 0
                        or result["errors"]
                        or not result["raw_exists"]
                    ):
                        fatal_errors.append(result)
                        stop_assigning = True
                    for hit in result["hits"]:
                        hits.append(
                            {
                                "worker_id": worker_id,
                                "range": [start, end],
                                "candidate": hit,
                            }
                        )
                    if result["hits"]:
                        stop_assigning = True
                    freed_workers.append(worker_id)
                    print(
                        "CHUNK"
                        f" worker={worker_id} range={start}-{end}"
                        f" seconds={result['elapsed_seconds']:.3f}"
                        f" hits={len(result['hits'])}"
                        f" assigned_through={assigned_through}",
                        flush=True,
                    )

                if not stop_assigning:
                    for worker_id in freed_workers:
                        job = next_job(worker_id)
                        if job is None:
                            break
                        _, start, end = job
                        pending[pool.submit(run_chunk, worker_id, start, end)] = job

    completed_ranges.sort()
    contiguous_through = args.start - 1
    for start, end in completed_ranges:
        if start != contiguous_through + 1:
            break
        contiguous_through = end

    summary = {
        "start": args.start,
        "maximum": args.maximum,
        "workers": args.workers,
        "chunk_size": args.chunk_size,
        "assigned_through": assigned_through,
        "contiguous_through": contiguous_through,
        "completed_chunks": len(completed_ranges),
        "hits": hits,
        "fatal_errors": fatal_errors,
    }
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("SUMMARY=" + json.dumps(summary, sort_keys=True), flush=True)
    return 1 if fatal_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
