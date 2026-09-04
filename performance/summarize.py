#!/usr/bin/python3

import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} RAW_TSV")
    source = Path(sys.argv[1])
    values: dict[tuple[str, str], list[float]] = defaultdict(list)
    with source.open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            values[(row["algorithm"], row["operation"])].append(
                float(row["mean_ns"])
            )

    print("algorithm\toperation\tsamples\tmedian_ns")
    medians: dict[tuple[str, str], float] = {}
    for key in sorted(values):
        medians[key] = statistics.median(values[key])
        print(f"{key[0]}\t{key[1]}\t{len(values[key])}\t{medians[key]:.3f}")
    for operation, control in (
        ("expand", "keygen"),
        ("sign", "sign"),
        ("verify", "verify"),
    ):
        ed301 = medians.get(("Ed301", operation))
        ed25519 = medians.get(("ED25519", control))
        ed448 = medians.get(("ED448", control))
        if ed301 is None or ed25519 is None or ed448 is None:
            return 1
        print(
            f"ratio\t{operation}\tEd301/Ed25519={ed301 / ed25519:.6f}"
            f"\tEd301/Ed448={ed301 / ed448:.6f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
