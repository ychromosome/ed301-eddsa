#!/usr/bin/env python3
"""Materialize deterministic Rust/Python differential vectors."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise RuntimeError(message)


def load_module(path: Path, name: str):
    resolved = path.resolve(strict=True)
    spec = importlib.util.spec_from_file_location(name, resolved)
    if spec is None or spec.loader is None:
        fail(f"cannot load {resolved}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if Path(module.__file__).resolve(strict=True) != resolved:
        fail(f"module identity mismatch for {resolved}")
    return module


def flip(value: bytes, offset: int, mask: int) -> bytes:
    output = bytearray(value)
    output[offset] ^= mask
    return bytes(output)


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: materialize_vectors.py <repository> <output.json>")

    repository = Path(sys.argv[1]).resolve(strict=True)
    output_path = Path(sys.argv[2]).resolve()
    local_root = Path(__file__).resolve(strict=True).parent
    adapter = load_module(local_root / "oracle_adapter.py", "ed301_blind_adapter")
    comparison_path = (
        repository / "provider-tests" / "oracle" / "ed301_eddsa" / "reference.py"
    )
    comparison = load_module(comparison_path, "ed301_existing_reference")

    seed_labels = [f"case-{index}".encode("ascii") for index in range(8)]
    messages = [
        b"",
        b"\x00",
        bytes(range(32)),
        hashlib.shake_256(b"blind-message-137").digest(137),
        bytes(range(256)),
        (b"Ed301-blind-differential:" * 21)[:511],
        hashlib.shake_256(b"blind-message-1024").digest(1024),
        hashlib.shake_256(b"blind-message-4096").digest(4096),
    ]

    cases = []
    for index, (label, message) in enumerate(zip(seed_labels, messages, strict=True)):
        seed = hashlib.shake_256(b"Ed301 blind differential seed:" + label).digest(38)
        blind_public = adapter.derive_public_key(seed)
        blind_signature = adapter.sign(seed, message)
        comparison_public = comparison.public_from_seed(seed)
        comparison_signature = comparison.sign(seed, message)
        if blind_public != comparison_public:
            fail(f"public-key oracle disagreement in case {index}")
        if blind_signature != comparison_signature:
            fail(f"signature oracle disagreement in case {index}")
        if not adapter.verify(blind_public, message, blind_signature):
            fail(f"blind oracle rejected case {index}")
        if not comparison.verify(blind_public, message, blind_signature):
            fail(f"comparison oracle rejected case {index}")
        if adapter.sign(seed, message) != blind_signature:
            fail(f"blind oracle is nondeterministic in case {index}")
        cases.append(
            {
                "id": f"blind-differential-{index}",
                "message_hex": message.hex(),
                "public_key_hex": blind_public.hex(),
                "seed_hex": seed.hex(),
                "signature_hex": blind_signature.hex(),
            }
        )

    first = cases[0]
    second = cases[1]
    public_key = bytes.fromhex(first["public_key_hex"])
    message = bytes.fromhex(first["message_hex"])
    signature = bytes.fromhex(first["signature_hex"])
    other_public = bytes.fromhex(second["public_key_hex"])
    other_signature = bytes.fromhex(second["signature_hex"])
    identity = b"\x01" + b"\x00" * 37
    order = comparison.L.to_bytes(38, "little")
    modulus = comparison.P.to_bytes(38, "little")

    verification_inputs = [
        ("valid-control", public_key, message, signature),
        ("message-appended", public_key, message + b"\x00", signature),
        ("commitment-bit-flip", public_key, message, flip(signature, 0, 1)),
        ("response-bit-flip", public_key, message, flip(signature, 38, 1)),
        ("signature-short", public_key, message, signature[:-1]),
        ("signature-long", public_key, message, signature + b"\x00"),
        ("public-key-short", public_key[:-1], message, signature),
        ("public-key-long", public_key + b"\x00", message, signature),
        ("public-key-reserved-bit", flip(public_key, 37, 0x20), message, signature),
        ("commitment-reserved-bit", public_key, message, flip(signature, 37, 0x20)),
        ("response-equals-L", public_key, message, signature[:38] + order),
        ("identity-public-key", identity, message, signature),
        ("noncanonical-public-y-p", modulus, message, signature),
        ("other-public-key", other_public, message, signature),
        ("other-signature", public_key, message, other_signature),
        ("all-zero-signature", public_key, message, b"\x00" * 76),
    ]

    verification_cases = []
    for identifier, key, case_message, case_signature in verification_inputs:
        blind_result = adapter.verify(key, case_message, case_signature)
        comparison_result = comparison.verify(key, case_message, case_signature)
        if blind_result != comparison_result:
            fail(f"verification oracle disagreement in {identifier}")
        verification_cases.append(
            {
                "expected": blind_result,
                "id": identifier,
                "message_hex": case_message.hex(),
                "public_key_hex": key.hex(),
                "signature_hex": case_signature.hex(),
            }
        )

    document = {
        "blind_source_sha256": adapter.SOURCE_SHA256,
        "cases": cases,
        "comparison_oracle_sha256": hashlib.sha256(
            comparison_path.read_bytes()
        ).hexdigest(),
        "freeze_commit": "0c48294893e9b7ec46109de51c3a04829befb39f",
        "schema": "ed301-eddsa-blind-differential-v1",
        "verification_cases": verification_cases,
    }
    output_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"blind_vector_materialization=PASS cases={len(cases)} "
        f"verification={len(verification_cases)} output={output_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
