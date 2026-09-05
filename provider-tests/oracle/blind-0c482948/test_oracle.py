#!/usr/bin/env python3
"""Deterministic regression checks for the hardened blind-oracle adapter."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def load_module(path: Path, name: str):
    resolved = path.resolve(strict=True)
    spec = importlib.util.spec_from_file_location(name, resolved)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {resolved}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if Path(module.__file__).resolve(strict=True) != resolved:
        raise RuntimeError(f"module identity mismatch for {resolved}")
    return module


def main() -> int:
    root = Path(__file__).resolve(strict=True).parent
    adapter = load_module(root / "oracle_adapter.py", "ed301_blind_adapter_test")
    vectors = json.loads((root / "blind_oracle_vectors.json").read_text("utf-8"))
    checks = 0

    def check(condition: bool, label: str) -> None:
        nonlocal checks
        if not condition:
            raise RuntimeError(f"blind oracle regression failed: {label}")
        checks += 1

    expected_api = {
        "Ed301Error",
        "derive_public_key",
        "sign",
        "validate_public_key",
        "verify",
    }
    check(set(adapter.__all__) == expected_api, "exact adapter API")
    raw_helpers = {
        "clear_cofactor",
        "decode_field",
        "decode_point",
        "encode_field",
        "encode_point",
        "is_on_curve",
        "is_prime_subgroup_nonidentity",
        "point_add",
        "point_double",
        "point_equal",
        "point_neg",
        "scalar_mult",
    }
    for helper in sorted(raw_helpers):
        check(not hasattr(adapter, helper), f"raw helper hidden: {helper}")

    for case in vectors["cases"]:
        seed = bytes.fromhex(case["seed_hex"])
        message = bytes.fromhex(case["message_hex"])
        public_key = bytes.fromhex(case["public_key_hex"])
        signature = bytes.fromhex(case["signature_hex"])
        check(adapter.derive_public_key(seed) == public_key, case["id"] + " public")
        check(adapter.sign(seed, message) == signature, case["id"] + " signature")
        check(adapter.sign(seed, message) == signature, case["id"] + " deterministic")
        check(adapter.validate_public_key(public_key), case["id"] + " public valid")
        check(adapter.verify(public_key, message, signature), case["id"] + " verify")

    for case in vectors["verification_cases"]:
        actual = adapter.verify(
            bytes.fromhex(case["public_key_hex"]),
            bytes.fromhex(case["message_hex"]),
            bytes.fromhex(case["signature_hex"]),
        )
        check(actual is case["expected"], case["id"] + " decision")

    first = vectors["cases"][0]
    seed = bytes.fromhex(first["seed_hex"])
    message = bytes.fromhex(first["message_hex"])
    public_key = bytes.fromhex(first["public_key_hex"])
    signature = bytes.fromhex(first["signature_hex"])
    mutable_public = bytearray(public_key)
    mutable_message = bytearray(message)
    mutable_signature = bytearray(signature)
    original_public = bytes(mutable_public)
    original_message = bytes(mutable_message)
    original_signature = bytes(mutable_signature)

    check(not adapter.verify(mutable_public, message, signature), "mutable public rejected")
    check(not adapter.verify(public_key, mutable_message, signature), "mutable message rejected")
    check(not adapter.verify(public_key, message, mutable_signature), "mutable signature rejected")
    check(not adapter.verify(memoryview(public_key), message, signature), "memoryview rejected")
    check(not adapter.verify(public_key, "not bytes", signature), "string rejected")
    check(bytes(mutable_public) == original_public, "mutable public unchanged")
    check(bytes(mutable_message) == original_message, "mutable message unchanged")
    check(bytes(mutable_signature) == original_signature, "mutable signature unchanged")

    throwing_calls = [
        (adapter.derive_public_key, (bytearray(seed),)),
        (adapter.sign, (seed, bytearray(message))),
        (adapter.validate_public_key, (bytearray(public_key),)),
    ]
    for function, arguments in throwing_calls:
        try:
            function(*arguments)
        except adapter.Ed301Error:
            check(True, function.__name__ + " mutable input rejected")
        else:
            check(False, function.__name__ + " mutable input accepted")

    print(f"blind_oracle_regressions=PASS checks={checks}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
