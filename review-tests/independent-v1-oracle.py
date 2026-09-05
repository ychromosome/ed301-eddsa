#!/usr/bin/env python3
"""Independent Ed301-EdDSA-v1 transcript/KAT cross-check.

The curve arithmetic is loaded from the sealed pre-v1 blind oracle.  Only the
new transcript below was derived from inputs/v1/ED301-EdDSA-v1.md; it does not
import the repository's new v1 Python reference or vector generator.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BLIND_PATH = (
    ROOT
    / "provider-tests/oracle/blind-0c482948/source/ed301_eddsa.py"
)
VECTOR_PATH = ROOT / "inputs/v1/ed301-eddsa-v1.json"
DOMAIN_LABEL = b"SigEd301-v1"


def load_blind_curve():
    spec = importlib.util.spec_from_file_location("sealed_blind_ed301", BLIND_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load sealed blind curve oracle")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


curve = load_blind_curve()


def domain(context: bytes = b"") -> bytes:
    if not isinstance(context, bytes):
        raise TypeError("context must be bytes")
    if len(context) > 255:
        raise ValueError("context exceeds one-octet bound")
    return DOMAIN_LABEL + bytes((0, len(context))) + context


def trace(seed: bytes, message: bytes, context: bytes = b"") -> dict[str, str]:
    if len(seed) != curve.SEED_BYTES:
        raise ValueError("seed length")
    dom = domain(context)
    expanded = curve.H(seed)
    lower = bytearray(expanded[: curve.FIELD_BYTES])
    prefix = expanded[curve.FIELD_BYTES :]
    lower[0] &= 0xFC
    lower[-1] = (lower[-1] & 0x0F) | 0x10
    secret_scalar = int.from_bytes(lower, "little")
    public_key = curve.encode_point(
        curve.scalar_mult(secret_scalar, curve.B_POINT)
    )
    nonce_hash = curve.H(dom + prefix + message)
    nonce = int.from_bytes(nonce_hash, "little") % curve.L
    commitment = curve.encode_point(curve.scalar_mult(nonce, curve.B_POINT))
    challenge_hash = curve.H(dom + commitment + public_key + message)
    challenge = int.from_bytes(challenge_hash, "little") % curve.L
    response = (nonce + challenge * secret_scalar) % curve.L
    response_encoding = curve.encode_scalar(response)
    signature = commitment + response_encoding
    return {
        "expanded_hash_hex": expanded.hex(),
        "pruned_secret_scalar_le_hex": bytes(lower).hex(),
        "prefix_hex": prefix.hex(),
        "public_key_hex": public_key.hex(),
        "nonce_hash_hex": nonce_hash.hex(),
        "nonce_mod_L_le_hex": curve.encode_scalar(nonce).hex(),
        "commitment_R_hex": commitment.hex(),
        "challenge_hash_hex": challenge_hash.hex(),
        "challenge_mod_L_le_hex": curve.encode_scalar(challenge).hex(),
        "response_S_le_hex": response_encoding.hex(),
        "signature_hex": signature.hex(),
    }


def verify(public_key: bytes, message: bytes, context: bytes, signature: bytes) -> bool:
    try:
        dom = domain(context)
        public_point = curve.validate_public_key(public_key)
        if len(signature) != curve.SIGNATURE_BYTES:
            return False
        commitment_encoding = signature[: curve.FIELD_BYTES]
        commitment = curve.decode_point(commitment_encoding)
        response = curve.decode_scalar(signature[curve.FIELD_BYTES :])
        challenge = int.from_bytes(
            curve.H(dom + commitment_encoding + public_key + message), "little"
        ) % curve.L
        left = curve.scalar_mult(curve.COFACTOR * response, curve.B_POINT)
        right = curve.point_add(
            curve.scalar_mult(curve.COFACTOR, commitment),
            curve.scalar_mult(curve.COFACTOR * challenge, public_point),
        )
        return curve.point_equal(left, right)
    except (curve.Ed301Error, TypeError, ValueError):
        return False


def check_record(record: dict[str, str]) -> int:
    seed = bytes.fromhex(record["seed_hex"])
    message = bytes.fromhex(record["message_hex"])
    context = bytes.fromhex(record["context_hex"])
    computed = trace(seed, message, context)
    checks = 0
    for key, value in computed.items():
        assert record[key] == value, f"{record['id']}: {key} mismatch"
        checks += 1
    signature = bytes.fromhex(computed["signature_hex"])
    public_key = bytes.fromhex(computed["public_key_hex"])
    assert verify(public_key, message, context, signature)
    assert not verify(public_key, message, context + b"\x00", signature)
    checks += 2
    if "empty_context_signature_hex" in record:
        empty = trace(seed, message, b"")["signature_hex"]
        assert record["empty_context_signature_hex"] == empty
        assert empty != computed["signature_hex"]
        checks += 2
    return checks


def main() -> None:
    document = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    parameters = document["parameters"]
    assert parameters["domain_prefix_ascii"].encode() == DOMAIN_LABEL
    assert parameters["phflag"] == 0
    assert parameters["max_context_bytes"] == 255
    assert domain() == b"SigEd301-v1\x00\x00"
    assert len(domain(bytes(range(255)))) == len(DOMAIN_LABEL) + 2 + 255
    try:
        domain(bytes(256))
    except ValueError:
        pass
    else:
        raise AssertionError("256-byte context accepted")

    records = document["cases"] + document["context_cases"]
    checks = 6
    for record in records:
        checks += check_record(record)

    v1_by_id = {record["id"]: record for record in document["cases"]}
    for legacy in document["legacy_rejection"]:
        public_key = bytes.fromhex(legacy["public_key_hex"])
        message = bytes.fromhex(legacy["message_hex"])
        legacy_signature = bytes.fromhex(legacy["legacy_signature_hex"])
        v1_signature = bytes.fromhex(v1_by_id[legacy["id"]]["signature_hex"])
        assert curve.verify(public_key, message, legacy_signature)
        assert not verify(public_key, message, b"", legacy_signature)
        assert verify(public_key, message, b"", v1_signature)
        assert not curve.verify(public_key, message, v1_signature)
        checks += 4

    # Length binding is injective for every accepted opaque context.
    domains = {domain(bytes(range(length))) for length in range(256)}
    assert len(domains) == 256
    checks += 1

    print(
        "independent_v1_oracle=PASS "
        f"records={len(records)} legacy_boundaries={len(document['legacy_rejection'])} "
        f"checks={checks}"
    )


if __name__ == "__main__":
    main()
