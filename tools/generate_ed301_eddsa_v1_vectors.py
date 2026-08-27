#!/usr/bin/env python3
"""Materialize Ed301-EdDSA-v1 vectors from the independent Python oracle."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise RuntimeError(message)


def hex_fields(trace: dict[str, bytes]) -> dict[str, str]:
    return {
        "expanded_hash_hex": trace["expanded_hash"].hex(),
        "pruned_secret_scalar_le_hex": trace["pruned_secret_scalar"].hex(),
        "prefix_hex": trace["prefix"].hex(),
        "public_key_hex": trace["public_key"].hex(),
        "nonce_hash_hex": trace["nonce_hash"].hex(),
        "nonce_mod_L_le_hex": trace["nonce_scalar"].hex(),
        "commitment_R_hex": trace["commitment"].hex(),
        "challenge_hash_hex": trace["challenge_hash"].hex(),
        "challenge_mod_L_le_hex": trace["challenge_scalar"].hex(),
        "response_S_le_hex": trace["response"].hex(),
        "signature_hex": trace["signature"].hex(),
    }


def main() -> int:
    if len(sys.argv) not in (2, 3):
        raise SystemExit(
            "usage: generate_ed301_eddsa_v1_vectors.py "
            "<repository> [output-directory]"
        )
    repository = Path(sys.argv[1]).resolve(strict=True)
    output_dir = (
        Path(sys.argv[2]).resolve()
        if len(sys.argv) == 3
        else repository / "inputs" / "v1"
    )
    oracle_root = repository / "provider-tests" / "oracle"
    sys.path.insert(0, str(oracle_root))
    from ed301_eddsa import reference as legacy  # noqa: PLC0415
    from ed301_eddsa_v1 import reference as current  # noqa: PLC0415

    old_positive_path = (
        repository / "inputs" / "round4" / "ed301-eddsa-draft-00.json"
    )
    old_edge_path = (
        repository / "inputs" / "round4" / "ed301-eddsa-edge-draft-00.json"
    )
    old_positive = json.loads(old_positive_path.read_text(encoding="utf-8"))
    old_edge = json.loads(old_edge_path.read_text(encoding="utf-8"))

    cases = []
    for old_case in old_positive["cases"]:
        seed = bytes.fromhex(old_case["seed_hex"])
        message = bytes.fromhex(old_case["message_hex"])
        trace = current.sign_trace(seed, message)
        if trace["public_key"].hex() != old_case["public_key_hex"]:
            fail(f"public key changed for {old_case['id']}")
        if trace["signature"].hex() == old_case["signature_hex"]:
            fail(f"domain did not change the signature for {old_case['id']}")
        if not current.verify(trace["public_key"], message, trace["signature"]):
            fail(f"current oracle rejected {old_case['id']}")
        if legacy.verify(trace["public_key"], message, trace["signature"]):
            fail(f"legacy oracle accepted v1 signature {old_case['id']}")
        if current.verify(
            trace["public_key"],
            message,
            bytes.fromhex(old_case["signature_hex"]),
        ):
            fail(f"v1 oracle accepted legacy signature {old_case['id']}")
        case = {
            "id": old_case["id"],
            "seed_hex": seed.hex(),
            "message_hex": message.hex(),
            "context_hex": "",
        }
        case.update(hex_fields(trace))
        cases.append(case)

    context_inputs = [
        (
            "context-ascii",
            bytes.fromhex(old_positive["cases"][0]["seed_hex"]),
            b"Ed301 native context",
            b"foo",
        ),
        (
            "context-binary",
            bytes.fromhex(old_positive["cases"][2]["seed_hex"]),
            b"\x00context\xffmessage\x80",
            b"\x00\xff\x80\x01",
        ),
        (
            "context-max-255",
            bytes.fromhex(old_positive["cases"][1]["seed_hex"]),
            b"",
            bytes(range(255)),
        ),
    ]
    context_cases = []
    for identifier, seed, message, context in context_inputs:
        trace = current.sign_trace(seed, message, context)
        empty_context_signature = current.sign(seed, message)
        if trace["signature"] == empty_context_signature:
            fail(f"native context did not change {identifier}")
        if not current.verify(
            trace["public_key"], message, trace["signature"], context
        ):
            fail(f"context oracle rejected {identifier}")
        if current.verify(trace["public_key"], message, trace["signature"]):
            fail(f"empty context accepted {identifier}")
        altered = context[:-1] + bytes((context[-1] ^ 1,))
        if current.verify(
            trace["public_key"], message, trace["signature"], altered
        ):
            fail(f"altered context accepted {identifier}")
        case = {
            "id": identifier,
            "seed_hex": seed.hex(),
            "message_hex": message.hex(),
            "context_hex": context.hex(),
            "empty_context_signature_hex": empty_context_signature.hex(),
        }
        case.update(hex_fields(trace))
        context_cases.append(case)

    positive = {
        "schema": "ed301-eddsa-v1-vectors-v1",
        "specification": current.SPEC_IDENTIFIER,
        "status": "experimental-review-vectors",
        "warning": "Variable-time reference output; not production cryptography.",
        "parameters": {
            "parameter_set": "ED301-v1",
            "domain_prefix_ascii": current.DOMAIN_PREFIX.decode("ascii"),
            "phflag": current.PHFLAG,
            "max_context_bytes": current.MAX_CONTEXT_BYTES,
            "hash_output_bytes": current.HASH_BYTES,
            "seed_bytes": current.SEED_BYTES,
            "public_key_bytes": current.PUBLIC_KEY_BYTES,
            "signature_bytes": current.SIGNATURE_BYTES,
        },
        "cases": cases,
        "context_cases": context_cases,
        "legacy_rejection": [
            {
                "id": item["id"],
                "public_key_hex": item["public_key_hex"],
                "message_hex": item["message_hex"],
                "legacy_signature_hex": item["signature_hex"],
            }
            for item in old_positive["cases"]
        ],
    }

    edge = copy.deepcopy(old_edge)
    edge["schema"] = "ed301-eddsa-v1-edge-v1"
    edge["specification"] = current.SPEC_IDENTIFIER
    edge["status"] = "experimental-review-vectors"
    points = {
        item["id"]: bytes.fromhex(item["encoding_hex"])
        for item in edge["point_cases"]
    }
    seed_by_case = {item["id"]: bytes.fromhex(item["seed_hex"]) for item in cases}
    for item in edge["verification_cases"]:
        if "input" not in item:
            continue
        construction = item["construction"]
        message = bytes.fromhex(item["input"]["message_hex"])
        if construction["kind"] == "identity-commitment-equation":
            seed = seed_by_case[construction["seed_case"]]
            commitment = bytes.fromhex(construction["commitment_R_hex"])
            nonce = 0
        elif construction["kind"] == "mixed-torsion-commitment-equation":
            seed = bytes.fromhex(construction["seed_hex"])
            secret_scalar, prefix, _ = current.expand_seed(seed)
            nonce_hash, nonce = current._hash_to_scalar(
                (current.domain(), prefix, message)
            )
            prime = legacy.scalar_mult(nonce, legacy.BASE_POINT)
            torsion = legacy.decode_point(points[construction["torsion_point_case"]])
            commitment = legacy.encode_point(legacy.point_add(prime, torsion))
            construction["nonce_hash_hex"] = nonce_hash.hex()
            construction["nonce_mod_L_le_hex"] = nonce.to_bytes(38, "little").hex()
            construction["prime_commitment_R_hex"] = legacy.encode_point(prime).hex()
        else:
            fail(f"unsupported edge construction {construction['kind']}")
        secret_scalar, _, _ = current.expand_seed(seed)
        public_key = current.public_from_seed(seed)
        challenge_hash, challenge = current._hash_to_scalar(
            (current.domain(), commitment, public_key, message)
        )
        response = (nonce + challenge * secret_scalar) % current.L
        signature = commitment + response.to_bytes(38, "little")
        if not current.verify(public_key, message, signature):
            fail(f"reconstructed edge did not verify: {item['id']}")
        item["input"]["public_key_hex"] = public_key.hex()
        item["input"]["signature_hex"] = signature.hex()
        construction["commitment_R_hex"] = commitment.hex()
        construction["challenge_hash_hex"] = challenge_hash.hex()
        construction["challenge_mod_L_le_hex"] = challenge.to_bytes(38, "little").hex()
        construction["response_S_le_hex"] = response.to_bytes(38, "little").hex()
        if item["id"] == "valid-review-mixed-torsion-commitment":
            point_case = next(
                candidate
                for candidate in edge["point_cases"]
                if candidate["id"] == "review-mixed-torsion-R"
            )
            point_case["encoding_hex"] = commitment.hex()

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "ed301-eddsa-v1.json").write_text(
        json.dumps(positive, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "ed301-eddsa-edge-v1.json").write_text(
        json.dumps(edge, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
