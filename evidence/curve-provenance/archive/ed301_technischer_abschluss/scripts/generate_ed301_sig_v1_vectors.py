#!/usr/bin/env python3
"""Generate the reproducible Ed301-Sig-v1 review vectors.

The generator deliberately imports the reviewed, variable-time Python
reference.  It is a conformance-vector tool, not an independent
implementation and not production cryptographic software.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from copy import deepcopy
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "referenz"
if str(REFERENCE) not in sys.path:
    sys.path.insert(0, str(REFERENCE))

import ed301_curve as curve  # noqa: E402
import ed301_sig as sig  # noqa: E402


SCHEMA_POSITIVE = "Ed301-Sig-v1-positive-vectors-v1"
SCHEMA_NEGATIVE = "Ed301-Sig-v1-negative-vectors-v1"
PARAMETERS_PATH = ROOT / "parameter" / "ed301-v1.json"
SPECIFICATION_PATH = ROOT / "spezifikation" / "Ed301-Sig-v1.md"
REFERENCE_PATH = ROOT / "referenz" / "ed301_sig.py"
CURVE_REFERENCE_PATH = ROOT / "referenz" / "ed301_curve.py"
SOURCE_PATHS = (
    PARAMETERS_PATH,
    SPECIFICATION_PATH,
    REFERENCE_PATH,
    CURVE_REFERENCE_PATH,
)


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources() -> list[dict[str, str]]:
    return [
        {
            "path": str(path.relative_to(ROOT)),
            "sha256": sha256_file(path),
        }
        for path in SOURCE_PATHS
    ]


def bytes_value(value: bytes) -> dict[str, Any]:
    return {"hex": value.hex(), "length_decimal": str(len(value))}


def integer_value(value: int, *, encoded_le38: bool = False) -> dict[str, str]:
    result = {
        "decimal": str(value),
        "hex_be": format(value, "x"),
    }
    if encoded_le38:
        result["encoding_le38_hex"] = value.to_bytes(38, "little").hex()
    return result


def point_value(point: curve.Point) -> dict[str, Any]:
    return {
        "x": integer_value(point[0]),
        "y": integer_value(point[1]),
        "encoding_hex": curve.encode_point(point).hex(),
    }


def validate_fixed_sources() -> None:
    params = json.loads(PARAMETERS_PATH.read_text(encoding="utf-8"))
    checks = {
        int(params["field"]["p_decimal"]): curve.P,
        int(params["edwards"]["a_decimal"]): curve.A_EDWARDS,
        int(params["edwards"]["d_decimal"]): curve.D_EDWARDS,
        int(params["group"]["q_decimal"]): curve.Q,
        int(params["group"]["cofactor_h"]): curve.H,
    }
    if any(left != right for left, right in checks.items()):
        raise RuntimeError("parameter JSON and Python curve reference disagree")
    if params["basepoint"]["G_compressed_edwards_hex"] != curve.G_ENCODING.hex():
        raise RuntimeError("parameter JSON and Python basepoint encoding disagree")
    specification = SPECIFICATION_PATH.read_text(encoding="utf-8")
    if sig.DOM.hex() not in specification or sig.SUITE.decode("ascii") not in specification:
        raise RuntimeError("signature reference domain is absent from the specification")


def positive_trace(
    vector_id: str,
    seed: bytes,
    context: bytes,
    message: bytes,
    *,
    description: str,
    repeat_of: str | None = None,
) -> dict[str, Any]:
    material = sig._derive_key_material(seed)
    frame_s = sig._frame_secret_scalar(seed, material.scalar_retry)
    xof_s = sig._shake256(frame_s)
    reduced_s = int.from_bytes(xof_s, "little") % curve.Q
    if reduced_s != material.scalar:
        raise AssertionError("secret-scalar trace mismatch")

    frame_prefix = sig._frame_prefix(seed)
    prefix = sig._shake256(frame_prefix)
    if prefix != material.prefix:
        raise AssertionError("prefix trace mismatch")

    nonce, nonce_retry = sig._derive_nonzero_scalar(
        lambda retry: sig._frame_nonce(
            prefix, material.public_key, context, message, retry
        )
    )
    frame_nonce = sig._frame_nonce(
        prefix, material.public_key, context, message, nonce_retry
    )
    xof_nonce = sig._shake256(frame_nonce)
    if int.from_bytes(xof_nonce, "little") % curve.Q != nonce:
        raise AssertionError("nonce trace mismatch")

    point_r = curve.scalar_multiply(nonce, curve.G)
    encoded_r = curve.encode_point(point_r)
    frame_challenge = sig._frame_challenge(
        material.public_key, context, message, encoded_r
    )
    xof_challenge = sig._shake256(frame_challenge)
    challenge = int.from_bytes(xof_challenge, "little") % curve.Q
    scalar_s = (nonce + challenge * material.scalar) % curve.Q
    signature = encoded_r + curve.encode_scalar(scalar_s)

    secret_key, public_key = sig.keygen(seed)
    reference_signature = sig.sign(secret_key, context, message)
    if secret_key != seed or public_key != material.public_key:
        raise AssertionError("KeyGen trace mismatch")
    if reference_signature != signature:
        raise AssertionError("Sign trace mismatch")
    if not sig.verify(public_key, context, message, signature):
        raise AssertionError("generated positive signature does not verify")

    vector: dict[str, Any] = {
        "id": vector_id,
        "description": description,
        "inputs": {
            "seed_hex": seed.hex(),
            "context_hex": context.hex(),
            "context_length_decimal": str(len(context)),
            "message_hex": message.hex(),
            "message_length_decimal": str(len(message)),
        },
        "key_derivation": {
            "scalar_retry_decimal": str(material.scalar_retry),
            "scalar_frame_hex": frame_s.hex(),
            "scalar_xof64_hex": xof_s.hex(),
            "secret_scalar_s": integer_value(material.scalar, encoded_le38=True),
            "prefix_frame_hex": frame_prefix.hex(),
            "prefix_xof64_hex": prefix.hex(),
            "public_point_A": point_value(material.public_point),
            "public_key_hex": material.public_key.hex(),
        },
        "nonce_derivation": {
            "nonce_retry_decimal": str(nonce_retry),
            "nonce_frame_hex": frame_nonce.hex(),
            "nonce_xof64_hex": xof_nonce.hex(),
            "nonce_scalar_r": integer_value(nonce, encoded_le38=True),
            "commitment_point_R": point_value(point_r),
            "commitment_encoding_R_hex": encoded_r.hex(),
        },
        "challenge_derivation": {
            "challenge_frame_hex": frame_challenge.hex(),
            "challenge_xof64_hex": xof_challenge.hex(),
            "challenge_scalar_k": integer_value(challenge, encoded_le38=True),
        },
        "result": {
            "response_scalar_S": integer_value(scalar_s, encoded_le38=True),
            "signature_hex": signature.hex(),
            "signature_length_decimal": str(len(signature)),
            "verify": True,
        },
    }
    if repeat_of is not None:
        vector["repeat_of"] = repeat_of
    return vector


def positive_case_inputs() -> list[dict[str, Any]]:
    short = {
        "id": "positive-short-nonempty",
        "description": "Short opaque message and nonempty context.",
        "seed": bytes.fromhex("ff" * 38),
        "context": b"Menora",
        "message": b"ED301-Sig-v1",
    }
    return [
        {
            "id": "positive-empty",
            "description": "Empty context and empty message.",
            "seed": bytes(range(38)),
            "context": b"",
            "message": b"",
        },
        short,
        {
            "id": "positive-max-context-long-message",
            "description": "Maximum 255-byte binary context and 4096-byte message.",
            "seed": bytes.fromhex("a55a" * 19),
            "context": bytes(range(255)),
            "message": bytes(range(256)) * 16,
        },
        {
            "id": "positive-binary",
            "description": "Opaque binary inputs containing zero and high bytes.",
            "seed": bytes(reversed(range(38))),
            "context": bytes.fromhex("00ff80007f"),
            "message": bytes.fromhex("00ff000102807f") + bytes(range(64)),
        },
        {
            **short,
            "id": "positive-short-deterministic-repeat",
            "description": "Exact deterministic repetition of positive-short-nonempty.",
            "repeat_of": "positive-short-nonempty",
        },
    ]


def make_positive_package() -> dict[str, Any]:
    vectors = []
    for case in positive_case_inputs():
        vectors.append(
            positive_trace(
                case["id"],
                case["seed"],
                case["context"],
                case["message"],
                description=case["description"],
                repeat_of=case.get("repeat_of"),
            )
        )
    by_id = {item["id"]: item for item in vectors}
    repeat = by_id["positive-short-deterministic-repeat"]
    original = by_id[repeat["repeat_of"]]
    repeat_comparable = deepcopy(repeat)
    original_comparable = deepcopy(original)
    for item in (repeat_comparable, original_comparable):
        item.pop("id")
        item.pop("description")
        item.pop("repeat_of", None)
    if repeat_comparable != original_comparable:
        raise AssertionError("deterministic repeat differs from its original")
    return {
        "schema": SCHEMA_POSITIVE,
        "status": "reference-conformance-vectors-not-production-audited",
        "suite": sig.SUITE.decode("ascii"),
        "domain_hex": sig.DOM.hex(),
        "encoding_conventions": {
            "bytes": "lowercase hexadecimal without 0x; empty bytes are the empty string",
            "integers_decimal": "base-10 strings",
            "integers_hex_be": "minimal lowercase big-endian magnitude without 0x; zero is 0",
            "scalar_encodings": "exactly 38-byte little-endian lowercase hexadecimal",
        },
        "sources": sources(),
        "vector_count_decimal": str(len(vectors)),
        "vectors": vectors,
    }


def verification_case(
    vector_id: str,
    category: str,
    reason: str,
    public_key: bytes,
    context: bytes,
    message: bytes,
    signature: bytes,
    declared_message_length: int | None = None,
    **extra: Any,
) -> dict[str, Any]:
    if declared_message_length is None:
        declared_message_length = len(message)
    result = {
        "id": vector_id,
        "category": category,
        "reason": reason,
        "public_key_hex": public_key.hex(),
        "context_hex": context.hex(),
        "message_hex": message.hex(),
        "message_length_decimal": str(declared_message_length),
        "signature_hex": signature.hex(),
        "expected_verify": False,
    }
    result.update(extra)
    return result


def custom_challenge_frame(
    public_key: bytes,
    context: bytes,
    message: bytes,
    encoded_r: bytes,
    *,
    dom: bytes = sig.DOM,
    operation: int = sig.OP_CHALLENGE,
    field_count: int = 4,
    fields: list[tuple[int, bytes]] | None = None,
) -> bytes:
    if fields is None:
        fields = [
            (sig.TAG_PUBLIC_KEY, public_key),
            (sig.TAG_CONTEXT, context),
            (sig.TAG_MESSAGE, message),
            (sig.TAG_R, encoded_r),
        ]
    return dom + bytes([operation, field_count]) + b"".join(
        sig._field(tag, value) for tag, value in fields
    )


def alternate_protocol_signature(
    seed: bytes,
    context: bytes,
    message: bytes,
    frame_builder: Any,
) -> tuple[bytes, dict[str, Any]]:
    material = sig._derive_key_material(seed)
    nonce, _ = sig._derive_nonzero_scalar(
        lambda retry: sig._frame_nonce(
            material.prefix, material.public_key, context, message, retry
        )
    )
    point_r = curve.scalar_multiply(nonce, curve.G)
    encoded_r = curve.encode_point(point_r)
    frame = frame_builder(material.public_key, context, message, encoded_r)
    xof = sig._shake256(frame)
    challenge = int.from_bytes(xof, "little") % curve.Q
    scalar_s = (nonce + challenge * material.scalar) % curve.Q
    signature = encoded_r + curve.encode_scalar(scalar_s)
    return signature, {
        "alternate_challenge_frame_hex": frame.hex(),
        "alternate_challenge_xof64_hex": xof.hex(),
        "alternate_challenge_k": integer_value(challenge, encoded_le38=True),
    }


def find_nonreconstructable_encoding() -> bytes:
    for y in range(2, 10000):
        y2 = y * y % curve.P
        denominator = (curve.A_EDWARDS - curve.D_EDWARDS * y2) % curve.P
        if denominator == 0:
            continue
        x2 = (1 - y2) * pow(denominator, curve.P - 2, curve.P) % curve.P
        if pow(x2, (curve.P - 1) // 2, curve.P) == curve.P - 1:
            encoded = y.to_bytes(38, "little")
            try:
                curve.decode_point(encoded)
            except ValueError:
                return encoded
    raise RuntimeError("failed to find deterministic nonreconstructable encoding")


def make_internal_vectors(base: dict[str, Any]) -> dict[str, Any]:
    seed = bytes.fromhex(base["inputs"]["seed_hex"])
    context = bytes.fromhex(base["inputs"]["context_hex"])
    message = bytes.fromhex(base["inputs"]["message_hex"])
    public_key = bytes.fromhex(base["key_derivation"]["public_key_hex"])
    encoded_r = bytes.fromhex(base["nonce_derivation"]["commitment_encoding_R_hex"])
    prefix = bytes.fromhex(base["key_derivation"]["prefix_xof64_hex"])

    zero64 = b"\x00" * 64
    one64 = b"\x01" + b"\x00" * 63
    key_frames = [sig._frame_secret_scalar(seed, retry) for retry in (0, 1)]
    nonce_frames = [
        sig._frame_nonce(prefix, public_key, context, message, retry)
        for retry in (0, 1)
    ]

    canonical_nonce = nonce_frames[0]
    wrong_nonce_operation = bytearray(canonical_nonce)
    wrong_nonce_operation[len(sig.DOM)] = sig.OP_CHALLENGE
    canonical_challenge = sig._frame_challenge(public_key, context, message, encoded_r)
    swapped_challenge = custom_challenge_frame(
        public_key,
        context,
        message,
        encoded_r,
        fields=[
            (sig.TAG_R, encoded_r),
            (sig.TAG_PUBLIC_KEY, public_key),
            (sig.TAG_CONTEXT, context),
            (sig.TAG_MESSAGE, message),
        ],
    )

    synthetic_s = 1
    synthetic_r = 1
    synthetic_k = curve.Q - 1
    synthetic_S = (synthetic_r + synthetic_k * synthetic_s) % curve.Q
    if synthetic_S != 0:
        raise AssertionError("synthetic S=0 construction failed")

    return {
        "classification": (
            "Internal XOF-injection and framing tests only; these are not ordinary "
            "verification vectors and MUST NOT be passed to an unmodified verifier."
        ),
        "null_and_retry": [
            {
                "id": "internal-key-scalar-zero-then-one",
                "operation": "key scalar derivation",
                "injected_xof64_hex": [zero64.hex(), one64.hex()],
                "frame_hex": [frame.hex() for frame in key_frames],
                "expected_retries_decimal": "1",
                "expected_scalar_decimal": "1",
            },
            {
                "id": "internal-nonce-zero-then-one",
                "operation": "nonce derivation",
                "injected_xof64_hex": [zero64.hex(), one64.hex()],
                "frame_hex": [frame.hex() for frame in nonce_frames],
                "expected_retries_decimal": "1",
                "expected_scalar_decimal": "1",
            },
            {
                "id": "internal-retry-exhaustion",
                "operation": "nonzero scalar derivation",
                "start_retry_decimal": str(sig.MAX_U32),
                "injected_xof64_hex": zero64.hex(),
                "expected": "OverflowError without counter wrap",
            },
            {
                "id": "internal-zero-challenge-accepted",
                "operation": "challenge reduction",
                "injected_xof64_hex": zero64.hex(),
                "expected_k_decimal": "0",
                "expected": "no retry",
            },
            {
                "id": "internal-zero-S-accepted",
                "operation": "response equation",
                "synthetic_s_decimal": str(synthetic_s),
                "synthetic_r_decimal": str(synthetic_r),
                "synthetic_k_decimal": str(synthetic_k),
                "expected_S_decimal": str(synthetic_S),
                "expected_S_encoding_le38_hex": curve.encode_scalar(0).hex(),
                "expected": "canonical encoding; signature equation decides",
            },
        ],
        "framing": [
            {
                "id": "internal-nonce-wrong-operation",
                "canonical_frame_hex": canonical_nonce.hex(),
                "altered_frame_hex": bytes(wrong_nonce_operation).hex(),
                "canonical_xof64_hex": sig._shake256(canonical_nonce).hex(),
                "altered_xof64_hex": sig._shake256(bytes(wrong_nonce_operation)).hex(),
                "verifier_observability": (
                    "Nonce derivation is signer-internal; a verifier cannot reject solely "
                    "because a signer used a different nonce derivation."
                ),
            },
            {
                "id": "internal-challenge-field-order",
                "canonical_frame_hex": canonical_challenge.hex(),
                "altered_frame_hex": swapped_challenge.hex(),
                "canonical_xof64_hex": sig._shake256(canonical_challenge).hex(),
                "altered_xof64_hex": sig._shake256(swapped_challenge).hex(),
                "expected": "frames and XOF outputs differ",
            },
        ],
    }


def make_negative_package(positive: dict[str, Any]) -> dict[str, Any]:
    base = next(
        item for item in positive["vectors"] if item["id"] == "positive-short-nonempty"
    )
    seed = bytes.fromhex(base["inputs"]["seed_hex"])
    context = bytes.fromhex(base["inputs"]["context_hex"])
    message = bytes.fromhex(base["inputs"]["message_hex"])
    public_key = bytes.fromhex(base["key_derivation"]["public_key_hex"])
    signature = bytes.fromhex(base["result"]["signature_hex"])
    encoded_r, encoded_s = signature[:38], signature[38:]

    vectors: list[dict[str, Any]] = []

    def add(
        vector_id: str,
        category: str,
        reason: str,
        *,
        pk: bytes = public_key,
        ctx: bytes = context,
        msg: bytes = message,
        signature_value: bytes = signature,
        declared_message_length: int | None = None,
        **extra: Any,
    ) -> None:
        item = verification_case(
            vector_id,
            category,
            reason,
            pk,
            ctx,
            msg,
            signature_value,
            declared_message_length,
            **extra,
        )
        announced = len(msg) if declared_message_length is None else declared_message_length
        reference_result = (
            0 <= announced <= sig.MAX_U64
            and announced == len(msg)
            and sig.verify(pk, ctx, msg, signature_value)
        )
        if reference_result:
            raise AssertionError(f"negative vector unexpectedly verifies: {vector_id}")
        vectors.append(item)

    add(
        "negative-message-manipulated",
        "binding",
        "One message byte differs from the signed transcript.",
        msg=message[:-1] + bytes([message[-1] ^ 1]),
    )
    add(
        "negative-context-manipulated",
        "binding",
        "One context byte differs from the signed transcript.",
        ctx=context[:-1] + bytes([context[-1] ^ 1]),
    )
    other_pk = sig.keygen(bytes(reversed(range(38))))[1]
    add(
        "negative-public-key-substituted",
        "binding",
        "A different valid prime-subgroup public key is supplied.",
        pk=other_pk,
    )
    altered_s_int = (int.from_bytes(encoded_s, "little") + 1) % curve.Q
    add(
        "negative-signature-S-manipulated",
        "binding",
        "The canonical response scalar is changed by one.",
        signature_value=encoded_r + curve.encode_scalar(altered_s_int),
    )
    altered_r = bytearray(encoded_r)
    altered_r[0] ^= 1
    add(
        "negative-signature-R-bit-manipulated",
        "binding",
        "One bit of the commitment encoding is changed.",
        signature_value=bytes(altered_r) + encoded_s,
    )

    add("negative-public-key-short", "length", "Public key has 37 bytes.", pk=public_key[:-1])
    add("negative-public-key-long", "length", "Public key has 39 bytes.", pk=public_key + b"\x00")
    add("negative-signature-short", "length", "Signature has 75 bytes.", signature_value=signature[:-1])
    add("negative-signature-long", "length", "Signature has 77 bytes.", signature_value=signature + b"\x00")
    add(
        "negative-message-length-announced-short",
        "length",
        "The announced message length is one byte shorter than the supplied message.",
        declared_message_length=len(message) - 1,
    )
    add(
        "negative-message-length-announced-long",
        "length",
        "The announced message length is one byte longer than the supplied message.",
        declared_message_length=len(message) + 1,
    )
    add(
        "negative-message-length-u64-overflow",
        "input-boundary",
        "The announced message length is 2^64 and cannot be encoded as u64.",
        declared_message_length=1 << 64,
    )

    add(
        "negative-S-equal-q",
        "scalar-canonicality",
        "S=q is outside the required interval 0<=S<q and must not be reduced.",
        signature_value=encoded_r + curve.Q.to_bytes(38, "little"),
    )
    add(
        "negative-S-greater-q",
        "scalar-canonicality",
        "S=q+1 is outside the required interval and must not be reduced.",
        signature_value=encoded_r + (curve.Q + 1).to_bytes(38, "little"),
    )

    bad_pk_301 = bytearray(public_key)
    bad_pk_301[37] |= 0x20
    add(
        "negative-public-key-reserved-bit-301",
        "point-canonicality",
        "Reserved point bit 301 is set.",
        pk=bytes(bad_pk_301),
    )
    bad_r_302 = bytearray(encoded_r)
    bad_r_302[37] |= 0x40
    add(
        "negative-R-reserved-bit-302",
        "point-canonicality",
        "Reserved point bit 302 is set.",
        signature_value=bytes(bad_r_302) + encoded_s,
    )
    y_equal_p = curve.P.to_bytes(38, "little")
    add(
        "negative-public-key-y-equal-p",
        "point-canonicality",
        "Public-key y=p is noncanonical.",
        pk=y_equal_p,
    )
    add(
        "negative-R-y-equal-p",
        "point-canonicality",
        "Commitment y=p is noncanonical.",
        signature_value=y_equal_p + encoded_s,
    )

    identity = curve.encode_point(curve.IDENTITY)
    order2 = curve.encode_point(curve.ORDER_2)
    order4_point = (pow(45677, curve.P - 2, curve.P), 0)
    if curve.scalar_multiply(4, order4_point) != curve.IDENTITY:
        raise AssertionError("order-4 point construction failed")
    order4 = curve.encode_point(order4_point)
    material = sig._derive_key_material(seed)
    point_r = curve.decode_point(encoded_r, require_prime_order=True)
    mixed_a2 = curve.encode_point(curve.point_add(material.public_point, curve.ORDER_2))
    mixed_a4 = curve.encode_point(curve.point_add(material.public_point, order4_point))
    mixed_r2 = curve.encode_point(curve.point_add(point_r, curve.ORDER_2))
    mixed_r4 = curve.encode_point(curve.point_add(point_r, order4_point))

    for suffix, encoding, explanation in (
        ("identity", identity, "identity"),
        ("torsion-order-2", order2, "order-2 torsion point"),
        ("torsion-order-4", order4, "order-4 torsion point"),
        ("mixed-order-2q", mixed_a2, "mixed point with a nonzero order-2 component"),
        ("mixed-order-4q", mixed_a4, "mixed point with a nonzero order-4 component"),
    ):
        add(
            f"negative-public-key-{suffix}",
            "subgroup",
            f"Public key is the {explanation}, not a nonidentity q-subgroup point.",
            pk=encoding,
        )
    for suffix, encoding, explanation in (
        ("identity", identity, "identity"),
        ("torsion-order-2", order2, "order-2 torsion point"),
        ("torsion-order-4", order4, "order-4 torsion point"),
        ("mixed-order-2q", mixed_r2, "mixed point with a nonzero order-2 component"),
        ("mixed-order-4q", mixed_r4, "mixed point with a nonzero order-4 component"),
    ):
        add(
            f"negative-R-{suffix}",
            "subgroup",
            f"R is the {explanation}, not a nonidentity q-subgroup point.",
            signature_value=encoding + encoded_s,
        )

    nonpoint = find_nonreconstructable_encoding()
    add(
        "negative-public-key-nonreconstructable",
        "point-decoding",
        "The encoded y yields a nonsquare x^2 and cannot reconstruct a curve point.",
        pk=nonpoint,
    )
    add(
        "negative-R-nonreconstructable",
        "point-decoding",
        "The encoded R.y yields a nonsquare x^2 and cannot reconstruct a curve point.",
        signature_value=nonpoint + encoded_s,
    )
    identity_wrong_sign = bytearray(identity)
    identity_wrong_sign[37] |= 0x80
    add(
        "negative-public-key-x0-sign-one",
        "point-canonicality",
        "x=0 has the forbidden sign bit one.",
        pk=bytes(identity_wrong_sign),
    )
    add(
        "negative-R-x0-sign-one",
        "point-canonicality",
        "R with x=0 has the forbidden sign bit one.",
        signature_value=bytes(identity_wrong_sign) + encoded_s,
    )
    add(
        "negative-context-256",
        "input-boundary",
        "Version 1 permits at most 255 context bytes.",
        ctx=bytes(range(256)),
    )

    alternate_builders = [
        (
            "negative-wrong-suite",
            "domain-separation",
            "Challenge uses suite Ed301-Sig-v0.",
            lambda a, c, m, r: custom_challenge_frame(
                a, c, m, r, dom=bytes([12]) + b"Ed301-Sig-v0" + b"\x01\x00"
            ),
        ),
        (
            "negative-wrong-version",
            "domain-separation",
            "Challenge uses version 2.",
            lambda a, c, m, r: custom_challenge_frame(
                a, c, m, r, dom=sig.DOM[:-2] + b"\x02\x00"
            ),
        ),
        (
            "negative-wrong-mode",
            "domain-separation",
            "Challenge uses mode 1 instead of pure mode 0.",
            lambda a, c, m, r: custom_challenge_frame(
                a, c, m, r, dom=sig.DOM[:-1] + b"\x01"
            ),
        ),
        (
            "negative-wrong-domain-prefix",
            "domain-separation",
            "Challenge domain has a changed suite-length prefix.",
            lambda a, c, m, r: custom_challenge_frame(
                a, c, m, r, dom=b"\x0d" + sig.DOM[1:]
            ),
        ),
        (
            "negative-wrong-operation",
            "framing",
            "Challenge operation byte is OP_NONCE instead of OP_CHALLENGE.",
            lambda a, c, m, r: custom_challenge_frame(
                a, c, m, r, operation=sig.OP_NONCE
            ),
        ),
        (
            "negative-wrong-field-count",
            "framing",
            "Challenge declares three fields while carrying four.",
            lambda a, c, m, r: custom_challenge_frame(a, c, m, r, field_count=3),
        ),
        (
            "negative-wrong-R-tag",
            "framing",
            "Challenge uses an unknown tag for R.",
            lambda a, c, m, r: custom_challenge_frame(
                a,
                c,
                m,
                r,
                fields=[
                    (sig.TAG_PUBLIC_KEY, a),
                    (sig.TAG_CONTEXT, c),
                    (sig.TAG_MESSAGE, m),
                    (0x08, r),
                ],
            ),
        ),
        (
            "negative-wrong-field-order",
            "framing",
            "Challenge places R before A, context and message.",
            lambda a, c, m, r: custom_challenge_frame(
                a,
                c,
                m,
                r,
                fields=[
                    (sig.TAG_R, r),
                    (sig.TAG_PUBLIC_KEY, a),
                    (sig.TAG_CONTEXT, c),
                    (sig.TAG_MESSAGE, m),
                ],
            ),
        ),
    ]
    for vector_id, category, reason, builder in alternate_builders:
        alternate_signature, construction = alternate_protocol_signature(
            seed, context, message, builder
        )
        add(
            vector_id,
            category,
            reason,
            signature_value=alternate_signature,
            construction=construction,
        )

    return {
        "schema": SCHEMA_NEGATIVE,
        "status": "reference-conformance-vectors-not-production-audited",
        "suite": sig.SUITE.decode("ascii"),
        "domain_hex": sig.DOM.hex(),
        "base_positive_vector_id": base["id"],
        "classification": {
            "verification_vectors": "Each is an ordinary Verify input with expected result false.",
            "internal_only": (
                "Injected-XOF and framing semantics; not ordinary verification inputs."
            ),
        },
        "encoding_conventions": positive["encoding_conventions"],
        "sources": sources(),
        "verification_vector_count_decimal": str(len(vectors)),
        "verification_vectors": vectors,
        "internal_only": make_internal_vectors(base),
    }


def generate_packages() -> tuple[dict[str, Any], dict[str, Any]]:
    validate_fixed_sources()
    positive = make_positive_package()
    negative = make_negative_package(positive)
    return positive, negative


def canonical_json(document: dict[str, Any]) -> str:
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-directory",
        type=pathlib.Path,
        default=ROOT / "vektoren",
        help="destination directory (default: ed301_technischer_abschluss/vektoren)",
    )
    args = parser.parse_args()
    positive, negative = generate_packages()
    args.output_directory.mkdir(parents=True, exist_ok=True)
    outputs = {
        "ed301-sig-v1-positive.json": positive,
        "ed301-sig-v1-negative.json": negative,
    }
    for name, document in outputs.items():
        path = args.output_directory / name
        path.write_text(canonical_json(document), encoding="utf-8")
        print(f"{path}: sha256={sha256_file(path)}")
    print(
        "positive_vectors="
        f"{len(positive['vectors'])} verification_negatives="
        f"{len(negative['verification_vectors'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
