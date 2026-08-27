#!/usr/bin/env python3
"""Generate deterministic X301-v1 conformance vectors.

This is standard-library-only review tooling.  The traced ladder is checked
against the Python reference, while its affine result is also checked with a
separate general Montgomery group law on the main curve or explicit z=2
twist.  Nothing in this file is production cryptographic software.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "referenz"
if str(REFERENCE) not in sys.path:
    sys.path.insert(0, str(REFERENCE))

import ed301_curve as curve  # noqa: E402
import x301  # noqa: E402


POSITIVE_SCHEMA = "X301-v1-positive-vectors-v1"
NEGATIVE_SCHEMA = "X301-v1-negative-vectors-v1"
SPEC_PATH = ROOT / "spezifikation" / "X301-v1.md"
ED_SPEC_PATH = ROOT / "spezifikation" / "ED301-v1.md"
PARAMETER_PATH = ROOT / "parameter" / "ed301-v1.json"
REFERENCE_PATH = ROOT / "referenz" / "x301.py"
CURVE_PATH = ROOT / "referenz" / "ed301_curve.py"
SOURCE_PATHS = (SPEC_PATH, ED_SPEC_PATH, PARAMETER_PATH, REFERENCE_PATH, CURVE_PATH)

IGNORED_RAW_BITS = (0, 1, 300, 301, 302, 303)
VARIABLE_BITS = tuple(range(2, 300))
TWIST_Z = 2

SECRET_A = bytes(range(38))
SECRET_B = bytes(reversed(range(38)))
SECRET_C = b"\x00" * 38
SECRET_D = b"\xff" * 38
REJECTED_NT_EXAMPLE = bytes.fromhex(
    "5caf05bd7871f4673bd712e08efdb5dddf8ca4ffffffffffffffffffffffffffffffffffff1f"
)


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_records() -> list[dict[str, str]]:
    return [
        {"path": str(path.relative_to(ROOT)), "sha256": sha256_file(path)}
        for path in SOURCE_PATHS
    ]


def integer_value(value: int, *, le38: bool = False) -> dict[str, str]:
    result = {"decimal": str(value), "hex_be": format(value, "x")}
    if le38:
        result["encoding_le38_hex"] = value.to_bytes(38, "little").hex()
    return result


def clamp_without_rejection(secret: bytes) -> bytes:
    if type(secret) is not bytes or len(secret) != 38:
        raise ValueError("secret must be exactly 38 bytes")
    result = bytearray(secret)
    result[0] &= 0xFC
    result[37] = (result[37] & 0x0F) | 0x10
    return bytes(result)


def raw_preimages(clamped: bytes) -> list[bytes]:
    if len(clamped) != 38:
        raise ValueError("clamped scalar must be 38 bytes")
    value = int.from_bytes(clamped, "little")
    ignored_mask = sum(1 << bit for bit in IGNORED_RAW_BITS)
    base = value & ~ignored_mask
    outputs = []
    for selection in range(1 << len(IGNORED_RAW_BITS)):
        raw = base
        for index, bit in enumerate(IGNORED_RAW_BITS):
            if selection >> index & 1:
                raw |= 1 << bit
        outputs.append(raw.to_bytes(38, "little"))
    if len(set(outputs)) != 64:
        raise AssertionError("ignored-bit enumeration did not yield 64 preimages")
    return outputs


def traced_ladder(scalar: int, u: int) -> tuple[int, int, int]:
    """Literal §7 ladder with an observable iteration counter."""

    if not (1 << 300) <= scalar <= (1 << 301) - 4 or scalar & 3:
        raise ValueError("scalar is outside the X301 clamp set")
    if scalar == x301.N_TWIST or not 0 <= u < curve.P:
        raise ValueError("invalid X301 ladder input")
    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0
    iterations = 0
    for bit_index in range(300, -1, -1):
        iterations += 1
        bit = (scalar >> bit_index) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit

        add = (x2 + z2) % curve.P
        aa = add * add % curve.P
        subtract = (x2 - z2) % curve.P
        bb = subtract * subtract % curve.P
        e = (aa - bb) % curve.P
        c = (x3 + z3) % curve.P
        d = (x3 - z3) % curve.P
        da = d * add % curve.P
        cb = c * subtract % curve.P
        x3 = (da + cb) ** 2 % curve.P
        z3 = x1 * (da - cb) ** 2 % curve.P
        x2 = aa * bb % curve.P
        z2 = e * (aa + curve.A24_MINUS * e) % curve.P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return x2, z2, iterations


AffinePoint = tuple[int, int] | None


def _sqrt_even(value: int) -> int:
    root = pow(value % curve.P, (curve.P + 1) // 4, curve.P)
    if root * root % curve.P != value % curve.P:
        raise ValueError("not a square")
    return root if root & 1 == 0 else curve.P - root


def classify_u_and_recover(u: int) -> tuple[str, int, tuple[int, int]]:
    """Return model name, coefficient C and a point on C*v²=f(u)."""

    rhs = (u**3 + curve.A_MONTGOMERY * u * u + u) % curve.P
    if rhs == 0:
        raise ValueError("torsion u has no positive-vector affine cross-check")
    main_v2 = rhs * pow(curve.B_MONTGOMERY, curve.P - 2, curve.P) % curve.P
    symbol = pow(main_v2, (curve.P - 1) // 2, curve.P)
    if symbol == 1:
        model = "main"
        coefficient = curve.B_MONTGOMERY
    elif symbol == curve.P - 1:
        model = "twist-z2"
        coefficient = TWIST_Z * curve.B_MONTGOMERY % curve.P
    else:
        raise AssertionError("unexpected quadratic-character result")
    v2 = rhs * pow(coefficient, curve.P - 2, curve.P) % curve.P
    point = (u, _sqrt_even(v2))
    if (coefficient * point[1] * point[1] - rhs) % curve.P:
        raise AssertionError("recovered Montgomery point is inconsistent")
    return model, coefficient, point


def affine_add(left: AffinePoint, right: AffinePoint, coefficient: int) -> AffinePoint:
    """Independent general group law for C*v²=u³+A*u²+u."""

    if left is None:
        return right
    if right is None:
        return left
    u1, v1 = left
    u2, v2 = right
    if u1 == u2:
        if (v1 + v2) % curve.P == 0:
            return None
        denominator = 2 * coefficient * v1 % curve.P
        slope = (3 * u1 * u1 + 2 * curve.A_MONTGOMERY * u1 + 1)
    else:
        denominator = (u2 - u1) % curve.P
        slope = (v2 - v1) % curve.P
    if denominator == 0:
        return None
    slope = slope * pow(denominator, curve.P - 2, curve.P) % curve.P
    u3 = (coefficient * slope * slope - curve.A_MONTGOMERY - u1 - u2) % curve.P
    v3 = (-v1 - slope * (u3 - u1)) % curve.P
    rhs = (u3**3 + curve.A_MONTGOMERY * u3 * u3 + u3) % curve.P
    if coefficient * v3 * v3 % curve.P != rhs:
        raise AssertionError("general Montgomery addition left its model")
    return u3, v3


def affine_multiply(scalar: int, point: tuple[int, int], coefficient: int) -> AffinePoint:
    result: AffinePoint = None
    addend: AffinePoint = point
    while scalar:
        if scalar & 1:
            result = affine_add(result, addend, coefficient)
        addend = affine_add(addend, addend, coefficient)
        scalar >>= 1
    return result


def positive_vector(
    vector_id: str,
    operation: str,
    secret: bytes,
    input_u_encoding: bytes,
    description: str,
) -> dict[str, Any]:
    clamped = x301.clamp_secret_bytes(secret)
    scalar = x301.decode_secret_scalar(secret)
    input_u = curve.decode_field(input_u_encoding)
    x_projective, z_projective, iterations = traced_ladder(scalar, input_u)
    reference_projective = curve.montgomery_ladder_projective(scalar, input_u)
    if (x_projective, z_projective) != reference_projective:
        raise AssertionError("traced and reference ladders disagree")
    if iterations != 301 or z_projective == 0:
        raise AssertionError("positive ladder did not produce a finite 301-round result")
    affine_u = x_projective * pow(z_projective, curve.P - 2, curve.P) % curve.P
    encoded_output = curve.encode_field(affine_u)
    if operation == "Public":
        if input_u_encoding != x301.BASE_U_ENCODING:
            raise AssertionError("Public vector does not use BASE_U")
        reference_output = x301.public_from_secret(secret)
    elif operation in ("Shared", "X301"):
        reference_output = x301.shared_secret(secret, input_u_encoding)
    else:
        raise ValueError("unknown positive operation")
    if encoded_output != reference_output:
        raise AssertionError("traced ladder and X301 reference disagree")

    model, coefficient, input_point = classify_u_and_recover(input_u)
    independent_result = affine_multiply(scalar, input_point, coefficient)
    if independent_result is None or independent_result[0] != affine_u:
        raise AssertionError("general point multiplication and x-only ladder disagree")

    crosscheck: dict[str, Any] = {
        "method": "independent-general-affine-Montgomery-group-law",
        "model": model,
        "model_coefficient_C": integer_value(coefficient),
        "input_point_u": integer_value(input_point[0]),
        "input_point_v_even": integer_value(input_point[1]),
        "result_u": integer_value(independent_result[0], le38=True),
        "matches_ladder": True,
    }
    if input_u == x301.BASE_U:
        edwards_result = curve.scalar_multiply(scalar, curve.G)
        edwards_u = curve.edwards_to_montgomery(edwards_result)[0]
        if edwards_u != affine_u:
            raise AssertionError("general Edwards multiplication and ladder disagree")
        crosscheck["additional_method"] = "general-affine-twisted-Edwards-group-law"
        crosscheck["additional_edwards_result_u"] = integer_value(edwards_u, le38=True)

    return {
        "id": vector_id,
        "description": description,
        "operation": operation,
        "secret_input_hex": secret.hex(),
        "clamped_scalar_bytes_hex": clamped.hex(),
        "scalar_k": integer_value(scalar, le38=True),
        "input_u": {
            "decimal": str(input_u),
            "hex_be": format(input_u, "x"),
            "encoding_le38_hex": input_u_encoding.hex(),
            "model": model,
        },
        "ladder": {
            "iteration_count_decimal": str(iterations),
            "projective_X": integer_value(x_projective),
            "projective_Z": integer_value(z_projective),
            "affine_u": integer_value(affine_u, le38=True),
        },
        "independent_crosscheck": crosscheck,
        "output_encoding_hex": encoded_output.hex(),
        "expected": "success",
    }


def validate_sources() -> None:
    params = json.loads(PARAMETER_PATH.read_text(encoding="utf-8"))
    if int(params["field"]["p_decimal"]) != x301.P:
        raise RuntimeError("parameter p and X301 reference disagree")
    if int(params["group"]["order_N_decimal"]) != x301.N:
        raise RuntimeError("parameter N and X301 reference disagree")
    if int(params["twist"]["order_decimal"]) != x301.N_TWIST:
        raise RuntimeError("parameter N_t and X301 reference disagree")
    if int(params["basepoint"]["G_montgomery_u_decimal"]) != x301.BASE_U:
        raise RuntimeError("parameter BASE_U and X301 reference disagree")
    if not x301.verify_parameters():
        raise RuntimeError("X301 reference parameter self-check failed")
    specification = SPEC_PATH.read_text(encoding="utf-8")
    for fixed in ("298 variable Bits", "301 Iterationen", x301.BASE_U_ENCODING.hex()):
        if fixed not in specification:
            raise RuntimeError(f"X301 specification marker absent: {fixed}")


def make_clamp_analysis() -> dict[str, Any]:
    minimum = x301.clamp_secret_bytes(SECRET_C)
    maximum = x301.clamp_secret_bytes(SECRET_D)
    minimum_k = int.from_bytes(minimum, "little")
    maximum_k = int.from_bytes(maximum, "little")
    if minimum_k != 1 << 300 or maximum_k != (1 << 301) - 4:
        raise AssertionError("clamp boundary mismatch")

    representative_clamped = x301.clamp_secret_bytes(SECRET_A)
    preimages = raw_preimages(representative_clamped)
    outputs = {x301.clamp_secret_bytes(raw) for raw in preimages}
    if outputs != {representative_clamped}:
        raise AssertionError("the 64 raw preimages do not share one clamped scalar")
    common_public = {x301.public_from_secret(raw) for raw in preimages}
    if len(common_public) != 1:
        raise AssertionError("ignored raw bits changed Public")

    baseline = int.from_bytes(representative_clamped, "little")
    changed_deltas = []
    for bit in VARIABLE_BITS:
        toggled = baseline ^ (1 << bit)
        delta = abs(toggled - baseline)
        if delta != 1 << bit:
            raise AssertionError("variable-bit proof failed")
        changed_deltas.append(str(delta))
    return {
        "clamp_formula": "k = 2^300 + 4*n; 0 <= n < 2^298",
        "variable_bit_positions": [2, 299],
        "variable_bit_count_decimal": str(len(VARIABLE_BITS)),
        "variable_bit_flip_deltas_decimal": changed_deltas,
        "ignored_or_overwritten_raw_bit_positions": list(IGNORED_RAW_BITS),
        "ignored_raw_bit_count_decimal": str(len(IGNORED_RAW_BITS)),
        "raw_preimage_count_decimal": str(len(preimages)),
        "raw_preimages_hex": [item.hex() for item in preimages],
        "common_clamped_bytes_hex": representative_clamped.hex(),
        "common_scalar_k": integer_value(baseline, le38=True),
        "common_public_hex": next(iter(common_public)).hex(),
        "minimum_clamp": {
            "raw_secret_hex": SECRET_C.hex(),
            "clamped_bytes_hex": minimum.hex(),
            "k": integer_value(minimum_k, le38=True),
        },
        "maximum_clamp": {
            "raw_secret_hex": SECRET_D.hex(),
            "clamped_bytes_hex": maximum.hex(),
            "k": integer_value(maximum_k, le38=True),
        },
    }


def make_positive_package() -> dict[str, Any]:
    public_a = x301.public_from_secret(SECRET_A)
    public_b = x301.public_from_secret(SECRET_B)
    public_c = x301.public_from_secret(SECRET_C)
    public_d = x301.public_from_secret(SECRET_D)
    cases = [
        ("public-a-section-13", "Public", SECRET_A, x301.BASE_U_ENCODING, "Section 13 party A public key."),
        ("public-b-section-13", "Public", SECRET_B, x301.BASE_U_ENCODING, "Section 13 party B public key."),
        ("public-clamp-minimum", "Public", SECRET_C, x301.BASE_U_ENCODING, "Minimum clamped scalar 2^300."),
        ("public-clamp-maximum", "Public", SECRET_D, x301.BASE_U_ENCODING, "Maximum clamped scalar 2^301-4."),
        ("shared-a-with-b", "Shared", SECRET_A, public_b, "Section 13 A-to-B shared result."),
        ("shared-b-with-a", "Shared", SECRET_B, public_a, "Section 13 B-to-A shared result."),
        ("shared-c-with-d", "Shared", SECRET_C, public_d, "Second mutual agreement, C-to-D."),
        ("shared-d-with-c", "Shared", SECRET_D, public_c, "Second mutual agreement, D-to-C."),
        ("twist-u2-secret-a", "X301", SECRET_A, curve.encode_field(2), "Canonical explicit z=2 twist input u=2."),
        ("twist-u2-secret-b", "X301", SECRET_B, curve.encode_field(2), "Second scalar on explicit z=2 twist input u=2."),
    ]
    vectors = [positive_vector(*case) for case in cases]
    by_id = {item["id"]: item for item in vectors}
    agreement_pairs = [
        {
            "id": "agreement-a-b-section-13",
            "a_to_b_vector": "shared-a-with-b",
            "b_to_a_vector": "shared-b-with-a",
            "shared_encoding_hex": by_id["shared-a-with-b"]["output_encoding_hex"],
        },
        {
            "id": "agreement-c-d",
            "a_to_b_vector": "shared-c-with-d",
            "b_to_a_vector": "shared-d-with-c",
            "shared_encoding_hex": by_id["shared-c-with-d"]["output_encoding_hex"],
        },
    ]
    for pair in agreement_pairs:
        if by_id[pair["a_to_b_vector"]]["output_encoding_hex"] != pair["shared_encoding_hex"]:
            raise AssertionError("first agreement direction mismatch")
        if by_id[pair["b_to_a_vector"]]["output_encoding_hex"] != pair["shared_encoding_hex"]:
            raise AssertionError("second agreement direction mismatch")
    return {
        "schema": POSITIVE_SCHEMA,
        "status": "reference-conformance-vectors-not-production-audited",
        "suite": "X301-v1",
        "encoding_conventions": {
            "bytes": "lowercase hexadecimal without 0x",
            "integers_decimal": "base-10 strings",
            "integers_hex_be": "minimal lowercase big-endian magnitude without 0x",
            "field_and_scalar_encodings": "exactly 38-byte little-endian hexadecimal",
        },
        "sources": source_records(),
        "clamp_analysis": make_clamp_analysis(),
        "positive_vector_count_decimal": str(len(vectors)),
        "agreement_pair_count_decimal": str(len(agreement_pairs)),
        "agreement_pairs": agreement_pairs,
        "vectors": vectors,
    }


def negative_api_case(
    vector_id: str,
    operation: str,
    reason: str,
    rejection_stage: str,
    *,
    secret_hex: str | None = None,
    secret_type: str = "bytes",
    u_hex: str | None = None,
    u_type: str = "bytes",
) -> dict[str, Any]:
    return {
        "id": vector_id,
        "operation": operation,
        "reason": reason,
        "rejection_stage": rejection_stage,
        "secret": {"type": secret_type, "hex": secret_hex},
        "u_input": {"type": u_type, "hex": u_hex},
        "expected": "FAIL",
    }


def execute_negative_api_case(item: dict[str, Any]) -> None:
    secret_record = item["secret"]
    if secret_record["type"] == "bytes":
        secret: Any = bytes.fromhex(secret_record["hex"])
    elif secret_record["type"] == "str":
        secret = secret_record["hex"]
    else:
        raise AssertionError("unknown test secret type")
    u_record = item["u_input"]
    if u_record["type"] == "bytes":
        u: Any = None if u_record["hex"] is None else bytes.fromhex(u_record["hex"])
    elif u_record["type"] == "str":
        u = u_record["hex"]
    else:
        raise AssertionError("unknown test u type")
    try:
        if item["operation"] == "Public":
            x301.public_from_secret(secret)
        elif item["operation"] in ("Shared", "X301"):
            x301.shared_secret(secret, u)
        else:
            raise AssertionError("unknown negative operation")
    except (AssertionError, TypeError, ValueError):
        return
    raise AssertionError(f"negative API vector unexpectedly succeeded: {item['id']}")


def make_negative_package() -> dict[str, Any]:
    good_secret = SECRET_A.hex()
    base_u = x301.BASE_U_ENCODING.hex()
    nt_preimages = raw_preimages(x301.N_TWIST.to_bytes(38, "little"))
    if REJECTED_NT_EXAMPLE not in nt_preimages:
        raise AssertionError("the normative N_t preimage was not enumerated")
    selected_nt = [REJECTED_NT_EXAMPLE] + [
        value for value in nt_preimages if value != REJECTED_NT_EXAMPLE
    ][:3]
    for raw in nt_preimages:
        if int.from_bytes(clamp_without_rejection(raw), "little") != x301.N_TWIST:
            raise AssertionError("N_t raw preimage enumeration failed")

    reserved_encodings = {}
    for bit in (301, 302, 303):
        encoded = bytearray(x301.BASE_U_ENCODING)
        encoded[bit // 8] |= 1 << (bit % 8)
        reserved_encodings[bit] = bytes(encoded)

    cases = [
        negative_api_case("secret-length-37", "Public", "Secret has 37 bytes.", "secret-length", secret_hex=good_secret[:-2], u_hex=None),
        negative_api_case("secret-length-39", "Public", "Secret has 39 bytes.", "secret-length", secret_hex=good_secret + "00", u_hex=None),
        negative_api_case("secret-not-bytes", "Public", "Secret is a text value, not bytes.", "secret-type", secret_hex=good_secret, secret_type="str", u_hex=None),
    ]
    for index, raw in enumerate(selected_nt):
        cases.append(
            negative_api_case(
                f"secret-clamps-to-Nt-preimage-{index}",
                "Public" if index == 0 else "Shared",
                "Raw secret clamps to the excluded twist order N_t.",
                "decode-scalar-Nt",
                secret_hex=raw.hex(),
                u_hex=None if index == 0 else base_u,
            )
        )
    cases.extend(
        [
            negative_api_case("u-length-37", "Shared", "u input has 37 bytes.", "u-length", secret_hex=good_secret, u_hex=base_u[:-2]),
            negative_api_case("u-length-39", "Shared", "u input has 39 bytes.", "u-length", secret_hex=good_secret, u_hex=base_u + "00"),
            negative_api_case("u-not-bytes", "Shared", "u input is text, not bytes.", "u-type", secret_hex=good_secret, u_hex=base_u, u_type="str"),
            negative_api_case("u-reserved-bit-301", "Shared", "Reserved u bit 301 is set.", "decode-u-reserved-bits", secret_hex=good_secret, u_hex=reserved_encodings[301].hex()),
            negative_api_case("u-reserved-bit-302", "Shared", "Reserved u bit 302 is set.", "decode-u-reserved-bits", secret_hex=good_secret, u_hex=reserved_encodings[302].hex()),
            negative_api_case("u-reserved-bit-303", "Shared", "Reserved u bit 303 is set.", "decode-u-reserved-bits", secret_hex=good_secret, u_hex=reserved_encodings[303].hex()),
            negative_api_case("u-equal-p", "Shared", "u=p is noncanonical.", "decode-u-range", secret_hex=good_secret, u_hex=curve.P.to_bytes(38, "little").hex()),
            negative_api_case("u-equal-p-plus-1", "Shared", "u=p+1 is above the field range.", "decode-u-range", secret_hex=good_secret, u_hex=(curve.P + 1).to_bytes(38, "little").hex()),
            negative_api_case("u-zero", "Shared", "u=0 is rational cofactor torsion.", "ladder-Z-zero", secret_hex=good_secret, u_hex=curve.encode_field(0).hex()),
            negative_api_case("u-one", "Shared", "u=1 is the rational order-4 case.", "ladder-Z-zero", secret_hex=good_secret, u_hex=curve.encode_field(1).hex()),
            negative_api_case("u-p-minus-1", "Shared", "u=p-1 is a twist cofactor-torsion input.", "ladder-Z-zero", secret_hex=good_secret, u_hex=curve.encode_field(curve.P - 1).hex()),
        ]
    )
    for item in cases:
        execute_negative_api_case(item)

    parser_cases = [
        {
            "id": "outer-parser-wrong-suite",
            "suite": "X301-v2",
            "version_decimal": "1",
            "secret_hex": good_secret,
            "u_hex": base_u,
            "rejection_stage": "outer-parser-suite-selection",
            "expected": "FAIL-before-X301",
        },
        {
            "id": "outer-parser-wrong-version",
            "suite": "X301-v1",
            "version_decimal": "2",
            "secret_hex": good_secret,
            "u_hex": base_u,
            "rejection_stage": "outer-parser-version-selection",
            "expected": "FAIL-before-X301",
        },
    ]
    return {
        "schema": NEGATIVE_SCHEMA,
        "status": "reference-conformance-vectors-not-production-audited",
        "suite": "X301-v1",
        "sources": source_records(),
        "api_vector_count_decimal": str(len(cases)),
        "api_vectors": cases,
        "outer_parser_vector_count_decimal": str(len(parser_cases)),
        "outer_parser_vectors": parser_cases,
        "excluded_Nt_preimage_proof": {
            "N_t": integer_value(x301.N_TWIST, le38=True),
            "raw_preimage_count_decimal": str(len(nt_preimages)),
            "raw_preimages_hex": [item.hex() for item in nt_preimages],
            "ordinary_negative_vector_ids": [
                f"secret-clamps-to-Nt-preimage-{index}" for index in range(len(selected_nt))
            ],
        },
        "internal_only": {
            "classification": "Fault-injection and KeyGen control-flow tests; not ordinary X301 input vectors.",
            "keygen_retry": {
                "id": "internal-keygen-retry-after-Nt",
                "random_draws_hex": [REJECTED_NT_EXAMPLE.hex(), SECRET_A.hex()],
                "expected_draw_count_decimal": "2",
                "expected_secret_hex": SECRET_A.hex(),
                "expected_public_hex": x301.public_from_secret(SECRET_A).hex(),
            },
            "all_zero_rejection": {
                "id": "internal-finite-zero-output-fault",
                "injected_ladder_affine_u_decimal": "0",
                "expected_rejection_stage": "post-ladder-AllZero",
                "expected": "FAIL-without-output",
            },
        },
    }


def generate_packages() -> tuple[dict[str, Any], dict[str, Any]]:
    validate_sources()
    return make_positive_package(), make_negative_package()


def canonical_json(document: dict[str, Any]) -> str:
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-directory", type=pathlib.Path, default=ROOT / "vektoren"
    )
    args = parser.parse_args()
    positive, negative = generate_packages()
    args.output_directory.mkdir(parents=True, exist_ok=True)
    outputs = {
        "x301-v1-positive.json": positive,
        "x301-v1-negative.json": negative,
    }
    for name, document in outputs.items():
        path = args.output_directory / name
        path.write_text(canonical_json(document), encoding="utf-8")
        print(f"{path}: sha256={sha256_file(path)}")
    print(
        f"positive_vectors={len(positive['vectors'])} "
        f"api_negatives={len(negative['api_vectors'])} "
        f"parser_negatives={len(negative['outer_parser_vectors'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
