#!/usr/bin/env python3
"""Deterministic, non-constant-time basepoint derivation for ED301 c=44730.

This is an auditable parameter-generation script, not production arithmetic.
It uses only Python's standard library and prints every attempted hash-and-
increment intermediate through the first accepted counter.
"""

import hashlib
import math
import platform


P_MODULUS = (1 << 301) - (1 << 99) + 947
CURVE_D = 301
CANDIDATE_COUNTER = 44730
CURVE_S = 947 + CANDIDATE_COUNTER
CURVE_A = CURVE_S * CURVE_S % P_MODULUS
COFACTOR = 4
SUBGROUP_Q = 1018517988167243043134222844204689080525734197342817290458622896758534223469429834039334403
CURVE_ORDER = COFACTOR * SUBGROUP_Q

DST = b"ED301-BASEPOINT-DERIVATION-v1"
XOF_LENGTH = 38
COUNTER_LENGTH = 4
IDENTITY = (0, 1)


def inverse(z):
    z %= P_MODULUS
    if z == 0:
        raise ZeroDivisionError("inverse of zero")
    return pow(z, P_MODULUS - 2, P_MODULUS)


def is_on_curve(point):
    x, y = point
    x2 = x * x % P_MODULUS
    y2 = y * y % P_MODULUS
    return (CURVE_A * x2 + y2 - 1 - CURVE_D * x2 * y2) % P_MODULUS == 0


def point_add(p1, p2):
    x1, y1 = p1
    x2, y2 = p2
    product = CURVE_D * x1 * x2 * y1 * y2 % P_MODULUS
    denominator_x = (1 + product) % P_MODULUS
    denominator_y = (1 - product) % P_MODULUS
    if denominator_x == 0 or denominator_y == 0:
        raise ArithmeticError("complete Edwards denominator unexpectedly vanished")
    x3 = (x1 * y2 + y1 * x2) * inverse(denominator_x) % P_MODULUS
    y3 = (y1 * y2 - CURVE_A * x1 * x2) * inverse(denominator_y) % P_MODULUS
    result = (x3, y3)
    if not is_on_curve(result):
        raise ArithmeticError("addition produced an off-curve point")
    return result


def scalar_multiply(scalar, point):
    if scalar < 0:
        raise ValueError("negative scalar")
    result = IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def recover_even_x(y):
    y2 = y * y % P_MODULUS
    numerator = (1 - y2) % P_MODULUS
    denominator = (CURVE_A - CURVE_D * y2) % P_MODULUS
    details = {
        "y_squared": y2,
        "x2_numerator": numerator,
        "x2_denominator": denominator,
    }
    if denominator == 0:
        details["reason"] = "zero_x2_denominator"
        return None, details
    x_squared = numerator * inverse(denominator) % P_MODULUS
    root = pow(x_squared, (P_MODULUS + 1) // 4, P_MODULUS)
    details["x_squared"] = x_squared
    details["sqrt_candidate"] = root
    details["sqrt_candidate_lsb"] = root & 1
    if root * root % P_MODULUS != x_squared:
        details["reason"] = "x_squared_is_nonsquare"
        return None, details
    x = root if root & 1 == 0 else P_MODULUS - root
    details["selected_even_x"] = x
    details["selected_x_lsb"] = x & 1
    return x, details


def encode_field_le(value):
    if not 0 <= value < P_MODULUS:
        raise ValueError("non-canonical field value")
    encoded = value.to_bytes(38, "little")
    if encoded[37] & 0xE0:
        raise AssertionError("field encoding has a bit above position 300")
    return encoded


def encode_edwards(point):
    x, y = point
    encoded = bytearray(encode_field_le(y))
    encoded[37] |= (x & 1) << 7
    if encoded[37] & 0x60:
        raise AssertionError("reserved point-encoding bits are nonzero")
    return bytes(encoded)


def decode_edwards(encoded):
    if len(encoded) != 38 or encoded[37] & 0x60:
        raise ValueError("invalid length or reserved bits")
    sign = encoded[37] >> 7
    y_bytes = bytearray(encoded)
    y_bytes[37] &= 0x1F
    y = int.from_bytes(y_bytes, "little")
    if y >= P_MODULUS:
        raise ValueError("non-canonical y")
    x_even, _ = recover_even_x(y)
    if x_even is None:
        raise ValueError("y has no Edwards point")
    if x_even == 0 and sign != 0:
        raise ValueError("non-canonical sign for x=0")
    x = x_even if x_even & 1 == sign else P_MODULUS - x_even
    point = (x, y)
    if not is_on_curve(point):
        raise ValueError("decoded point is off curve")
    return point


def edwards_to_montgomery(point):
    x, y = point
    if x == 0 or y == 1:
        raise ValueError("exceptional Edwards point for Montgomery map")
    u = (1 + y) * inverse(1 - y) % P_MODULUS
    v = u * inverse(x) % P_MODULUS
    return u, v


def montgomery_to_edwards(point):
    u, v = point
    if v == 0 or u == P_MODULUS - 1:
        raise ValueError("exceptional Montgomery point for Edwards map")
    x = u * inverse(v) % P_MODULUS
    y = (u - 1) * inverse(u + 1) % P_MODULUS
    return x, y


def derive_basepoint():
    for counter in range(1 << (8 * COUNTER_LENGTH)):
        counter_bytes = counter.to_bytes(COUNTER_LENGTH, "big")
        hash_input = DST + counter_bytes
        raw = hashlib.shake_256(hash_input).digest(XOF_LENGTH)
        masked = bytearray(raw)
        masked[37] &= 0x1F
        y = int.from_bytes(masked, "little")

        print(f"attempt_counter={counter}")
        print(f"attempt_counter_be_hex={counter_bytes.hex()}")
        print(f"attempt_hash_input_hex={hash_input.hex()}")
        print(f"attempt_shake256_38_raw_hex={raw.hex()}")
        print(f"attempt_masked_301bit_le_hex={bytes(masked).hex()}")
        print(f"attempt_y={y}")

        if y >= P_MODULUS:
            print("attempt_result=reject_y_ge_p")
            continue
        x, details = recover_even_x(y)
        for key, value in details.items():
            print(f"attempt_{key}={value}")
        if x is None:
            print(f"attempt_result=reject_{details['reason']}")
            continue
        candidate = (x, y)
        if not is_on_curve(candidate):
            raise AssertionError("reconstructed candidate is off curve")
        cleared = scalar_multiply(COFACTOR, candidate)
        print(f"attempt_candidate_P_x={candidate[0]}")
        print(f"attempt_candidate_P_y={candidate[1]}")
        print(f"attempt_candidate_P_x_lsb={candidate[0] & 1}")
        print(f"attempt_cleared_G_x={cleared[0]}")
        print(f"attempt_cleared_G_y={cleared[1]}")
        if cleared == IDENTITY:
            print("attempt_result=reject_identity_after_cofactor_clearing")
            continue
        if scalar_multiply(SUBGROUP_Q, cleared) != IDENTITY:
            raise AssertionError("cofactor-cleared point is not in the q subgroup")
        print("attempt_result=accept_first_valid_counter")
        return counter, raw, bytes(masked), candidate, cleared
    raise RuntimeError("all 32-bit counters exhausted")


def main():
    if CURVE_A != 2086388329:
        raise AssertionError("unexpected c44730 parameter a")
    if CURVE_ORDER != 4074071952668972172536891376818756322102936789371269161834491587034136893877719336157337612:
        raise AssertionError("unexpected c44730 curve order")
    if P_MODULUS % 4 != 3 or math.gcd(COFACTOR, SUBGROUP_Q) != 1:
        raise AssertionError("parameter precondition failed")

    sample_space = 1 << 301
    field_rejections = sample_space - P_MODULUS
    print(f"python_version={platform.python_version()}")
    print(f"p={P_MODULUS}")
    print(f"curve_candidate_c={CANDIDATE_COUNTER}")
    print(f"curve_s={CURVE_S}")
    print(f"a={CURVE_A}")
    print(f"d={CURVE_D}")
    print(f"N={CURVE_ORDER}")
    print(f"h={COFACTOR}")
    print(f"q={SUBGROUP_Q}")
    print(f"gcd_h_q={math.gcd(COFACTOR, SUBGROUP_Q)}")
    print(f"dst_ascii={DST.decode('ascii')}")
    print(f"dst_hex={DST.hex()}")
    print(f"dst_length={len(DST)}")
    print("hash_input_framing=DST || I2OSP(counter,4,big-endian)")
    print("counter_start=0")
    print("counter_end_inclusive=4294967295")
    print(f"shake256_output_length={XOF_LENGTH}")
    print("candidate_interpretation=mask out[37] with 0x1f, then OS2IP-little-endian")
    print("candidate_acceptance=accept only y<p; otherwise increment counter")
    print(f"candidate_sample_space_size={sample_space}")
    print(f"candidate_field_rejection_count={field_rejections}")
    print("candidate_field_rejection_probability_exact=(2^99-947)/2^301")
    print("candidate_field_rejection_probability_bound=<2^-202")
    print(f"candidate_field_rejection_probability_log2_approx={math.log2(field_rejections) - 301:.17f}")
    print("candidate_bias=zero; masking is uniform on 301-bit integers and rejection is uniform on F_p")
    print("candidate_x_sign_rule=select the unique square root with canonical integer LSB 0")
    print("cofactor_clearing=[4]P")

    counter, raw, masked, candidate, basepoint = derive_basepoint()
    x, y = basepoint
    q_times_g = scalar_multiply(SUBGROUP_Q, basepoint)
    four_times_p = scalar_multiply(COFACTOR, candidate)
    encoded = encode_edwards(basepoint)
    decoded = decode_edwards(encoded)

    A = 2 * (CURVE_A + CURVE_D) * inverse(CURVE_A - CURVE_D) % P_MODULUS
    B = 4 * inverse(CURVE_A - CURVE_D) % P_MODULUS
    u, v = edwards_to_montgomery(basepoint)
    montgomery_equation = (B * v * v - (u * u * u + A * u * u + u)) % P_MODULUS
    inverse_map = montgomery_to_edwards((u, v))

    print(f"selected_counter={counter}")
    print(f"selected_shake256_38_raw_hex={raw.hex()}")
    print(f"selected_masked_301bit_le_hex={masked.hex()}")
    print(f"candidate_P_x={candidate[0]}")
    print(f"candidate_P_y={candidate[1]}")
    print(f"G_x={x}")
    print(f"G_y={y}")
    print(f"G_x_hex_be_38={x:076x}")
    print(f"G_y_hex_be_38={y:076x}")
    print(f"G_x_le_38={encode_field_le(x).hex()}")
    print(f"G_y_le_38={encode_field_le(y).hex()}")
    print(f"G_x_lsb={x & 1}")
    print(f"G_is_on_curve={int(is_on_curve(basepoint))}")
    print(f"G_is_identity={int(basepoint == IDENTITY)}")
    print(f"four_P_equals_G={int(four_times_p == basepoint)}")
    print(f"q_times_G_x={q_times_g[0]}")
    print(f"q_times_G_y={q_times_g[1]}")
    print(f"q_times_G_is_identity={int(q_times_g == IDENTITY)}")
    print("G_exact_order_q=1")
    print(f"G_compressed_edwards_38_hex={encoded.hex()}")
    print(f"G_compressed_edwards_length={len(encoded)}")
    print(f"G_compressed_sign_bit={(encoded[37] >> 7) & 1}")
    print(f"G_compressed_reserved_bits_zero={int((encoded[37] & 0x60) == 0)}")
    print(f"G_compressed_roundtrip={int(decoded == basepoint)}")
    print(f"montgomery_A={A}")
    print(f"montgomery_B={B}")
    print(f"G_montgomery_u={u}")
    print(f"G_montgomery_v={v}")
    print(f"G_montgomery_u_hex_be_38={u:076x}")
    print(f"G_montgomery_v_hex_be_38={v:076x}")
    print(f"G_montgomery_u_le_38={encode_field_le(u).hex()}")
    print(f"G_montgomery_v_le_38={encode_field_le(v).hex()}")
    print(f"G_montgomery_equation_pass={int(montgomery_equation == 0)}")
    print(f"G_montgomery_inverse_map_pass={int(inverse_map == basepoint)}")

    final_checks = [
        is_on_curve(candidate),
        is_on_curve(basepoint),
        basepoint != IDENTITY,
        q_times_g == IDENTITY,
        four_times_p == basepoint,
        decoded == basepoint,
        montgomery_equation == 0,
        inverse_map == basepoint,
    ]
    print(f"all_basepoint_checks_pass={int(all(final_checks))}")
    raise SystemExit(0 if all(final_checks) else 1)


if __name__ == "__main__":
    main()
