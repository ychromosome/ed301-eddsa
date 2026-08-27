#!/usr/bin/env python3
"""Unabhaengige Ordnungsverifikation per Punktzeuge und Hasse-Eindeutigkeit.

Das Skript verwendet ausschliesslich Python-Integerarithmetik. Es ruft weder
PARI noch dessen Kurvenarithmetik oder Point-Counting-Code auf.
"""

from __future__ import annotations

from math import isqrt


P = (1 << 301) - (1 << 99) + 947
A_MONTGOMERY = 2227159334125704787653500619327586789416272110408090300695513211469626158691878389661638844
B_MONTGOMERY = 2227159334125704787653500619327586789416272110408090300695513211469626158691878389661638846
A2 = A_MONTGOMERY * B_MONTGOMERY % P
A4 = B_MONTGOMERY * B_MONTGOMERY % P
TWIST_Z = 2
A2_TWIST = TWIST_Z * A2 % P
A4_TWIST = TWIST_Z * TWIST_Z * A4 % P

N = 4074071952668972172536891376818756322102936790024709516523088567757405009860459412423203588
Q = 2778806880828370518402978361289226106539992143950047018858348906107
H = 1466122738063207659815884

N_TWIST = 4074071952668972172536891376818756322102936784639035486021471962009519960963485915607182436
Q_TWIST = 4820831355970401167364587956319363065593389810855266651
H_TWIST = 845097380895393028653093414403133036

Point = tuple[int, int] | None


def inv(value: int) -> int:
    return pow(value % P, -1, P)


def legendre(value: int) -> int:
    result = pow(value % P, (P - 1) // 2, P)
    return -1 if result == P - 1 else result


def sqrt_mod(value: int) -> int:
    value %= P
    root = pow(value, (P + 1) // 4, P)
    if root * root % P != value:
        raise ValueError("kein Quadrat")
    return min(root, P - root)


def is_on_curve(point: Point, a2: int, a4: int) -> bool:
    if point is None:
        return True
    x, y = point
    return (y * y - (x * x * x + a2 * x * x + a4 * x)) % P == 0


def add(first: Point, second: Point, a2: int, a4: int) -> Point:
    if first is None:
        return second
    if second is None:
        return first
    x1, y1 = first
    x2, y2 = second
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if first == second:
        if y1 == 0:
            return None
        slope = (3 * x1 * x1 + 2 * a2 * x1 + a4) * inv(2 * y1) % P
    else:
        slope = (y2 - y1) * inv(x2 - x1) % P
    x3 = (slope * slope - a2 - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    result = (x3, y3)
    assert is_on_curve(result, a2, a4)
    return result


def multiply(scalar: int, point: Point, a2: int, a4: int) -> Point:
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = add(result, addend, a2, a4)
        addend = add(addend, addend, a2, a4)
        scalar >>= 1
    return result


def first_affine_point(a2: int, a4: int) -> tuple[int, Point]:
    for x in range(1, 1_000_000):
        rhs = (x * x * x + a2 * x * x + a4 * x) % P
        if rhs and legendre(rhs) == 1:
            point = (x, sqrt_mod(rhs))
            assert is_on_curve(point, a2, a4)
            return x, point
    raise RuntimeError("kein deterministischer Punkt gefunden")


def unique_hasse_multiple(order: int, prime_factor: int) -> tuple[int, int, int]:
    radius = isqrt(4 * P)
    lower = P + 1 - radius
    upper = P + 1 + radius
    first_multiplier = (lower + prime_factor - 1) // prime_factor
    last_multiplier = upper // prime_factor
    assert first_multiplier == last_multiplier
    assert first_multiplier * prime_factor == order
    return lower, upper, first_multiplier


def verify_curve(
    label: str,
    a2: int,
    a4: int,
    order: int,
    prime_factor: int,
    cofactor: int,
) -> None:
    seed_x, seed_point = first_affine_point(a2, a4)
    witness = multiply(cofactor, seed_point, a2, a4)
    assert witness is not None
    assert is_on_curve(witness, a2, a4)
    assert multiply(prime_factor, witness, a2, a4) is None
    lower, upper, multiplier = unique_hasse_multiple(order, prime_factor)
    assert multiplier == cofactor
    print(f"{label}_seed_x={seed_x}")
    print(f"{label}_seed_point={seed_point}")
    print(f"{label}_subgroup_witness={witness}")
    print(f"{label}_q_times_witness=infinity")
    print(f"{label}_hasse_lower={lower}")
    print(f"{label}_hasse_upper={upper}")
    print(f"{label}_unique_multiplier={multiplier}")
    print(f"{label}_verified_order={order}")


def main() -> None:
    assert legendre(TWIST_Z) == -1
    assert N == H * Q
    assert N_TWIST == H_TWIST * Q_TWIST
    assert N + N_TWIST == 2 * P + 2
    verify_curve("curve", A2, A4, N, Q, H)
    verify_curve("twist", A2_TWIST, A4_TWIST, N_TWIST, Q_TWIST, H_TWIST)
    print("independent_order_verification=pass")


if __name__ == "__main__":
    main()
