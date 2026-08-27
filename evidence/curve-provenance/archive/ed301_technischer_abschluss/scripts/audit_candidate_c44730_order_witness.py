#!/usr/bin/env python3
"""Unabhaengiger Ordnungsnachweis fuer den ED301-Kandidaten c=44730.

Dieses Skript verwendet nur Python-Integerarithmetik. Es importiert weder
PARI noch eine andere Kurvenbibliothek und benutzt keinen Point-Counting-Code.

Fuer Kurve und quadratischen Twist wird ein nichttrivialer Punkt Q mit
[q]Q = O konstruiert. Da im jeweiligen Hasse-Intervall genau ein Vielfaches
der separat ECPP-zertifizierten Primzahl q liegt, ist die Gruppenordnung
dadurch eindeutig bestimmt.
"""

from __future__ import annotations

from math import isqrt


P = (1 << 301) - (1 << 99) + 947
D_EDWARDS = 301
C = 44730
S = 947 + C
A_EDWARDS = S * S % P

A_MONTGOMERY = 2 * (A_EDWARDS + D_EDWARDS) * pow(
    A_EDWARDS - D_EDWARDS, -1, P
) % P
B_MONTGOMERY = 4 * pow(A_EDWARDS - D_EDWARDS, -1, P) % P

# B*v^2 = u^3 + A*u^2 + u wird mit X=B*u, Y=B^2*v zu
# Y^2 = X^3 + (A*B)X^2 + B^2*X skaliert.
A2 = A_MONTGOMERY * B_MONTGOMERY % P
A4 = B_MONTGOMERY * B_MONTGOMERY % P

TWIST_Z = 2
A2_TWIST = TWIST_Z * A2 % P
A4_TWIST = TWIST_Z * TWIST_Z * A4 % P

Q = 1018517988167243043134222844204689080525734197342817290458622896758534223469429834039334403
N = 4 * Q
Q_TWIST = 1018517988167243043134222844204689080525734196323118960177517235683197019236556497968262103
N_TWIST = 4 * Q_TWIST

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
    # floor(2*sqrt(p)) liefert einen sicheren ganzzahligen Hasse-Radius.
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
) -> None:
    seed_x, seed_point = first_affine_point(a2, a4)
    witness = multiply(4, seed_point, a2, a4)
    assert witness is not None
    assert is_on_curve(witness, a2, a4)
    assert multiply(prime_factor, witness, a2, a4) is None
    lower, upper, multiplier = unique_hasse_multiple(order, prime_factor)
    assert multiplier == 4
    print(f"{label}_seed_x={seed_x}")
    print(f"{label}_seed_point={seed_point}")
    print(f"{label}_subgroup_witness={witness}")
    print(f"{label}_q_times_witness=infinity")
    print(f"{label}_hasse_lower={lower}")
    print(f"{label}_hasse_upper={upper}")
    print(f"{label}_unique_multiplier={multiplier}")
    print(f"{label}_verified_order={order}")


def main() -> None:
    assert C == 44730
    assert S == 45677
    assert A_EDWARDS == 2086388329
    assert P % 4 == 3
    assert legendre(A_EDWARDS) == 1
    assert legendre(D_EDWARDS) == -1
    assert legendre(TWIST_Z) == -1
    assert N + N_TWIST == 2 * P + 2
    print(f"p={P}")
    print(f"c={C}")
    print(f"s={S}")
    print(f"a={A_EDWARDS}")
    print(f"A={A_MONTGOMERY}")
    print(f"B={B_MONTGOMERY}")
    print(f"weierstrass_coefficients={(0, A2, 0, A4, 0)}")
    print(
        "twist_coefficients="
        f"{(0, A2_TWIST, 0, A4_TWIST, 0)}"
    )
    verify_curve("curve", A2, A4, N, Q)
    verify_curve("twist", A2_TWIST, A4_TWIST, N_TWIST, Q_TWIST)
    print("independent_order_verification=pass")


if __name__ == "__main__":
    main()
