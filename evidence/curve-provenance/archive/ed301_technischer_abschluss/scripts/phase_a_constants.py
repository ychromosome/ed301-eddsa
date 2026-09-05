#!/usr/bin/env python3
"""Reproduziert die elementaren ED301-Parameter nur mit Python-Integerarithmetik."""

from __future__ import annotations


P = (1 << 301) - (1 << 99) + 947
A_EDWARDS = 1
D_EDWARDS = 301
IDENTITY = (0, 1)


def inv(value: int) -> int:
    return pow(value % P, -1, P)


def legendre(value: int) -> int:
    result = pow(value % P, (P - 1) // 2, P)
    if result == P - 1:
        return -1
    return result


def is_on_edwards(point: tuple[int, int]) -> bool:
    x, y = point
    return (A_EDWARDS * x * x + y * y - 1 - D_EDWARDS * x * x * y * y) % P == 0


def edwards_add(
    first: tuple[int, int], second: tuple[int, int]
) -> tuple[int, int]:
    x1, y1 = first
    x2, y2 = second
    product = D_EDWARDS * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + y1 * x2) * inv(1 + product) % P
    y3 = (y1 * y2 - A_EDWARDS * x1 * x2) * inv(1 - product) % P
    return x3, y3


def scalar_mul(scalar: int, point: tuple[int, int]) -> tuple[int, int]:
    result = IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = edwards_add(result, addend)
        addend = edwards_add(addend, addend)
        scalar >>= 1
    return result


def main() -> None:
    a_montgomery = 2 * (A_EDWARDS + D_EDWARDS) * inv(A_EDWARDS - D_EDWARDS) % P
    b_montgomery = 4 * inv(A_EDWARDS - D_EDWARDS) % P
    a24_plus = (a_montgomery + 2) * inv(4) % P
    a24_minus = (a_montgomery - 2) * inv(4) % P

    # B*v^2 = u^3 + A*u^2 + u, X=B*u, Y=B^2*v.
    # Damit: Y^2 = X^3 + (A*B)X^2 + B^2*X.
    weierstrass_a2 = a_montgomery * b_montgomery % P
    weierstrass_a4 = b_montgomery * b_montgomery % P
    discriminant = (
        16
        * pow(b_montgomery, 6, P)
        * (a_montgomery * a_montgomery - 4)
    ) % P
    c4 = 16 * (weierstrass_a2 * weierstrass_a2 - 3 * weierstrass_a4) % P
    j_invariant = pow(c4, 3, P) * inv(discriminant) % P

    order_four = (1, 0)
    assert P.bit_length() == 301
    assert hex(P) == (
        "0x1ffffffffffffffffffffffffffffffffffffffffffffffffff"
        "80000000000000000000003b3"
    )
    assert P % 4 == 3
    assert legendre(A_EDWARDS) == 1
    assert legendre(D_EDWARDS) == -1
    assert A_EDWARDS not in (0, D_EDWARDS)
    assert D_EDWARDS != 0
    assert is_on_edwards(order_four)
    assert scalar_mul(2, order_four) == (0, P - 1)
    assert scalar_mul(4, order_four) == IDENTITY
    assert a_montgomery not in (2, P - 2)
    assert legendre(a_montgomery * a_montgomery - 4) == -1
    assert legendre(2) == -1
    assert discriminant != 0

    values = {
        "p_dec": P,
        "p_hex": hex(P),
        "bitlen_p": P.bit_length(),
        "p_mod_4": P % 4,
        "legendre_a": legendre(A_EDWARDS),
        "legendre_d": legendre(D_EDWARDS),
        "A_dec": a_montgomery,
        "A_hex": hex(a_montgomery),
        "B_dec": b_montgomery,
        "B_hex": hex(b_montgomery),
        "A24_plus_dec": a24_plus,
        "A24_plus_hex": hex(a24_plus),
        "A24_minus_dec": a24_minus,
        "A24_minus_hex": hex(a24_minus),
        "weierstrass_a2_dec": weierstrass_a2,
        "weierstrass_a4_dec": weierstrass_a4,
        "weierstrass_discriminant_dec": discriminant,
        "j_invariant_dec": j_invariant,
        "twist_non_square_z": 2,
    }
    for name, value in values.items():
        print(f"{name}={value}")


if __name__ == "__main__":
    main()
