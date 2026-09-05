#!/usr/bin/env python3
import ast
import math
import sys


def is_prime_u64(n):
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    # Deterministic Miller-Rabin basis set for every unsigned 64-bit integer.
    for a in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def find_witness(n, p):
    for a in range(2, 1_000_000):
        if pow(a, n - 1, n) == 1 and math.gcd(pow(a, (n - 1) // p, n) - 1, n) == 1:
            return a
    return None


def root_of(cert):
    return cert if isinstance(cert, int) else cert[0]


def verify(cert, depth=0):
    indent = "  " * depth
    if isinstance(cert, int):
        ok = cert < 2**64 and is_prime_u64(cert)
        print(f"{indent}terminal={cert} deterministic_u64_prime={int(ok)}")
        return ok

    if not isinstance(cert, list) or len(cert) != 2:
        print(f"{indent}malformed_certificate=1")
        return False
    n, entries = cert
    if n < 2 or not isinstance(entries, list):
        return False
    z = n - 1
    F = 1
    factors_ok = True
    seen = set()
    print(f"{indent}N={n}")
    for entry in entries:
        if isinstance(entry, int):
            p = entry
            prime_ok = p < 2**64 and is_prime_u64(p)
            witness = find_witness(n, p) if prime_ok and z % p == 0 else None
            sub_ok = prime_ok
            supplied = False
        else:
            if not isinstance(entry, list) or len(entry) != 3:
                return False
            p, witness, subcert = entry
            sub_ok = root_of(subcert) == p and verify(subcert, depth + 1)
            prime_ok = sub_ok
            supplied = True
        valuation = 0
        zz = z
        while p > 1 and zz % p == 0:
            valuation += 1
            zz //= p
        witness_ok = (witness is not None and pow(witness, n - 1, n) == 1
                      and math.gcd(pow(witness, (n - 1) // p, n) - 1, n) == 1)
        distinct = p not in seen
        seen.add(p)
        item_ok = prime_ok and valuation > 0 and witness_ok and distinct
        factors_ok &= item_ok
        F *= p ** valuation
        print(f"{indent}factor={p} valuation={valuation} witness={witness} "
              f"supplied={int(supplied)} prime_ok={int(prime_ok)} witness_ok={int(witness_ok)}")
    u, divisible = divmod(z, F)
    c1 = u % F
    c2 = u // F
    disc = c1 * c1 - 4 * c2
    disc_square = disc >= 0 and math.isqrt(disc) ** 2 == disc
    recomposition = divisible == 0 and n == 1 + c1 * F + c2 * F * F
    bound = F ** 3 > n
    pocklington_bound = F ** 2 > n
    final_criterion = pocklington_bound or not disc_square
    bls_ok = factors_ok and recomposition and bound and final_criterion
    print(f"{indent}F={F} F_bits={F.bit_length()} F_cubed_gt_N={int(bound)}")
    print(f"{indent}F_squared_gt_N={int(pocklington_bound)} c1={c1} c2={c2} "
          f"discriminant={disc} discriminant_square={int(disc_square)}")
    print(f"{indent}recomposition_exact={int(recomposition)} certificate_level_valid={int(bls_ok)}")
    return bls_ok


if len(sys.argv) != 2:
    raise SystemExit(f"usage: {sys.argv[0]} PARI_N_MINUS_1_CERTIFICATE")

with open(sys.argv[1], "rt", encoding="ascii") as f:
    certificate = ast.literal_eval(f.read())

valid = verify(certificate)
print(f"independent_N_minus_1_certificate_valid={int(valid)}")
raise SystemExit(0 if valid else 1)
