#!/usr/bin/env python3
import ast
import math
import sys
import time

if len(sys.argv) != 2:
    raise SystemExit(f"usage: {sys.argv[0]} PARI_ECPP_CERTIFICATE")
CERT_PATH = sys.argv[1]


def add(P, Q, a, n):
    if P[2] % n == 0:
        return Q
    if Q[2] % n == 0:
        return P
    x1, y1, z1 = (v % n for v in P)
    x2, y2, z2 = (v % n for v in Q)
    z1z1 = z1 * z1 % n
    z2z2 = z2 * z2 % n
    u1 = x1 * z2z2 % n
    u2 = x2 * z1z1 % n
    s1 = y1 * z2 * z2z2 % n
    s2 = y2 * z1 * z1z1 % n
    if u1 == u2:
        if s1 != s2:
            return (1, 1, 0)
        return double(P, a, n)
    h = (u2 - u1) % n
    r = (s2 - s1) % n
    hh = h * h % n
    hhh = h * hh % n
    u1hh = u1 * hh % n
    x3 = (r * r - hhh - 2 * u1hh) % n
    y3 = (r * (u1hh - x3) - s1 * hhh) % n
    z3 = h * z1 * z2 % n
    return (x3, y3, z3)


def double(P, a, n):
    x, y, z = (v % n for v in P)
    if z == 0 or y == 0:
        return (1, 1, 0)
    yy = y * y % n
    yyyy = yy * yy % n
    zz = z * z % n
    m = (3 * x * x + a * zz * zz) % n
    s = 4 * x * yy % n
    x3 = (m * m - 2 * s) % n
    y3 = (m * (s - x3) - 8 * yyyy) % n
    z3 = 2 * y * z % n
    return (x3, y3, z3)


def mul(k, P, a, n):
    R = (1, 1, 0)
    Q = P
    while k:
        if k & 1:
            R = add(R, Q, a, n)
        Q = double(Q, a, n)
        k >>= 1
    return R


def ecpp_bound_holds(q, n):
    # Exact integer form of q > (n^(1/4) + 1)^2.
    A = q - 1
    return A * A > n and (A * A + n) ** 2 > (2 * A + 4) ** 2 * n


def prime_by_complete_trial_division(n):
    if n < 2:
        return False, None
    if n % 2 == 0:
        return n == 2, 2
    limit = math.isqrt(n)
    sieve = bytearray(b"\x01") * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for p in range(2, math.isqrt(limit) + 1):
        if sieve[p]:
            sieve[p * p:limit + 1:p] = b"\x00" * (((limit - p * p) // p) + 1)
    for p in range(3, limit + 1, 2):
        if sieve[p] and n % p == 0:
            return False, p
    return True, limit


with open(CERT_PATH, "rt", encoding="ascii") as f:
    cert = ast.literal_eval(f.read())

all_ok = True
for i, (n, trace, s, a, point) in enumerate(cert, 1):
    x, y = point
    m = n + 1 - trace
    divisible = m % s == 0
    q = m // s if divisible else 0
    link_ok = q == cert[i][0] if i < len(cert) else q < 2**64
    bound_ok = ecpp_bound_holds(q, n)
    trace_ok = trace * trace < 4 * n
    b = (y * y - x * x * x - a * x) % n
    curve_ok = (y * y - (x * x * x + a * x + b)) % n == 0
    discriminant_unit = math.gcd((4 * pow(a, 3, n) + 27 * pow(b, 2, n)) % n, n) == 1
    P = (x, y, 1)
    mP = mul(m, P, a, n)
    sP = mul(s, P, a, n)
    mP_infinity = mP[2] % n == 0
    sP_finite_everywhere = math.gcd(sP[2], n) == 1
    checks = [n > 0, divisible, link_ok, bound_ok, trace_ok, curve_ok,
              discriminant_unit, mP_infinity, sP_finite_everywhere]
    ok = all(checks)
    all_ok &= ok
    print(f"step={i} N={n} q={q} checks_ok={int(ok)} "
          f"mP_inf={int(mP_infinity)} gcd(Z_sP,N)={math.gcd(sP[2], n)}")

terminal_q = (cert[-1][0] + 1 - cert[-1][1]) // cert[-1][2]
t0 = time.monotonic()
terminal_prime, divisor_or_limit = prime_by_complete_trial_division(terminal_q)
trial_ms = round((time.monotonic() - t0) * 1000)
all_ok &= terminal_prime
print(f"terminal_q={terminal_q}")
print(f"terminal_q_sqrt_floor={math.isqrt(terminal_q)}")
print(f"terminal_complete_trial_division_prime={int(terminal_prime)}")
print(f"terminal_trial_division_wall_ms={trial_ms}")
print(f"independent_certificate_valid={int(all_ok)}")
raise SystemExit(0 if all_ok else 1)
