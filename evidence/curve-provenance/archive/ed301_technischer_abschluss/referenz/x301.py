#!/usr/bin/env python3
"""X301-v1 reference implementation — NOT FOR PRODUCTION.

This module is deliberately straightforward and variable-time.  It exists to
make the byte-level X301-v1 specification and its test vectors reproducible;
it is not a side-channel-resistant XDH implementation.
"""

from __future__ import annotations

import os
from collections.abc import Callable

import ed301_curve as curve


PRODUCTION_READY = False
SECURITY_WARNING = (
    "REFERENCE ONLY: variable-time Python integers and branches; "
    "not production-ready"
)

SECRET_BYTES = 38
PUBLIC_BYTES = 38
SHARED_BYTES = 38

P = curve.P
Q = curve.Q
N = curve.N
Q_TWIST = int(
    "1018517988167243043134222844204689080525734196323118960177517235683197019236556497968262103"
)
N_TWIST = 4 * Q_TWIST

BASE_U = int(
    "1067917942141295978366266158278333061632895636270240461974100298644709548352069314007836251"
)
BASE_U_ENCODING = bytes.fromhex(
    "5ba6f0f4ccc6ff5f018a2496fe165eb7d1893949fe3d05f79c12d2bd99952cd42d2ae9546308"
)


def _require_secret(secret: bytes) -> bytes:
    if not isinstance(secret, bytes) or len(secret) != SECRET_BYTES:
        raise ValueError("X301 secret input must be exactly 38 bytes")
    return secret


def clamp_secret_bytes(secret: bytes) -> bytes:
    """Return the canonical clamped scalar bytes or reject the twist weak key."""

    raw = bytearray(_require_secret(secret))
    raw[0] &= 0xFC          # Scalar is a multiple of the common cofactor 4.
    raw[37] = (raw[37] & 0x0F) | 0x10  # Clear 301..303; set bit 300.
    clamped = bytes(raw)
    scalar = int.from_bytes(clamped, "little")
    if scalar == N_TWIST:
        raise ValueError("invalid X301 secret: clamped scalar equals twist order")
    return clamped


def decode_secret_scalar(secret: bytes) -> int:
    scalar = int.from_bytes(clamp_secret_bytes(secret), "little")
    if not (1 << 300) <= scalar < (1 << 301):
        raise AssertionError("X301 clamping produced an out-of-range scalar")
    if scalar & 3:
        raise AssertionError("X301 clamping did not clear the cofactor bits")
    return scalar


def x301(secret: bytes, u_encoding: bytes) -> bytes:
    """Apply the X301-v1 raw XDH function.

    Inputs are a 38-byte raw secret and a strict canonical 38-byte little-
    endian u-coordinate.  The point at infinity is an error and is never
    represented as an all-zero shared secret.
    """

    scalar = decode_secret_scalar(secret)
    u = curve.decode_field(u_encoding)
    result = curve.montgomery_ladder_u(scalar, u)
    if result is None:
        raise ValueError("invalid X301 input or result: point at infinity")
    encoded = curve.encode_field(result)
    if encoded == b"\x00" * SHARED_BYTES:
        raise ValueError("invalid X301 result: all-zero output")
    return encoded


def public_from_secret(secret: bytes) -> bytes:
    """Derive the canonical X301 public key from a raw 38-byte secret."""

    return x301(secret, BASE_U_ENCODING)


def shared_secret(secret: bytes, peer_public: bytes) -> bytes:
    """Return the raw shared u-coordinate; no KDF is applied."""

    return x301(secret, peer_public)


def keygen(
    random_bytes: Callable[[int], bytes] = os.urandom,
) -> tuple[bytes, bytes]:
    """Generate a raw secret and public key, resampling the one invalid clamp."""

    while True:
        secret = random_bytes(SECRET_BYTES)
        _require_secret(secret)
        try:
            public = public_from_secret(secret)
        except ValueError as exc:
            if "twist order" not in str(exc):
                raise
            continue
        return secret, public


def verify_parameters() -> bool:
    if BASE_U_ENCODING != curve.encode_field(BASE_U):
        return False
    if curve.edwards_to_montgomery(curve.G)[0] != BASE_U:
        return False
    if N != 4 * Q or N_TWIST != 4 * Q_TWIST:
        return False
    if not (N > 1 << 301 and N_TWIST < 1 << 301):
        return False
    return True


if __name__ == "__main__":
    print(SECURITY_WARNING)
    print(f"parameters_ok={int(verify_parameters())}")
    print(f"base_u={BASE_U_ENCODING.hex()}")
