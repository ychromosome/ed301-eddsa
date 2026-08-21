"""Small, non-constant-time Ed301 PureEdDSA reference.

This module exists to make the draft byte contract executable and reviewable.
It is deliberately not a production implementation: Python integers, affine
coordinates, inversions, branches and variable-time scalar multiplication all
operate on secret data.

The signature construction follows the generic algorithm in RFC 8032 section
3 with the project-defined ED301-v1 curve parameters.  It is not Ed25519,
Ed448, a named RFC 8032 instance, or a FIPS 186-5 approved parameter set.
"""

from __future__ import annotations

from hashlib import shake_256
from typing import Final, TypeAlias

SPEC_IDENTIFIER: Final = "Ed301-EdDSA-draft-00"

P: Final = (
    4074071952668972172536891376818756322102936787331872501272280264883462485411972664015193011
)
A: Final = 2_086_388_329
D: Final = 301
L: Final = (
    1018517988167243043134222844204689080525734197342817290458622896758534223469429834039334403
)
COFACTOR: Final = 4
ENCODING_BITS: Final = 304
C_RFC: Final = 2
N_RFC: Final = 300
FIELD_BYTES: Final = ENCODING_BITS // 8
SEED_BYTES: Final = FIELD_BYTES
PUBLIC_KEY_BYTES: Final = FIELD_BYTES
SIGNATURE_BYTES: Final = 2 * FIELD_BYTES
HASH_BYTES: Final = 2 * FIELD_BYTES

Point: TypeAlias = tuple[int, int]

IDENTITY: Final[Point] = (0, 1)
BASE_POINT: Final[Point] = (
    114483960210649758260691970228447544333115946824833551736797985468026643833345600929055,
    3123599847077067352547410063473606051762622289826321814465731066121453938271612909425522539,
)


class Ed301Error(ValueError):
    """Invalid input or violated draft invariant."""


def _require_bytes(value: bytes, expected_length: int, label: str) -> bytes:
    if not isinstance(value, bytes):
        raise Ed301Error(f"{label} must be bytes")
    if len(value) != expected_length:
        raise Ed301Error(f"{label} must be exactly {expected_length} bytes")
    return value


def _inverse(value: int) -> int:
    value %= P
    if value == 0:
        raise Ed301Error("attempted inversion of zero")
    return pow(value, -1, P)


def is_on_curve(point: Point) -> bool:
    """Return whether an affine pair is a canonical ED301-v1 point."""

    x, y = point
    if not (0 <= x < P and 0 <= y < P):
        return False
    xx = x * x % P
    yy = y * y % P
    return (A * xx + yy - 1 - D * xx * yy) % P == 0


def point_add(left: Point, right: Point) -> Point:
    """Add two ED301-v1 points using the complete affine formula."""

    if not is_on_curve(left) or not is_on_curve(right):
        raise Ed301Error("point addition requires valid curve points")
    x1, y1 = left
    x2, y2 = right
    product = D * x1 * x2 * y1 * y2 % P
    x3 = (x1 * y2 + x2 * y1) * _inverse(1 + product) % P
    y3 = (y1 * y2 - A * x1 * x2) * _inverse(1 - product) % P
    result = (x3, y3)
    if not is_on_curve(result):
        raise Ed301Error("point addition violated the curve invariant")
    return result


def scalar_mult(scalar: int, point: Point) -> Point:
    """Variable-time double-and-add scalar multiplication for review only."""

    if not isinstance(scalar, int) or scalar < 0:
        raise Ed301Error("scalar must be a non-negative integer")
    if not is_on_curve(point):
        raise Ed301Error("scalar multiplication requires a valid point")
    result = IDENTITY
    addend = point
    remaining = scalar
    while remaining:
        if remaining & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        remaining >>= 1
    return result


def encode_point(point: Point) -> bytes:
    """Encode a point as canonical little-endian y plus the x parity bit."""

    if not is_on_curve(point):
        raise Ed301Error("cannot encode an invalid point")
    x, y = point
    encoded = bytearray(y.to_bytes(FIELD_BYTES, "little"))
    if encoded[-1] & 0xE0:
        raise Ed301Error("canonical y unexpectedly occupies reserved bits")
    encoded[-1] |= (x & 1) << 7
    return bytes(encoded)


def decode_point(encoded: bytes) -> Point:
    """Decode one canonical ED301-v1 compressed Edwards point."""

    encoded = _require_bytes(encoded, FIELD_BYTES, "point")
    if encoded[-1] & 0x60:
        raise Ed301Error("reserved point-encoding bits are set")
    sign = encoded[-1] >> 7
    y_bytes = bytearray(encoded)
    y_bytes[-1] &= 0x1F
    y = int.from_bytes(y_bytes, "little")
    if y >= P:
        raise Ed301Error("non-canonical y coordinate")

    yy = y * y % P
    denominator = (A - D * yy) % P
    x_squared = (1 - yy) * _inverse(denominator) % P
    root = pow(x_squared, (P + 1) // 4, P)
    if root * root % P != x_squared:
        raise Ed301Error("encoded y does not recover a curve point")
    if root == 0 and sign:
        raise Ed301Error("negative encoding of zero x")
    x = root if (root & 1) == sign else (-root) % P
    point = (x, y)
    if not is_on_curve(point):
        raise Ed301Error("decoded point violates the curve equation")
    return point


def _hash(data: bytes) -> bytes:
    """The draft H function: SHAKE256 with an exact 76-byte output."""

    return shake_256(data).digest(HASH_BYTES)


def _hash_to_scalar(data: bytes) -> int:
    """Reduce a full 608-bit RFC hash integer modulo the subgroup order.

    Early reduction is byte-equivalent here because the base point and the
    fully validated public key have order L.
    """

    return int.from_bytes(_hash(data), "little") % L


def expand_seed(seed: bytes) -> tuple[int, bytes, bytes]:
    """Return the pruned secret scalar, nonce prefix and full expansion."""

    seed = _require_bytes(seed, SEED_BYTES, "seed")
    expanded = _hash(seed)
    lower = bytearray(expanded[:FIELD_BYTES])
    lower[0] &= 0xFC
    lower[-1] = (lower[-1] & 0x0F) | 0x10
    secret_scalar = int.from_bytes(lower, "little")
    if secret_scalar % (1 << C_RFC) != 0:
        raise Ed301Error("pruning failed to clear the cofactor bits")
    if secret_scalar.bit_length() != N_RFC + 1:
        raise Ed301Error("pruning failed to produce a 301-bit scalar")
    if secret_scalar % L == 0:
        raise Ed301Error("pruned scalar unexpectedly produces the identity")
    return secret_scalar, expanded[FIELD_BYTES:], expanded


def public_from_seed(seed: bytes) -> bytes:
    """Derive the 38-byte public key from one 38-byte seed."""

    secret_scalar, _, _ = expand_seed(seed)
    return encode_point(scalar_mult(secret_scalar, BASE_POINT))


def sign(seed: bytes, message: bytes) -> bytes:
    """Sign an opaque message using context-free PureEdDSA semantics."""

    seed = _require_bytes(seed, SEED_BYTES, "seed")
    if not isinstance(message, bytes):
        raise Ed301Error("message must be bytes")
    secret_scalar, prefix, _ = expand_seed(seed)
    public_key = encode_point(scalar_mult(secret_scalar, BASE_POINT))
    nonce = _hash_to_scalar(prefix + message)
    commitment = encode_point(scalar_mult(nonce, BASE_POINT))
    challenge = _hash_to_scalar(commitment + public_key + message)
    response = (nonce + challenge * secret_scalar) % L
    return commitment + response.to_bytes(FIELD_BYTES, "little")


def decode_scalar(encoded: bytes) -> int:
    """Parse one canonical 38-byte signature scalar in the range 0 <= S < L."""

    encoded = _require_bytes(encoded, FIELD_BYTES, "scalar")
    scalar = int.from_bytes(encoded, "little")
    if scalar >= L:
        raise Ed301Error("non-canonical scalar")
    return scalar


def _is_prime_subgroup(point: Point) -> bool:
    return scalar_mult(L, point) == IDENTITY


def _decode_validated_public_key(public_key: bytes) -> Point:
    """Decode and fully validate a nonidentity prime-subgroup public key."""

    public_point = decode_point(public_key)
    if public_point == IDENTITY or not _is_prime_subgroup(public_point):
        raise Ed301Error("invalid public key")
    return public_point


def validate_public_key(public_key: bytes) -> bool:
    """Apply the draft's strict nonidentity prime-subgroup public-key rule."""

    try:
        _decode_validated_public_key(public_key)
        return True
    except (Ed301Error, TypeError, ValueError):
        return False


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a validated key with canonical R/S and the cofactor equation."""

    try:
        public_key = _require_bytes(public_key, PUBLIC_KEY_BYTES, "public key")
        signature = _require_bytes(signature, SIGNATURE_BYTES, "signature")
        if not isinstance(message, bytes):
            return False
        commitment_encoding = signature[:FIELD_BYTES]
        response = decode_scalar(signature[FIELD_BYTES:])
        public_point = _decode_validated_public_key(public_key)
        commitment_point = decode_point(commitment_encoding)
        challenge = _hash_to_scalar(commitment_encoding + public_key + message)
        left = scalar_mult((COFACTOR * response) % L, BASE_POINT)
        right = point_add(
            scalar_mult(COFACTOR, commitment_point),
            scalar_mult((COFACTOR * challenge) % L, public_point),
        )
        return left == right
    except (Ed301Error, TypeError, ValueError, OverflowError):
        return False


if not is_on_curve(BASE_POINT):
    raise RuntimeError("the frozen ED301-v1 base point is invalid")
if scalar_mult(L, BASE_POINT) != IDENTITY:
    raise RuntimeError("the frozen ED301-v1 base point does not have order L")
