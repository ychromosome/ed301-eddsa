#!/usr/bin/env python3
"""Ed301-Sig-v1 reference implementation — NOT FOR PRODUCTION.

This standard-library-only module is deliberately variable-time and intended
solely for specification review and interoperable tests.  It is not hardened
against side channels, fault attacks, hostile runtimes, or denial of service.
The serialized secret key is exactly the original 38-byte seed; no cached
public key or derived material is accepted as secret-key input.
"""

from __future__ import annotations

import hashlib
import pathlib
import sys
from dataclasses import dataclass
from typing import Callable, Tuple

REFERENCE_DIRECTORY = pathlib.Path(__file__).resolve().parent
if str(REFERENCE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(REFERENCE_DIRECTORY))
import ed301_curve as curve


PRODUCTION_READY = False
SECURITY_WARNING = "REFERENCE ONLY: variable-time Ed301-Sig-v1; not production-ready"

SUITE = b"Ed301-Sig-v1"
DOM = bytes.fromhex("0c45643330312d5369672d76310100")
if DOM != bytes([len(SUITE)]) + SUITE + b"\x01\x00":
    raise AssertionError("fixed Ed301-Sig-v1 domain is inconsistent")

OP_KEY = 0x01
OP_PREFIX = 0x02
OP_NONCE = 0x03
OP_CHALLENGE = 0x04

TAG_SEED = 0x01
TAG_RETRY = 0x02
TAG_PREFIX = 0x03
TAG_PUBLIC_KEY = 0x04
TAG_CONTEXT = 0x05
TAG_MESSAGE = 0x06
TAG_R = 0x07

SEED_BYTES = 38
PUBLIC_KEY_BYTES = 38
SIGNATURE_BYTES = 76
XOF_BYTES = 64
MAX_CONTEXT_BYTES = 255
MAX_U32 = (1 << 32) - 1
MAX_U64 = (1 << 64) - 1


@dataclass(frozen=True)
class _KeyMaterial:
    scalar: int
    scalar_retry: int
    prefix: bytes
    public_point: curve.Point
    public_key: bytes


def _require_exact_bytes(name: str, value: bytes, length: int | None = None) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{name} must be bytes")
    if length is not None and len(value) != length:
        raise ValueError(f"{name} must be exactly {length} bytes")
    return value


def _validate_seed(seed: bytes) -> bytes:
    return _require_exact_bytes("seed", seed, SEED_BYTES)


def _validate_context_message(context: bytes, message: bytes) -> Tuple[bytes, bytes]:
    _require_exact_bytes("context", context)
    _require_exact_bytes("message", message)
    if len(context) > MAX_CONTEXT_BYTES:
        raise ValueError("context exceeds 255 bytes")
    if len(message) > MAX_U64:
        raise ValueError("message length does not fit u64")
    return context, message


def _u32be(value: int) -> bytes:
    if not isinstance(value, int) or not 0 <= value <= MAX_U32:
        raise ValueError("retry counter must fit unsigned 32 bits")
    return value.to_bytes(4, "big")


def _u64be(value: int) -> bytes:
    if not isinstance(value, int) or not 0 <= value <= MAX_U64:
        raise ValueError("length must fit unsigned 64 bits")
    return value.to_bytes(8, "big")


def _field(tag: int, value: bytes) -> bytes:
    if not isinstance(tag, int) or not 0 <= tag <= 0xFF:
        raise ValueError("field tag must fit one byte")
    _require_exact_bytes("field value", value)
    return bytes([tag]) + _u64be(len(value)) + value


def _frame_secret_scalar(seed: bytes, retry: int) -> bytes:
    _validate_seed(seed)
    return (
        DOM
        + bytes([OP_KEY, 2])
        + _field(TAG_SEED, seed)
        + _field(TAG_RETRY, _u32be(retry))
    )


def _frame_prefix(seed: bytes) -> bytes:
    _validate_seed(seed)
    return DOM + bytes([OP_PREFIX, 1]) + _field(TAG_SEED, seed)


def _frame_nonce(
    prefix: bytes,
    public_key: bytes,
    context: bytes,
    message: bytes,
    retry: int,
) -> bytes:
    _require_exact_bytes("prefix", prefix, XOF_BYTES)
    _require_exact_bytes("public key", public_key, PUBLIC_KEY_BYTES)
    _validate_context_message(context, message)
    return (
        DOM
        + bytes([OP_NONCE, 5])
        + _field(TAG_PREFIX, prefix)
        + _field(TAG_PUBLIC_KEY, public_key)
        + _field(TAG_CONTEXT, context)
        + _field(TAG_MESSAGE, message)
        + _field(TAG_RETRY, _u32be(retry))
    )


def _frame_challenge(
    public_key: bytes,
    context: bytes,
    message: bytes,
    encoded_r: bytes,
) -> bytes:
    _require_exact_bytes("public key", public_key, PUBLIC_KEY_BYTES)
    _validate_context_message(context, message)
    _require_exact_bytes("encoded R", encoded_r, PUBLIC_KEY_BYTES)
    return (
        DOM
        + bytes([OP_CHALLENGE, 4])
        + _field(TAG_PUBLIC_KEY, public_key)
        + _field(TAG_CONTEXT, context)
        + _field(TAG_MESSAGE, message)
        + _field(TAG_R, encoded_r)
    )


def _shake256(frame: bytes) -> bytes:
    _require_exact_bytes("hash frame", frame)
    return hashlib.shake_256(frame).digest(XOF_BYTES)


def _hash_to_scalar(frame: bytes) -> int:
    wide = _shake256(frame)
    if type(wide) is not bytes or len(wide) != XOF_BYTES:
        raise RuntimeError("SHAKE256 backend did not return exactly 64 bytes")
    return int.from_bytes(wide, "little") % curve.Q


def _derive_nonzero_scalar(
    frame_for_retry: Callable[[int], bytes],
    *,
    start_retry: int = 0,
) -> Tuple[int, int]:
    """Derive a nonzero scalar with u32-BE retry, never wrapping the counter."""

    if not isinstance(start_retry, int) or not 0 <= start_retry <= MAX_U32:
        raise ValueError("invalid initial retry counter")
    retry = start_retry
    while True:
        scalar = _hash_to_scalar(frame_for_retry(retry))
        if scalar != 0:
            return scalar, retry
        if retry == MAX_U32:
            raise OverflowError("nonzero-scalar retry counter exhausted without wrap")
        retry += 1


def _derive_key_material(seed: bytes) -> _KeyMaterial:
    seed = _validate_seed(seed)
    scalar, retry = _derive_nonzero_scalar(lambda counter: _frame_secret_scalar(seed, counter))
    prefix = _shake256(_frame_prefix(seed))
    if len(prefix) != XOF_BYTES:
        raise RuntimeError("SHAKE256 prefix has wrong length")
    public_point = curve.scalar_multiply(scalar, curve.G)
    if public_point == curve.IDENTITY:
        raise RuntimeError("nonzero secret scalar unexpectedly produced the identity")
    public_key = curve.encode_point(public_point)
    return _KeyMaterial(scalar, retry, prefix, public_point, public_key)


def keygen(seed: bytes) -> Tuple[bytes, bytes]:
    """Return ``(secret_key, public_key)``; secret_key is exactly seed38."""

    material = _derive_key_material(seed)
    return bytes(seed), material.public_key


def sign(secret_key: bytes, context: bytes, message: bytes) -> bytes:
    """Create a deterministic 76-byte signature and self-verify it."""

    seed = _validate_seed(secret_key)
    context, message = _validate_context_message(context, message)
    material = _derive_key_material(seed)  # Never trust cached A or prefix.

    nonce, _ = _derive_nonzero_scalar(
        lambda counter: _frame_nonce(
            material.prefix,
            material.public_key,
            context,
            message,
            counter,
        )
    )
    point_r = curve.scalar_multiply(nonce, curve.G)
    if point_r == curve.IDENTITY:
        raise RuntimeError("nonzero nonce unexpectedly produced the identity")
    encoded_r = curve.encode_point(point_r)
    challenge = _hash_to_scalar(
        _frame_challenge(material.public_key, context, message, encoded_r)
    )
    scalar_s = (nonce + challenge * material.scalar) % curve.Q
    signature = encoded_r + curve.encode_scalar(scalar_s)
    if len(signature) != SIGNATURE_BYTES:
        raise AssertionError("signature has wrong length")
    if not verify(material.public_key, context, message, signature):
        raise RuntimeError("internally generated signature failed self-verification")
    return signature


def verify(public_key: bytes, context: bytes, message: bytes, signature: bytes) -> bool:
    """Strictly verify canonical, nonidentity, exact-q-subgroup inputs."""

    try:
        _require_exact_bytes("public key", public_key, PUBLIC_KEY_BYTES)
        context, message = _validate_context_message(context, message)
        _require_exact_bytes("signature", signature, SIGNATURE_BYTES)
        point_a = curve.decode_point(public_key, require_prime_order=True)
        encoded_r = signature[:PUBLIC_KEY_BYTES]
        point_r = curve.decode_point(encoded_r, require_prime_order=True)
        scalar_s = curve.decode_scalar(signature[PUBLIC_KEY_BYTES:])
        challenge = _hash_to_scalar(
            _frame_challenge(public_key, context, message, encoded_r)
        )
        left = curve.scalar_multiply(scalar_s, curve.G)
        right = curve.point_add(point_r, curve.scalar_multiply(challenge, point_a))
        return left == right
    except (ArithmeticError, OverflowError, RuntimeError, TypeError, ValueError):
        return False


# Names matching the reviewed interface.
KeyGen = keygen
Sign = sign
Verify = verify


if __name__ == "__main__":
    print(SECURITY_WARNING)
    print(f"suite={SUITE.decode('ascii')}")
    print(f"dom={DOM.hex()}")
