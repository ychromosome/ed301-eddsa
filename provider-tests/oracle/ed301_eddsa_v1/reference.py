"""Variable-time reference for the Ed301-EdDSA-v1 byte contract.

The curve and encoding operations reuse the separately tested draft-00 Python
reference because Ed301-v1 itself is unchanged.  The transcript below is a
new, explicit implementation of the RFC 8032 Ed448 ``dom4`` pattern.  This is
test software only: Python integers, inversions and branches handle secrets.
"""

from __future__ import annotations

from hashlib import shake_256
from typing import Final

from ed301_eddsa import reference as curve

SPEC_IDENTIFIER: Final = "Ed301-EdDSA-v1"
DOMAIN_PREFIX: Final = b"SigEd301-v1"
PHFLAG: Final = 0
MAX_CONTEXT_BYTES: Final = 255

P: Final = curve.P
A: Final = curve.A
D: Final = curve.D
L: Final = curve.L
COFACTOR: Final = curve.COFACTOR
FIELD_BYTES: Final = curve.FIELD_BYTES
SEED_BYTES: Final = curve.SEED_BYTES
PUBLIC_KEY_BYTES: Final = curve.PUBLIC_KEY_BYTES
SIGNATURE_BYTES: Final = curve.SIGNATURE_BYTES
HASH_BYTES: Final = curve.HASH_BYTES
BASE_POINT: Final = curve.BASE_POINT
IDENTITY: Final = curve.IDENTITY
Ed301Error = curve.Ed301Error
decode_point = curve.decode_point
encode_point = curve.encode_point
point_add = curve.point_add
scalar_mult = curve.scalar_mult


def _require_bytes(value: bytes, label: str) -> bytes:
    if not isinstance(value, bytes):
        raise Ed301Error(f"{label} must be bytes")
    return value


def domain(context: bytes = b"") -> bytes:
    """Return ``SigEd301-v1 || phflag || len(context) || context``."""

    context = _require_bytes(context, "context")
    if len(context) > MAX_CONTEXT_BYTES:
        raise Ed301Error("context must contain at most 255 bytes")
    return DOMAIN_PREFIX + bytes((PHFLAG, len(context))) + context


def _hash(parts: tuple[bytes, ...]) -> bytes:
    state = shake_256()
    for part in parts:
        state.update(part)
    return state.digest(HASH_BYTES)


def _hash_to_scalar(parts: tuple[bytes, ...]) -> tuple[bytes, int]:
    digest = _hash(parts)
    return digest, int.from_bytes(digest, "little") % L


def expand_seed(seed: bytes):
    """Reuse the unchanged ED301-v1 key expansion."""

    return curve.expand_seed(seed)


def public_from_seed(seed: bytes) -> bytes:
    """Derive the unchanged 38-byte ED301-v1 public key."""

    return curve.public_from_seed(seed)


def sign_trace(seed: bytes, message: bytes, context: bytes = b"") -> dict[str, bytes]:
    """Return a signature and every normative transcript intermediate."""

    seed = curve._require_bytes(seed, SEED_BYTES, "seed")
    message = _require_bytes(message, "message")
    dom = domain(context)
    secret_scalar, prefix, expanded = curve.expand_seed(seed)
    public_key = curve.encode_point(curve.scalar_mult(secret_scalar, BASE_POINT))
    nonce_hash, nonce = _hash_to_scalar((dom, prefix, message))
    commitment = curve.encode_point(curve.scalar_mult(nonce, BASE_POINT))
    challenge_hash, challenge = _hash_to_scalar(
        (dom, commitment, public_key, message)
    )
    response = (nonce + challenge * secret_scalar) % L
    response_bytes = response.to_bytes(FIELD_BYTES, "little")
    lower = bytearray(expanded[:FIELD_BYTES])
    lower[0] &= 0xFC
    lower[-1] = (lower[-1] & 0x0F) | 0x10
    return {
        "expanded_hash": expanded,
        "pruned_secret_scalar": bytes(lower),
        "prefix": prefix,
        "public_key": public_key,
        "nonce_hash": nonce_hash,
        "nonce_scalar": nonce.to_bytes(FIELD_BYTES, "little"),
        "commitment": commitment,
        "challenge_hash": challenge_hash,
        "challenge_scalar": challenge.to_bytes(FIELD_BYTES, "little"),
        "response": response_bytes,
        "signature": commitment + response_bytes,
    }


def sign(seed: bytes, message: bytes, context: bytes = b"") -> bytes:
    """Sign with the native Ed301-EdDSA-v1 context."""

    return sign_trace(seed, message, context)["signature"]


def validate_public_key(public_key: bytes) -> bool:
    """Apply the unchanged ED301-v1 public-key policy."""

    return curve.validate_public_key(public_key)


def verify(
    public_key: bytes,
    message: bytes,
    signature: bytes,
    context: bytes = b"",
) -> bool:
    """Verify with canonical inputs and the factor-four equation."""

    try:
        public_key = curve._require_bytes(
            public_key, PUBLIC_KEY_BYTES, "public key"
        )
        signature = curve._require_bytes(
            signature, SIGNATURE_BYTES, "signature"
        )
        message = _require_bytes(message, "message")
        dom = domain(context)
        commitment_encoding = signature[:FIELD_BYTES]
        response = curve.decode_scalar(signature[FIELD_BYTES:])
        public_point = curve._decode_validated_public_key(public_key)
        commitment_point = curve.decode_point(commitment_encoding)
        _, challenge = _hash_to_scalar(
            (dom, commitment_encoding, public_key, message)
        )
        left = curve.scalar_mult((COFACTOR * response) % L, BASE_POINT)
        right = curve.point_add(
            curve.scalar_mult(COFACTOR, commitment_point),
            curve.scalar_mult((COFACTOR * challenge) % L, public_point),
        )
        return left == right
    except (Ed301Error, TypeError, ValueError, OverflowError):
        return False


if domain() != b"SigEd301-v1\x00\x00":
    raise RuntimeError("invalid empty Ed301-EdDSA-v1 domain")
