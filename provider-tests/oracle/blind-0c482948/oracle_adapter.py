"""Hardened adapter for the frozen Package-A blind implementation.

The source below ``source/`` is an immutable experiment artifact.  This
adapter is the only supported API: it accepts exact immutable ``bytes`` and
does not expose the raw affine point helpers.
"""

from __future__ import annotations

import hashlib
import types
from pathlib import Path
from typing import Final

SOURCE_SHA256: Final = (
    "2364f483696c81dba7b81f0cc37f4037983a2c6795c204586e6c09f6a3669bf3"
)
SOURCE_MANIFEST_SHA256: Final = (
    "bda1c016894a55efb94fab1df5969b3540fc797bd9121214853d6a555a208fca"
)


def _load_frozen_source() -> types.ModuleType:
    adapter_root = Path(__file__).resolve(strict=True).parent
    source_root = adapter_root / "source"
    source_path = source_root / "ed301_eddsa.py"
    expected_path = source_path.absolute()

    if source_root.is_symlink() or source_path.is_symlink():
        raise RuntimeError("blind oracle source path must not contain a symlink")
    resolved_path = source_path.resolve(strict=True)
    if resolved_path != expected_path:
        raise RuntimeError("blind oracle source resolved outside its fixed path")

    source_bytes = resolved_path.read_bytes()
    if hashlib.sha256(source_bytes).hexdigest() != SOURCE_SHA256:
        raise RuntimeError("blind oracle source hash mismatch")

    # Compile exactly the bytes that were hashed.  A path-based loader would
    # reopen the file and introduce a needless hash/load race in a writable
    # development tree.
    module = types.ModuleType("_ed301_blind_0c482948_source")
    module.__file__ = str(resolved_path)
    module.__package__ = ""
    code = compile(source_bytes, str(resolved_path), "exec")
    exec(code, module.__dict__)
    if Path(module.__file__).resolve(strict=True) != resolved_path:
        raise RuntimeError("blind oracle module identity mismatch")
    return module


_IMPL = _load_frozen_source()
Ed301Error = _IMPL.Ed301Error


def _require_bytes(value: object, label: str) -> bytes:
    if type(value) is not bytes:
        raise Ed301Error(f"{label} must be exact immutable bytes")
    return value


def derive_public_key(seed: bytes) -> bytes:
    """Derive a public key through the frozen oracle."""

    return _IMPL.derive_public_key(_require_bytes(seed, "seed"))


def sign(seed: bytes, message: bytes) -> bytes:
    """Create a deterministic signature through the frozen oracle."""

    return _IMPL.sign(
        _require_bytes(seed, "seed"),
        _require_bytes(message, "message"),
    )


def validate_public_key(public_key: bytes) -> bool:
    """Validate an exact immutable public-key encoding or raise Ed301Error."""

    _IMPL.validate_public_key(_require_bytes(public_key, "public key"))
    return True


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify only exact immutable byte strings.

    Rejecting mutable buffers at this boundary prevents the frozen source
    from validating one public-key snapshot and hashing a later snapshot.
    """

    if type(public_key) is not bytes:
        return False
    if type(message) is not bytes:
        return False
    if type(signature) is not bytes:
        return False
    return bool(_IMPL.verify(public_key, message, signature))


__all__ = [
    "Ed301Error",
    "derive_public_key",
    "sign",
    "validate_public_key",
    "verify",
]
