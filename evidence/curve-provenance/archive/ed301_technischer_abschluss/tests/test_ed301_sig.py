#!/usr/bin/env python3
"""Design-review tests for the non-production Ed301-Sig-v1 reference."""

import pathlib
import sys
import unittest
from unittest import mock


REFERENCE_DIR = pathlib.Path(__file__).resolve().parents[1] / "referenz"
sys.path.insert(0, str(REFERENCE_DIR))

import ed301_curve as curve  # noqa: E402
import ed301_sig as sig  # noqa: E402


SEED = bytes(range(38))
EXPECTED_PUBLIC_KEY = bytes.fromhex(
    "1b20188d8c34d3eb09ffdcf15e726d3fea7b9cd6732ef0ed68d9ad20b9361816fa4657cecd07"
)
EXPECTED_SIGNATURE = bytes.fromhex(
    "9042a41da9ad7207774a7e252a9801fb3920a52cebf4ef953556027467b5ebfd0ebc2467a602d18d"
    "930ee8cc3d86bda55a0ebc7d3fcb04f8d202df921763c5559acc7fd04ff6f9b4f6196101"
)


def wide_scalar(value):
    return value.to_bytes(64, "little")


def injected_xof(*, secret=5, nonce=7, challenge=11, prefix=b"\xA5" * 64):
    """Return frame-aware deterministic XOF and its captured frame list."""

    frames = []

    def xof(frame):
        frames.append(frame)
        operation = frame[len(sig.DOM)]
        if operation == sig.OP_KEY:
            value = secret(int.from_bytes(frame[-4:], "big")) if callable(secret) else secret
            return wide_scalar(value)
        if operation == sig.OP_PREFIX:
            return prefix
        if operation == sig.OP_NONCE:
            value = nonce(int.from_bytes(frame[-4:], "big")) if callable(nonce) else nonce
            return wide_scalar(value)
        if operation == sig.OP_CHALLENGE:
            value = challenge(frame) if callable(challenge) else challenge
            return wide_scalar(value)
        raise AssertionError("unknown operation in injected XOF")

    return xof, frames


class DomainAndFrameTests(unittest.TestCase):
    def test_fixed_suite_and_domain(self):
        self.assertFalse(sig.PRODUCTION_READY)
        self.assertEqual(sig.SUITE, b"Ed301-Sig-v1")
        self.assertEqual(sig.DOM.hex(), "0c45643330312d5369672d76310100")
        self.assertEqual(sig.DOM, bytes([12]) + sig.SUITE + b"\x01\x00")

    def test_secret_scalar_frame_exact(self):
        expected = bytes.fromhex(
            "0c45643330312d5369672d763101000102"
            "010000000000000026000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425"
            "02000000000000000400000001"
        )
        self.assertEqual(sig._frame_secret_scalar(SEED, 1), expected)

    def test_prefix_frame_exact(self):
        expected = bytes.fromhex(
            "0c45643330312d5369672d763101000201"
            "010000000000000026000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425"
        )
        self.assertEqual(sig._frame_prefix(SEED), expected)

    def test_nonce_frame_exact(self):
        prefix = bytes(range(64))
        public_key = bytes(range(38))
        expected = bytes.fromhex(
            "0c45643330312d5369672d763101000305"
            "030000000000000040000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            "040000000000000026000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425"
            "050000000000000003637478"
            "0600000000000000036d7367"
            "02000000000000000400000001"
        )
        self.assertEqual(sig._frame_nonce(prefix, public_key, b"ctx", b"msg", 1), expected)

    def test_challenge_frame_exact(self):
        public_key = bytes(range(38))
        encoded_r = b"\x55" * 38
        expected = bytes.fromhex(
            "0c45643330312d5369672d763101000404"
            "040000000000000026000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425"
            "050000000000000003637478"
            "0600000000000000036d7367"
            "0700000000000000265555555555555555555555555555555555555555555555555555555555555555555555555555"
        )
        self.assertEqual(sig._frame_challenge(public_key, b"ctx", b"msg", encoded_r), expected)

    def test_field_lengths_are_u64_big_endian(self):
        value = b"abc"
        framed = sig._field(0x7F, value)
        self.assertEqual(framed, b"\x7f\x00\x00\x00\x00\x00\x00\x00\x03abc")
        self.assertEqual(sig._u64be(sig.MAX_U64), b"\xff" * 8)
        with self.assertRaises(ValueError):
            sig._u64be(sig.MAX_U64 + 1)


class DeterministicSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.secret_key, cls.public_key = sig.keygen(SEED)
        cls.signature = sig.sign(cls.secret_key, b"ctx", b"message")

    def test_keygen_is_deterministic_and_seed_only(self):
        self.assertEqual(self.secret_key, SEED)
        self.assertEqual(self.public_key, EXPECTED_PUBLIC_KEY)
        self.assertEqual(sig.keygen(SEED), (SEED, EXPECTED_PUBLIC_KEY))

    def test_sign_is_deterministic(self):
        self.assertEqual(self.signature, EXPECTED_SIGNATURE)
        self.assertEqual(sig.sign(SEED, b"ctx", b"message"), EXPECTED_SIGNATURE)
        self.assertEqual(len(self.signature), 76)

    def test_positive_verification(self):
        self.assertTrue(sig.verify(self.public_key, b"ctx", b"message", self.signature))
        self.assertTrue(sig.Verify(self.public_key, b"ctx", b"message", self.signature))

    def test_message_context_key_and_signature_manipulations(self):
        self.assertFalse(sig.verify(self.public_key, b"ctx", b"Message", self.signature))
        self.assertFalse(sig.verify(self.public_key, b"CTX", b"message", self.signature))
        other_public = sig.keygen(bytes(reversed(SEED)))[1]
        self.assertFalse(sig.verify(other_public, b"ctx", b"message", self.signature))

        altered_r = bytearray(self.signature)
        altered_r[0] ^= 1
        self.assertFalse(sig.verify(self.public_key, b"ctx", b"message", bytes(altered_r)))

        current_s = curve.decode_scalar(self.signature[38:])
        altered_s = self.signature[:38] + curve.encode_scalar((current_s + 1) % curve.Q)
        self.assertFalse(sig.verify(self.public_key, b"ctx", b"message", altered_s))

    def test_wrong_domains_fail(self):
        for wrong_dom in (sig.DOM[:-1] + b"\x01", b"\x0cWrong-Domain!!\x01\x00"):
            with mock.patch.object(sig, "DOM", wrong_dom):
                self.assertFalse(sig.verify(self.public_key, b"ctx", b"message", self.signature))

    def test_context_boundary(self):
        context255 = b"c" * 255
        signature = sig.sign(SEED, context255, b"")
        self.assertTrue(sig.verify(self.public_key, context255, b"", signature))
        with self.assertRaises(ValueError):
            sig.sign(SEED, b"c" * 256, b"")
        self.assertFalse(sig.verify(self.public_key, b"c" * 256, b"", signature))


class StrictVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public_key = sig.keygen(SEED)[1]
        cls.signature = sig.sign(SEED, b"", b"strict")
        cls.order4 = (pow(45677, curve.P - 2, curve.P), 0)

    def test_lengths_and_types(self):
        self.assertFalse(sig.verify(self.public_key[:-1], b"", b"strict", self.signature))
        self.assertFalse(sig.verify(self.public_key, b"", b"strict", self.signature[:-1]))
        self.assertFalse(sig.verify(bytearray(self.public_key), b"", b"strict", self.signature))
        self.assertFalse(sig.verify(self.public_key, bytearray(), b"strict", self.signature))
        self.assertFalse(sig.verify(self.public_key, b"", bytearray(b"strict"), self.signature))
        self.assertFalse(sig.verify(self.public_key, b"", b"strict", bytearray(self.signature)))

    def test_s_equal_q_is_rejected(self):
        signature = self.signature[:38] + curve.Q.to_bytes(38, "little")
        self.assertFalse(sig.verify(self.public_key, b"", b"strict", signature))

    def test_reserved_point_bits_are_rejected(self):
        bad_public = bytearray(self.public_key)
        bad_public[37] |= 0x20
        self.assertFalse(sig.verify(bytes(bad_public), b"", b"strict", self.signature))
        bad_r = bytearray(self.signature)
        bad_r[37] |= 0x40
        self.assertFalse(sig.verify(self.public_key, b"", b"strict", bytes(bad_r)))

    def test_torsion_and_mixed_order_public_keys_are_rejected(self):
        mixed2 = curve.point_add(curve.G, curve.ORDER_2)
        mixed4 = curve.point_add(curve.G, self.order4)
        for point in (curve.IDENTITY, curve.ORDER_2, self.order4, mixed2, mixed4):
            encoded = curve.encode_point(point)
            self.assertFalse(sig.verify(encoded, b"", b"strict", self.signature))

    def test_torsion_and_mixed_order_r_are_rejected(self):
        mixed2 = curve.point_add(curve.G, curve.ORDER_2)
        mixed4 = curve.point_add(curve.G, self.order4)
        for point in (curve.IDENTITY, curve.ORDER_2, self.order4, mixed2, mixed4):
            signature = curve.encode_point(point) + self.signature[38:]
            self.assertFalse(sig.verify(self.public_key, b"", b"strict", signature))

    def test_noncanonical_y_and_identity_sign_are_rejected(self):
        bad_public = curve.P.to_bytes(38, "little")
        self.assertFalse(sig.verify(bad_public, b"", b"strict", self.signature))
        identity_wrong_sign = bytearray(curve.encode_point(curve.IDENTITY))
        identity_wrong_sign[37] |= 0x80
        signature = bytes(identity_wrong_sign) + self.signature[38:]
        self.assertFalse(sig.verify(self.public_key, b"", b"strict", signature))


class RetryAndNullCaseTests(unittest.TestCase):
    def test_secret_scalar_zero_retries_from_zero(self):
        fake, frames = injected_xof(secret=lambda retry: 0 if retry == 0 else 5)
        with mock.patch.object(sig, "_shake256", side_effect=fake):
            material = sig._derive_key_material(SEED)
            self.assertEqual(material.scalar, 5)
            self.assertEqual(material.scalar_retry, 1)
        key_frames = [frame for frame in frames if frame[len(sig.DOM)] == sig.OP_KEY]
        self.assertEqual(key_frames[0], sig._frame_secret_scalar(SEED, 0))
        self.assertEqual(key_frames[1], sig._frame_secret_scalar(SEED, 1))

    def test_nonce_zero_retries_from_zero(self):
        fake, frames = injected_xof(nonce=lambda retry: 0 if retry == 0 else 7)
        with mock.patch.object(sig, "_shake256", side_effect=fake):
            secret_key, public_key = sig.keygen(SEED)
            signature = sig.sign(secret_key, b"", b"retry")
            self.assertTrue(sig.verify(public_key, b"", b"retry", signature))
        nonce_frames = [frame for frame in frames if frame[len(sig.DOM)] == sig.OP_NONCE]
        self.assertTrue(any(frame.endswith(b"\x00\x00\x00\x00") for frame in nonce_frames))
        self.assertTrue(any(frame.endswith(b"\x00\x00\x00\x01") for frame in nonce_frames))

    def test_retry_counter_never_wraps(self):
        with mock.patch.object(sig, "_shake256", return_value=b"\x00" * 64):
            with self.assertRaises(OverflowError):
                sig._derive_nonzero_scalar(
                    lambda retry: sig._frame_secret_scalar(SEED, retry),
                    start_retry=sig.MAX_U32,
                )

    def test_zero_challenge_is_allowed(self):
        fake, _ = injected_xof(secret=5, nonce=7, challenge=0)
        with mock.patch.object(sig, "_shake256", side_effect=fake):
            secret_key, public_key = sig.keygen(SEED)
            signature = sig.sign(secret_key, b"zero-k", b"")
            self.assertEqual(curve.decode_scalar(signature[38:]), 7)
            self.assertTrue(sig.verify(public_key, b"zero-k", b"", signature))

    def test_zero_signature_scalar_is_allowed(self):
        fake, _ = injected_xof(secret=1, nonce=1, challenge=curve.Q - 1)
        with mock.patch.object(sig, "_shake256", side_effect=fake):
            secret_key, public_key = sig.keygen(SEED)
            signature = sig.sign(secret_key, b"zero-S", b"")
            self.assertEqual(curve.decode_scalar(signature[38:]), 0)
            self.assertTrue(sig.verify(public_key, b"zero-S", b"", signature))


class SecretKeyAndBackendErrorTests(unittest.TestCase):
    def test_secret_key_is_exactly_seed38(self):
        public_key = sig.keygen(SEED)[1]
        with self.assertRaises(ValueError):
            sig.keygen(SEED[:-1])
        with self.assertRaises(TypeError):
            sig.keygen(bytearray(SEED))
        with self.assertRaises(ValueError):
            sig.sign(SEED + public_key, b"", b"")
        with self.assertRaises(TypeError):
            sig.sign((SEED, public_key), b"", b"")

    def test_sign_rejects_bad_context_and_message_inputs(self):
        with self.assertRaises(TypeError):
            sig.sign(SEED, "context", b"")
        with self.assertRaises(TypeError):
            sig.sign(SEED, b"", "message")

    def test_bad_xof_length_is_rejected(self):
        with mock.patch.object(sig, "_shake256", return_value=b"\x01" * 63):
            with self.assertRaises(RuntimeError):
                sig.keygen(SEED)

    def test_signer_self_verification_is_mandatory(self):
        with mock.patch.object(sig, "verify", return_value=False):
            with self.assertRaises(RuntimeError):
                sig.sign(SEED, b"", b"self-check")


if __name__ == "__main__":
    unittest.main(verbosity=2)
