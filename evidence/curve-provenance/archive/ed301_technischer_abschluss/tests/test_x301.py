#!/usr/bin/env python3
"""Tests for the non-production X301-v1 Python reference."""

from __future__ import annotations

import pathlib
import sys
import unittest


REFERENCE_DIR = pathlib.Path(__file__).resolve().parents[1] / "referenz"
sys.path.insert(0, str(REFERENCE_DIR))

import ed301_curve as curve  # noqa: E402
import x301  # noqa: E402


class ClampTests(unittest.TestCase):
    def test_parameters_and_warning(self):
        self.assertFalse(x301.PRODUCTION_READY)
        self.assertIn("not production-ready", x301.SECURITY_WARNING)
        self.assertTrue(x301.verify_parameters())

    def test_exact_clamp_bits_and_range(self):
        raw = bytes(range(38))
        clamped = x301.clamp_secret_bytes(raw)
        scalar = x301.decode_secret_scalar(raw)
        self.assertEqual(len(clamped), 38)
        self.assertEqual(clamped[0] & 0x03, 0)
        self.assertEqual(clamped[37] & 0xE0, 0)
        self.assertEqual(clamped[37] & 0x10, 0x10)
        self.assertGreaterEqual(scalar, 1 << 300)
        self.assertLess(scalar, 1 << 301)
        self.assertEqual(scalar & 3, 0)

    def test_ignored_raw_bits_have_64_preimages(self):
        base = bytearray(38)
        outputs = set()
        for low in range(4):
            for high in range(16):
                raw = bytearray(base)
                raw[0] = low
                raw[37] = high << 4
                outputs.add(x301.clamp_secret_bytes(bytes(raw)))
        self.assertEqual(len(outputs), 1)

    def test_twist_order_secret_is_rejected(self):
        bad = x301.N_TWIST.to_bytes(38, "little")
        self.assertEqual(bad[0] & 3, 0)
        self.assertEqual(bad[37] & 0x1F, bad[37])
        with self.assertRaisesRegex(ValueError, "twist order"):
            x301.decode_secret_scalar(bad)

    def test_secret_length_and_type(self):
        for bad in (b"", b"\x00" * 37, b"\x00" * 39, bytearray(38)):
            with self.assertRaises(ValueError):
                x301.decode_secret_scalar(bad)  # type: ignore[arg-type]


class OperationTests(unittest.TestCase):
    ALICE = bytes(range(38))
    BOB = bytes(reversed(range(38)))

    def test_public_key_and_shared_secret_symmetry(self):
        alice_public = x301.public_from_secret(self.ALICE)
        bob_public = x301.public_from_secret(self.BOB)
        self.assertEqual(len(alice_public), 38)
        self.assertEqual(len(bob_public), 38)
        self.assertNotEqual(alice_public, bob_public)
        left = x301.shared_secret(self.ALICE, bob_public)
        right = x301.shared_secret(self.BOB, alice_public)
        self.assertEqual(left, right)
        self.assertNotEqual(left, b"\x00" * 38)

    def test_public_ladder_matches_general_edwards_multiplication(self):
        for secret in (self.ALICE, self.BOB, b"\x00" * 38, b"\xff" * 38):
            scalar = x301.decode_secret_scalar(secret)
            point = curve.scalar_multiply(scalar, curve.G)
            expected_u, _ = curve.edwards_to_montgomery(point)
            self.assertEqual(
                x301.public_from_secret(secret),
                curve.encode_field(expected_u),
            )

    def test_zero_raw_secret_is_valid_after_clamp(self):
        secret = b"\x00" * 38
        scalar = x301.decode_secret_scalar(secret)
        self.assertEqual(scalar, 1 << 300)
        self.assertEqual(len(x301.public_from_secret(secret)), 38)

    def test_strict_u_input_rejections(self):
        secret = self.ALICE
        for bad in (b"", b"\x00" * 37, b"\x00" * 39):
            with self.assertRaises(ValueError):
                x301.x301(secret, bad)
        with self.assertRaises(ValueError):
            x301.x301(secret, curve.P.to_bytes(38, "little"))
        for mask in (0x20, 0x40, 0x80):
            bad = bytearray(x301.BASE_U_ENCODING)
            bad[37] |= mask
            with self.assertRaises(ValueError):
                x301.x301(secret, bytes(bad))

    def test_low_order_inputs_are_rejected(self):
        secret = self.ALICE
        for u in (0, 1):
            with self.assertRaisesRegex(ValueError, "point at infinity"):
                x301.x301(secret, curve.encode_field(u))

    def test_twist_input_is_supported(self):
        # u=2 has nonsquare Montgomery v^2 and therefore lies on the twist.
        rhs = (
            2**3 + curve.A_MONTGOMERY * 2**2 + 2
        ) * pow(curve.B_MONTGOMERY, -1, curve.P) % curve.P
        self.assertEqual(pow(rhs, (curve.P - 1) // 2, curve.P), curve.P - 1)
        output = x301.x301(self.ALICE, curve.encode_field(2))
        self.assertEqual(len(output), 38)
        self.assertNotEqual(output, b"\x00" * 38)

    def test_same_clamped_scalar_gives_same_results(self):
        first = bytearray(self.ALICE)
        second = bytearray(self.ALICE)
        second[0] ^= 0x03
        second[37] ^= 0xF0
        self.assertEqual(
            x301.clamp_secret_bytes(bytes(first)),
            x301.clamp_secret_bytes(bytes(second)),
        )
        self.assertEqual(
            x301.public_from_secret(bytes(first)),
            x301.public_from_secret(bytes(second)),
        )


class KeyGenTests(unittest.TestCase):
    def test_keygen_resamples_only_invalid_twist_scalar(self):
        invalid = x301.N_TWIST.to_bytes(38, "little")
        valid = bytes(range(38))
        values = iter((invalid, valid))
        calls = []

        def source(length):
            calls.append(length)
            return next(values)

        secret, public = x301.keygen(source)
        self.assertEqual(calls, [38, 38])
        self.assertEqual(secret, valid)
        self.assertEqual(public, x301.public_from_secret(valid))

    def test_keygen_rejects_broken_rng_length(self):
        with self.assertRaises(ValueError):
            x301.keygen(lambda _: b"\x00" * 37)


if __name__ == "__main__":
    unittest.main(verbosity=2)
