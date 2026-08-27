#!/usr/bin/env python3
"""Tests for the non-production ED301 c44730 curve reference module."""

import pathlib
import sys
import unittest


REFERENCE_DIR = pathlib.Path(__file__).resolve().parents[1] / "referenz"
sys.path.insert(0, str(REFERENCE_DIR))

import ed301_curve as ec  # noqa: E402


class ParameterTests(unittest.TestCase):
    def test_reference_warning_and_parameters(self):
        self.assertFalse(ec.PRODUCTION_READY)
        self.assertIn("not production-ready", ec.SECURITY_WARNING)
        self.assertEqual(ec.P, (1 << 301) - (1 << 99) + 947)
        self.assertEqual(ec.A_EDWARDS, 2086388329)
        self.assertEqual(ec.D_EDWARDS, 301)
        self.assertEqual(ec.H, 4)
        self.assertEqual(ec.N, ec.H * ec.Q)
        self.assertEqual(ec.P % 4, 3)

    def test_basepoint_constants(self):
        self.assertTrue(ec.verify_basepoint())
        self.assertTrue(ec.is_on_curve(ec.G))
        self.assertNotEqual(ec.G, ec.IDENTITY)
        self.assertTrue(ec.is_in_prime_subgroup(ec.G, allow_identity=False))
        self.assertEqual(ec.encode_point(ec.G), ec.G_ENCODING)

    def test_montgomery_constants(self):
        inv4 = pow(4, ec.P - 2, ec.P)
        self.assertEqual(ec.A24_MINUS, (ec.A_MONTGOMERY - 2) * inv4 % ec.P)
        self.assertNotEqual(ec.A_MONTGOMERY, 2)
        self.assertNotEqual(ec.A_MONTGOMERY, ec.P - 2)
        self.assertNotEqual(ec.B_MONTGOMERY, 0)


class EdwardsArithmeticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.order4 = (pow(45677, ec.P - 2, ec.P), 0)

    def test_identity(self):
        self.assertTrue(ec.is_on_curve(ec.IDENTITY))
        self.assertEqual(ec.point_add(ec.G, ec.IDENTITY), ec.G)
        self.assertEqual(ec.point_add(ec.IDENTITY, ec.G), ec.G)
        self.assertEqual(ec.scalar_multiply(0, ec.G), ec.IDENTITY)
        self.assertEqual(ec.scalar_multiply(1, ec.G), ec.G)

    def test_negation_and_subtraction(self):
        neg = ec.point_negate(ec.G)
        self.assertEqual(ec.point_add(ec.G, neg), ec.IDENTITY)
        self.assertEqual(ec.point_subtract(ec.G, ec.G), ec.IDENTITY)
        self.assertEqual(ec.scalar_multiply(-1, ec.G), neg)
        self.assertEqual(ec.scalar_multiply(ec.Q - 1, ec.G), neg)

    def test_order_two(self):
        self.assertTrue(ec.is_on_curve(ec.ORDER_2))
        self.assertEqual(ec.point_double(ec.ORDER_2), ec.IDENTITY)
        self.assertEqual(ec.scalar_multiply(2, ec.ORDER_2), ec.IDENTITY)
        self.assertFalse(ec.is_in_prime_subgroup(ec.ORDER_2))

    def test_order_four(self):
        self.assertTrue(ec.is_on_curve(self.order4))
        self.assertEqual(ec.point_double(self.order4), ec.ORDER_2)
        self.assertEqual(ec.scalar_multiply(4, self.order4), ec.IDENTITY)
        self.assertNotEqual(ec.scalar_multiply(2, self.order4), ec.IDENTITY)
        self.assertFalse(ec.is_in_prime_subgroup(self.order4))

    def test_basepoint_order(self):
        self.assertEqual(ec.scalar_multiply(ec.Q, ec.G), ec.IDENTITY)
        self.assertNotEqual(ec.scalar_multiply(ec.Q - 1, ec.G), ec.IDENTITY)
        self.assertEqual(ec.scalar_multiply(2, ec.G), ec.point_double(ec.G))

    def test_reject_off_curve_inputs(self):
        self.assertFalse(ec.is_on_curve((1, 1)))
        self.assertFalse(ec.is_on_curve((ec.P, 1)))
        with self.assertRaises(ValueError):
            ec.point_add((1, 1), ec.G)
        with self.assertRaises(ValueError):
            ec.scalar_multiply(1, (1, 1))


class EncodingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.order4 = (pow(45677, ec.P - 2, ec.P), 0)

    def test_field_roundtrips(self):
        for value in (0, 1, ec.P - 1):
            encoded = ec.encode_field(value)
            self.assertEqual(len(encoded), 38)
            self.assertEqual(ec.decode_field(encoded), value)

    def test_field_rejections(self):
        with self.assertRaises(ValueError):
            ec.encode_field(-1)
        with self.assertRaises(ValueError):
            ec.encode_field(ec.P)
        with self.assertRaises(ValueError):
            ec.decode_field(b"\x00" * 37)
        with self.assertRaises(ValueError):
            ec.decode_field(ec.P.to_bytes(38, "little"))
        for mask in (0x20, 0x40, 0x80):
            invalid = bytearray(38)
            invalid[37] = mask
            with self.assertRaises(ValueError):
                ec.decode_field(bytes(invalid))

    def test_scalar_roundtrips(self):
        for value in (0, 1, ec.Q - 1):
            encoded = ec.encode_scalar(value)
            self.assertEqual(len(encoded), 38)
            self.assertEqual(ec.decode_scalar(encoded), value)

    def test_scalar_rejections(self):
        with self.assertRaises(ValueError):
            ec.encode_scalar(-1)
        with self.assertRaises(ValueError):
            ec.encode_scalar(ec.Q)
        with self.assertRaises(ValueError):
            ec.decode_scalar(b"\x00" * 37)
        with self.assertRaises(ValueError):
            ec.decode_scalar(ec.Q.to_bytes(38, "little"))
        for mask in (0x10, 0x20, 0x40, 0x80):  # Overall bits 300..303.
            invalid = bytearray(38)
            invalid[37] = mask
            with self.assertRaises(ValueError):
                ec.decode_scalar(bytes(invalid))

    def test_point_roundtrips(self):
        points = (ec.IDENTITY, ec.ORDER_2, self.order4, ec.G, ec.point_negate(ec.G))
        for point in points:
            encoded = ec.encode_point(point)
            self.assertEqual(len(encoded), 38)
            self.assertEqual(encoded[37] & 0x60, 0)
            self.assertEqual(ec.decode_point(encoded), point)

    def test_strict_prime_order_decode(self):
        self.assertEqual(ec.decode_point(ec.G_ENCODING, require_prime_order=True), ec.G)
        for point in (ec.IDENTITY, ec.ORDER_2, self.order4):
            with self.assertRaises(ValueError):
                ec.decode_point(ec.encode_point(point), require_prime_order=True)

    def test_point_rejections(self):
        with self.assertRaises(ValueError):
            ec.encode_point((1, 1))
        with self.assertRaises(ValueError):
            ec.decode_point(b"\x00" * 37)

        for mask in (0x20, 0x40):
            invalid = bytearray(ec.G_ENCODING)
            invalid[37] |= mask
            with self.assertRaises(ValueError):
                ec.decode_point(bytes(invalid))

        noncanonical_y = bytearray(ec.P.to_bytes(38, "little"))
        with self.assertRaises(ValueError):
            ec.decode_point(bytes(noncanonical_y))

        identity_wrong_sign = bytearray(ec.encode_point(ec.IDENTITY))
        identity_wrong_sign[37] |= 0x80
        with self.assertRaises(ValueError):
            ec.decode_point(bytes(identity_wrong_sign))

        nonsquare_y = None
        for y in range(2, 1000):
            try:
                ec.recover_x(y, 0)
            except ValueError as exc:
                if "not a square" in str(exc):
                    nonsquare_y = y
                    break
        self.assertIsNotNone(nonsquare_y)
        with self.assertRaises(ValueError):
            ec.decode_point(nonsquare_y.to_bytes(38, "little"))


class MappingAndLadderTests(unittest.TestCase):
    def test_edwards_montgomery_roundtrips(self):
        for scalar in (1, 2, 3, 4, 5, 17, 12345, ec.Q - 1):
            edwards = ec.scalar_multiply(scalar, ec.G)
            montgomery = ec.edwards_to_montgomery(edwards)
            self.assertTrue(ec.is_on_montgomery(montgomery))
            self.assertEqual(ec.montgomery_to_edwards(montgomery), edwards)

    def test_mapping_exception_cases(self):
        with self.assertRaises(ValueError):
            ec.edwards_to_montgomery(ec.IDENTITY)
        with self.assertRaises(ValueError):
            ec.edwards_to_montgomery(ec.ORDER_2)
        self.assertTrue(ec.is_on_montgomery((0, 0)))
        with self.assertRaises(ValueError):
            ec.montgomery_to_edwards((0, 0))
        with self.assertRaises(ValueError):
            ec.montgomery_to_edwards((1, 1))

    def test_ladder_matches_general_edwards_multiplication(self):
        base_u, _ = ec.edwards_to_montgomery(ec.G)
        for scalar in (1, 2, 3, 4, 5, 8, 17, 31, 12345, ec.Q - 1):
            expected_point = ec.scalar_multiply(scalar, ec.G)
            expected_u, _ = ec.edwards_to_montgomery(expected_point)
            self.assertEqual(ec.montgomery_ladder_u(scalar, base_u), expected_u)

    def test_ladder_infinity_and_input_rejections(self):
        base_u, _ = ec.edwards_to_montgomery(ec.G)
        self.assertIsNone(ec.montgomery_ladder_u(0, base_u))
        self.assertIsNone(ec.montgomery_ladder_u(ec.Q, base_u))
        with self.assertRaises(ValueError):
            ec.montgomery_ladder_u(-1, base_u)
        with self.assertRaises(ValueError):
            ec.montgomery_ladder_u(1 << 301, base_u)
        with self.assertRaises(ValueError):
            ec.montgomery_ladder_u(1, ec.P)


if __name__ == "__main__":
    unittest.main(verbosity=2)
