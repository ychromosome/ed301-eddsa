#!/usr/bin/env python3
"""Consistency tests for the normative ED301 machine-readable parameter set."""

from __future__ import annotations

import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
REFERENCE_DIR = ROOT / "referenz"
sys.path.insert(0, str(REFERENCE_DIR))

import ed301_curve as ec  # noqa: E402


PARAMETER_PATH = ROOT / "parameter" / "ed301-v1.json"


class ParameterJsonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(PARAMETER_PATH.read_text(encoding="utf-8"))

    def test_schema_and_derivation(self):
        data = self.data
        self.assertEqual(data["schema"], "ED301-parameter-set-v1")
        derivation = data["derivation"]
        self.assertEqual(int(derivation["first_passing_counter"]), 44730)
        self.assertEqual(int(derivation["s"]), 45677)
        self.assertEqual(int(derivation["a"]), 45677**2)
        self.assertEqual(int(derivation["a"]), ec.A_EDWARDS)

    def test_field_and_edwards_parameters(self):
        data = self.data
        field = data["field"]
        edwards = data["edwards"]
        self.assertEqual(int(field["p_decimal"]), ec.P)
        self.assertEqual(int(field["p_hex"], 16), ec.P)
        self.assertEqual(field["bit_length"], ec.P.bit_length())
        self.assertEqual(field["p_mod_4"], ec.P % 4)
        self.assertEqual(field["p_mod_8"], ec.P % 8)
        self.assertEqual(int(edwards["a_decimal"]), ec.A_EDWARDS)
        self.assertEqual(int(edwards["a_hex"], 16), ec.A_EDWARDS)
        self.assertEqual(int(edwards["d_decimal"]), ec.D_EDWARDS)
        self.assertEqual(int(edwards["d_hex"], 16), ec.D_EDWARDS)
        self.assertTrue(edwards["addition_complete"])
        self.assertEqual(
            (int(edwards["identity"]["x"]), int(edwards["identity"]["y"])),
            ec.IDENTITY,
        )
        self.assertEqual(
            (int(edwards["order_2_point"]["x"]), int(edwards["order_2_point"]["y"])),
            ec.ORDER_2,
        )

    def test_group_relations(self):
        group = self.data["group"]
        twist = self.data["twist"]
        n = int(group["order_N_decimal"])
        q = int(group["q_decimal"])
        nt = int(twist["order_decimal"])
        qt = int(twist["q_twist_decimal"])
        self.assertEqual(n, ec.N)
        self.assertEqual(q, ec.Q)
        self.assertEqual(n, group["cofactor_h"] * q)
        self.assertEqual(nt, twist["cofactor"] * qt)
        self.assertEqual(n + nt, 2 * ec.P + 2)
        self.assertEqual(int(group["order_N_hex"], 16), n)
        self.assertEqual(int(group["q_hex"], 16), q)
        self.assertEqual(int(twist["order_hex"], 16), nt)
        self.assertEqual(int(twist["q_twist_hex"], 16), qt)
        self.assertEqual(int(group["frobenius_trace"]), ec.P + 1 - n)
        self.assertEqual(int(twist["frobenius_trace"]), ec.P + 1 - nt)
        self.assertEqual(int(group["embedding_degree"]), q - 1)
        self.assertEqual(int(twist["embedding_degree"]), qt - 1)

    def test_montgomery_and_weierstrass_parameters(self):
        montgomery = self.data["montgomery"]
        weierstrass = self.data["weierstrass"]
        self.assertEqual(int(montgomery["A_decimal"]), ec.A_MONTGOMERY)
        self.assertEqual(int(montgomery["A_hex"], 16), ec.A_MONTGOMERY)
        self.assertEqual(int(montgomery["B_decimal"]), ec.B_MONTGOMERY)
        self.assertEqual(int(montgomery["B_hex"], 16), ec.B_MONTGOMERY)
        self.assertEqual(int(montgomery["A24_minus_decimal"]), ec.A24_MINUS)
        self.assertEqual(int(montgomery["A24_minus_hex"], 16), ec.A24_MINUS)
        self.assertEqual(montgomery["A24_convention"], "minus")

        coefficients = [int(value) for value in weierstrass["coefficients"]]
        self.assertEqual(coefficients[0::2], [0, 0, 0])
        self.assertEqual(coefficients[1], ec.A_MONTGOMERY * ec.B_MONTGOMERY % ec.P)
        self.assertEqual(coefficients[3], ec.B_MONTGOMERY**2 % ec.P)

        twist_coefficients = [int(value) for value in self.data["twist"]["weierstrass_coefficients"]]
        self.assertEqual(twist_coefficients[1], 2 * coefficients[1] % ec.P)
        self.assertEqual(twist_coefficients[3], 4 * coefficients[3] % ec.P)

    def test_basepoint_and_encodings(self):
        basepoint = self.data["basepoint"]
        encoding = self.data["encoding"]
        point = (
            int(basepoint["G_edwards_x_decimal"]),
            int(basepoint["G_edwards_y_decimal"]),
        )
        self.assertEqual(point, ec.G)
        self.assertEqual(bytes.fromhex(basepoint["G_compressed_edwards_hex"]), ec.G_ENCODING)
        self.assertEqual(ec.decode_point(ec.G_ENCODING, require_prime_order=True), ec.G)
        self.assertEqual(ec.scalar_multiply(ec.Q, ec.G), ec.IDENTITY)

        montgomery_point = ec.edwards_to_montgomery(ec.G)
        self.assertEqual(int(basepoint["G_montgomery_u_decimal"]), montgomery_point[0])
        self.assertEqual(int(basepoint["G_montgomery_v_decimal"]), montgomery_point[1])
        self.assertEqual(
            bytes.fromhex(basepoint["G_montgomery_u_little_endian_hex"]),
            montgomery_point[0].to_bytes(38, "little"),
        )
        self.assertEqual(
            bytes.fromhex(basepoint["G_montgomery_v_little_endian_hex"]),
            montgomery_point[1].to_bytes(38, "little"),
        )
        self.assertEqual(encoding["field_bytes"], ec.FIELD_BYTES)
        self.assertEqual(encoding["point_bytes"], ec.FIELD_BYTES)
        self.assertEqual(encoding["scalar_bytes"], ec.SCALAR_BYTES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
