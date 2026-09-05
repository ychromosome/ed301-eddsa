#!/usr/bin/env python3
"""Exact-regeneration tests for the X301-v1 vector packages."""

from __future__ import annotations

import json
import pathlib
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "referenz"
SCRIPTS = ROOT / "scripts"
for directory in (REFERENCE, SCRIPTS):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import ed301_curve as curve  # noqa: E402
import generate_x301_v1_vectors as generator  # noqa: E402
import x301  # noqa: E402


POSITIVE_PATH = ROOT / "vektoren" / "x301-v1-positive.json"
NEGATIVE_PATH = ROOT / "vektoren" / "x301-v1-negative.json"


class X301VectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.positive = json.loads(POSITIVE_PATH.read_text(encoding="utf-8"))
        cls.negative = json.loads(NEGATIVE_PATH.read_text(encoding="utf-8"))
        cls.generated_positive, cls.generated_negative = generator.generate_packages()

    def test_exact_canonical_regeneration(self):
        self.assertEqual(self.positive, self.generated_positive)
        self.assertEqual(self.negative, self.generated_negative)
        self.assertEqual(
            POSITIVE_PATH.read_text(encoding="utf-8"),
            generator.canonical_json(self.positive),
        )
        self.assertEqual(
            NEGATIVE_PATH.read_text(encoding="utf-8"),
            generator.canonical_json(self.negative),
        )

    def test_source_hashes_are_current(self):
        expected = {item["path"]: item["sha256"] for item in generator.source_records()}
        for document in (self.positive, self.negative):
            actual = {item["path"]: item["sha256"] for item in document["sources"]}
            self.assertEqual(actual, expected)
        self.assertEqual(
            expected["referenz/x301.py"],
            "acf12998fa26f6d19d97ae356ddf9a973994b5b5166034a259c4aaf533aa7dfe",
        )
        self.assertEqual(
            expected["spezifikation/X301-v1.md"],
            "214f5385747f859e39e68407bcdbde49776f7e3d0b37de6e1aa6c1663352b592",
        )

    def test_positive_vectors_include_full_ladder_trace(self):
        vectors = self.positive["vectors"]
        self.assertEqual(int(self.positive["positive_vector_count_decimal"]), 10)
        models = set()
        for item in vectors:
            secret = bytes.fromhex(item["secret_input_hex"])
            u_encoding = bytes.fromhex(item["input_u"]["encoding_le38_hex"])
            u = curve.decode_field(u_encoding)
            scalar = x301.decode_secret_scalar(secret)
            projective_x, projective_z, iterations = generator.traced_ladder(scalar, u)
            self.assertEqual(iterations, 301, item["id"])
            self.assertEqual(
                projective_x, int(item["ladder"]["projective_X"]["decimal"]), item["id"]
            )
            self.assertEqual(
                projective_z, int(item["ladder"]["projective_Z"]["decimal"]), item["id"]
            )
            self.assertNotEqual(projective_z, 0, item["id"])
            affine = projective_x * pow(projective_z, curve.P - 2, curve.P) % curve.P
            self.assertEqual(affine, int(item["ladder"]["affine_u"]["decimal"]), item["id"])
            self.assertEqual(curve.encode_field(affine).hex(), item["output_encoding_hex"])
            self.assertTrue(item["independent_crosscheck"]["matches_ladder"])
            self.assertEqual(
                item["independent_crosscheck"]["method"],
                "independent-general-affine-Montgomery-group-law",
            )
            models.add(item["input_u"]["model"])
            if item["operation"] == "Public":
                self.assertEqual(x301.public_from_secret(secret).hex(), item["output_encoding_hex"])
            else:
                self.assertEqual(
                    x301.shared_secret(secret, u_encoding).hex(), item["output_encoding_hex"]
                )
        self.assertEqual(models, {"main", "twist-z2"})

    def test_section_13_and_mutual_agreements(self):
        by_id = {item["id"]: item for item in self.positive["vectors"]}
        self.assertEqual(
            by_id["public-a-section-13"]["output_encoding_hex"],
            "b5d19e31e6bfa6f5c47411738360ba94b7bbff1c4bb9fc646e9775bbd7565a6052819781c21a",
        )
        self.assertEqual(
            by_id["public-b-section-13"]["output_encoding_hex"],
            "86a7fa2ccb11a76c34fd7bca0f6e592c9991cb554cd7b326a2177df7dbb0f4c514381519921d",
        )
        self.assertEqual(
            by_id["shared-a-with-b"]["output_encoding_hex"],
            "70a54bebecf4a6f68aa30e6b081d29fb59da71ebd6fbf34f14780650ea2baa076c3afc7a4111",
        )
        self.assertEqual(int(self.positive["agreement_pair_count_decimal"]), 2)
        for pair in self.positive["agreement_pairs"]:
            self.assertEqual(
                by_id[pair["a_to_b_vector"]]["output_encoding_hex"],
                pair["shared_encoding_hex"],
            )
            self.assertEqual(
                by_id[pair["b_to_a_vector"]]["output_encoding_hex"],
                pair["shared_encoding_hex"],
            )

    def test_exact_298_variable_bits_and_64_raw_preimages(self):
        analysis = self.positive["clamp_analysis"]
        self.assertEqual(analysis["variable_bit_positions"], [2, 299])
        self.assertEqual(int(analysis["variable_bit_count_decimal"]), 298)
        self.assertEqual(len(analysis["variable_bit_flip_deltas_decimal"]), 298)
        self.assertEqual(
            [int(value) for value in analysis["variable_bit_flip_deltas_decimal"]],
            [1 << bit for bit in range(2, 300)],
        )
        self.assertEqual(
            analysis["ignored_or_overwritten_raw_bit_positions"], [0, 1, 300, 301, 302, 303]
        )
        preimages = [bytes.fromhex(value) for value in analysis["raw_preimages_hex"]]
        self.assertEqual(len(preimages), 64)
        self.assertEqual(len(set(preimages)), 64)
        common = bytes.fromhex(analysis["common_clamped_bytes_hex"])
        self.assertEqual({x301.clamp_secret_bytes(value) for value in preimages}, {common})
        self.assertEqual(int(analysis["minimum_clamp"]["k"]["decimal"]), 1 << 300)
        self.assertEqual(int(analysis["maximum_clamp"]["k"]["decimal"]), (1 << 301) - 4)

    def test_nt_has_64_preimages_and_several_ordinary_negatives(self):
        proof = self.negative["excluded_Nt_preimage_proof"]
        preimages = [bytes.fromhex(value) for value in proof["raw_preimages_hex"]]
        self.assertEqual(len(preimages), 64)
        self.assertEqual(len(set(preimages)), 64)
        self.assertEqual(
            {int.from_bytes(generator.clamp_without_rejection(value), "little") for value in preimages},
            {x301.N_TWIST},
        )
        self.assertEqual(len(proof["ordinary_negative_vector_ids"]), 4)
        api_ids = {item["id"] for item in self.negative["api_vectors"]}
        self.assertTrue(set(proof["ordinary_negative_vector_ids"]).issubset(api_ids))

    def test_all_ordinary_api_negatives_fail(self):
        vectors = self.negative["api_vectors"]
        self.assertEqual(int(self.negative["api_vector_count_decimal"]), len(vectors))
        for item in vectors:
            self.assertEqual(item["expected"], "FAIL")
            generator.execute_negative_api_case(item)
        required = {
            "secret-length-37",
            "secret-length-39",
            "secret-not-bytes",
            "secret-clamps-to-Nt-preimage-0",
            "u-length-37",
            "u-length-39",
            "u-not-bytes",
            "u-reserved-bit-301",
            "u-reserved-bit-302",
            "u-reserved-bit-303",
            "u-equal-p",
            "u-equal-p-plus-1",
            "u-zero",
            "u-one",
            "u-p-minus-1",
        }
        self.assertTrue(required.issubset({item["id"] for item in vectors}))
        stages = {item["rejection_stage"] for item in vectors}
        self.assertTrue(
            {
                "secret-length",
                "secret-type",
                "decode-scalar-Nt",
                "u-length",
                "u-type",
                "decode-u-reserved-bits",
                "decode-u-range",
                "ladder-Z-zero",
            }.issubset(stages)
        )

    def test_outer_parser_suite_and_version_reject_before_x301(self):
        vectors = self.negative["outer_parser_vectors"]
        self.assertEqual(int(self.negative["outer_parser_vector_count_decimal"]), 2)

        def parse_and_run(item):
            if item["suite"] != "X301-v1":
                return False
            if int(item["version_decimal"]) != 1:
                return False
            x301.shared_secret(
                bytes.fromhex(item["secret_hex"]), bytes.fromhex(item["u_hex"])
            )
            return True

        with mock.patch.object(x301, "shared_secret", side_effect=AssertionError("called")) as call:
            for item in vectors:
                self.assertFalse(parse_and_run(item), item["id"])
            call.assert_not_called()

    def test_internal_keygen_retry_is_separate_and_exact(self):
        internal = self.negative["internal_only"]
        self.assertIn("not ordinary X301 input vectors", internal["classification"])
        vector = internal["keygen_retry"]
        draws = iter(bytes.fromhex(value) for value in vector["random_draws_hex"])
        calls = []

        def source(length):
            calls.append(length)
            return next(draws)

        secret, public = x301.keygen(source)
        self.assertEqual(len(calls), int(vector["expected_draw_count_decimal"]))
        self.assertEqual(secret.hex(), vector["expected_secret_hex"])
        self.assertEqual(public.hex(), vector["expected_public_hex"])

    def test_internal_all_zero_fault_path_is_separate(self):
        vector = self.negative["internal_only"]["all_zero_rejection"]
        self.assertEqual(vector["expected_rejection_stage"], "post-ladder-AllZero")
        with mock.patch.object(curve, "montgomery_ladder_u", return_value=0):
            with self.assertRaisesRegex(ValueError, "all-zero"):
                x301.shared_secret(generator.SECRET_A, x301.BASE_U_ENCODING)


if __name__ == "__main__":
    unittest.main(verbosity=2)
