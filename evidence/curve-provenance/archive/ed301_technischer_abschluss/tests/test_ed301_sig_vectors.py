#!/usr/bin/env python3
"""Verify the checked-in Ed301-Sig-v1 machine-readable vector package."""

from __future__ import annotations

import hashlib
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
import ed301_sig as sig  # noqa: E402
import generate_ed301_sig_v1_vectors as generator  # noqa: E402


POSITIVE_PATH = ROOT / "vektoren" / "ed301-sig-v1-positive.json"
NEGATIVE_PATH = ROOT / "vektoren" / "ed301-sig-v1-negative.json"


def load(path: pathlib.Path):
    return json.loads(path.read_text(encoding="utf-8"))


class VectorPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.positive = load(POSITIVE_PATH)
        cls.negative = load(NEGATIVE_PATH)
        # A full in-memory regeneration independently compares every recorded
        # frame, XOF output, scalar, coordinate, encoding and expected result.
        cls.regenerated_positive, cls.regenerated_negative = generator.generate_packages()

    def test_packages_are_exact_canonical_regeneration(self):
        self.assertEqual(self.positive, self.regenerated_positive)
        self.assertEqual(self.negative, self.regenerated_negative)
        self.assertEqual(
            POSITIVE_PATH.read_text(encoding="utf-8"),
            generator.canonical_json(self.positive),
        )
        self.assertEqual(
            NEGATIVE_PATH.read_text(encoding="utf-8"),
            generator.canonical_json(self.negative),
        )

    def test_embedded_source_hashes(self):
        expected = {
            item["path"]: item["sha256"] for item in generator.sources()
        }
        for document in (self.positive, self.negative):
            actual = {item["path"]: item["sha256"] for item in document["sources"]}
            self.assertEqual(actual, expected)
            for digest in actual.values():
                self.assertEqual(len(digest), 64)
                int(digest, 16)

    def test_positive_coverage_and_verification(self):
        vectors = self.positive["vectors"]
        self.assertEqual(int(self.positive["vector_count_decimal"]), len(vectors))
        self.assertGreaterEqual(len(vectors), 5)
        contexts = [bytes.fromhex(item["inputs"]["context_hex"]) for item in vectors]
        messages = [bytes.fromhex(item["inputs"]["message_hex"]) for item in vectors]
        self.assertIn(0, map(len, contexts))
        self.assertIn(255, map(len, contexts))
        self.assertIn(0, map(len, messages))
        self.assertTrue(any(0 < len(message) < 64 for message in messages))
        self.assertTrue(any(len(message) >= 4096 for message in messages))

        for item in vectors:
            inputs = item["inputs"]
            seed = bytes.fromhex(inputs["seed_hex"])
            context = bytes.fromhex(inputs["context_hex"])
            message = bytes.fromhex(inputs["message_hex"])
            public_key = bytes.fromhex(item["key_derivation"]["public_key_hex"])
            signature = bytes.fromhex(item["result"]["signature_hex"])
            self.assertEqual(len(seed), 38, item["id"])
            self.assertEqual(len(public_key), 38, item["id"])
            self.assertEqual(len(signature), 76, item["id"])
            self.assertTrue(sig.verify(public_key, context, message, signature), item["id"])
            self.assertEqual(sig.sign(seed, context, message), signature, item["id"])

    def test_deterministic_repeat(self):
        by_id = {item["id"]: item for item in self.positive["vectors"]}
        repeated = by_id["positive-short-deterministic-repeat"]
        original = by_id[repeated["repeat_of"]]
        self.assertEqual(repeated["inputs"], original["inputs"])
        self.assertEqual(repeated["key_derivation"], original["key_derivation"])
        self.assertEqual(repeated["nonce_derivation"], original["nonce_derivation"])
        self.assertEqual(repeated["challenge_derivation"], original["challenge_derivation"])
        self.assertEqual(repeated["result"], original["result"])
        seed = bytes.fromhex(original["inputs"]["seed_hex"])
        context = bytes.fromhex(original["inputs"]["context_hex"])
        message = bytes.fromhex(original["inputs"]["message_hex"])
        signatures = {sig.sign(seed, context, message) for _ in range(3)}
        self.assertEqual(len(signatures), 1)

    def test_all_verification_negatives_reject(self):
        vectors = self.negative["verification_vectors"]
        self.assertEqual(
            int(self.negative["verification_vector_count_decimal"]), len(vectors)
        )
        self.assertGreaterEqual(len(vectors), 30)
        for item in vectors:
            self.assertIs(item["expected_verify"], False)
            message = bytes.fromhex(item["message_hex"])
            announced = int(item["message_length_decimal"])
            actual = (
                0 <= announced <= sig.MAX_U64
                and announced == len(message)
                and sig.verify(
                    bytes.fromhex(item["public_key_hex"]),
                    bytes.fromhex(item["context_hex"]),
                    message,
                    bytes.fromhex(item["signature_hex"]),
                )
            )
            self.assertFalse(
                actual,
                item["id"],
            )

    def test_required_negative_classes_present(self):
        ids = {item["id"] for item in self.negative["verification_vectors"]}
        required = {
            "negative-message-manipulated",
            "negative-context-manipulated",
            "negative-public-key-substituted",
            "negative-signature-S-manipulated",
            "negative-public-key-short",
            "negative-signature-long",
            "negative-message-length-announced-short",
            "negative-message-length-announced-long",
            "negative-message-length-u64-overflow",
            "negative-S-equal-q",
            "negative-S-greater-q",
            "negative-public-key-reserved-bit-301",
            "negative-R-reserved-bit-302",
            "negative-public-key-y-equal-p",
            "negative-R-identity",
            "negative-public-key-torsion-order-4",
            "negative-R-mixed-order-4q",
            "negative-public-key-nonreconstructable",
            "negative-R-x0-sign-one",
            "negative-context-256",
            "negative-wrong-suite",
            "negative-wrong-version",
            "negative-wrong-mode",
            "negative-wrong-domain-prefix",
            "negative-wrong-operation",
            "negative-wrong-field-count",
            "negative-wrong-R-tag",
            "negative-wrong-field-order",
        }
        self.assertFalse(required - ids)
        categories = {item["category"] for item in self.negative["verification_vectors"]}
        self.assertTrue(
            {
                "binding",
                "length",
                "scalar-canonicality",
                "point-canonicality",
                "point-decoding",
                "subgroup",
                "input-boundary",
                "domain-separation",
                "framing",
            }.issubset(categories)
        )

    def test_internal_vectors_are_separately_classified(self):
        internal = self.negative["internal_only"]
        self.assertIn("not ordinary verification vectors", internal["classification"])
        ordinary_ids = {item["id"] for item in self.negative["verification_vectors"]}
        internal_ids = {
            item["id"]
            for group in (internal["null_and_retry"], internal["framing"])
            for item in group
        }
        self.assertFalse(ordinary_ids & internal_ids)

    def test_internal_zero_and_retry_semantics(self):
        internal = {
            item["id"]: item
            for item in self.negative["internal_only"]["null_and_retry"]
        }
        key = internal["internal-key-scalar-zero-then-one"]
        key_frames = iter(bytes.fromhex(value) for value in key["frame_hex"])
        seen = []

        def key_frame(retry):
            frame = next(key_frames)
            seen.append((retry, frame))
            return frame

        with mock.patch.object(
            sig,
            "_shake256",
            side_effect=[bytes.fromhex(value) for value in key["injected_xof64_hex"]],
        ):
            scalar, retry = sig._derive_nonzero_scalar(key_frame)
        self.assertEqual((scalar, retry), (1, 1))
        self.assertEqual([value[0] for value in seen], [0, 1])

        nonce = internal["internal-nonce-zero-then-one"]
        nonce_frames = iter(bytes.fromhex(value) for value in nonce["frame_hex"])
        with mock.patch.object(
            sig,
            "_shake256",
            side_effect=[bytes.fromhex(value) for value in nonce["injected_xof64_hex"]],
        ):
            scalar, retry = sig._derive_nonzero_scalar(lambda _: next(nonce_frames))
        self.assertEqual((scalar, retry), (1, 1))

        with mock.patch.object(sig, "_shake256", return_value=b"\x00" * 64):
            with self.assertRaises(OverflowError):
                sig._derive_nonzero_scalar(
                    lambda retry: sig._frame_secret_scalar(bytes(range(38)), retry),
                    start_retry=sig.MAX_U32,
                )

        # The synthetic S=0 row checks the equation without replacing SHAKE in
        # the public API: [0]G = [1]G + [q-1][1]G.
        left = curve.scalar_multiply(0, curve.G)
        right = curve.point_add(
            curve.G, curve.scalar_multiply(curve.Q - 1, curve.G)
        )
        self.assertEqual(left, right)
        self.assertEqual(curve.decode_scalar(b"\x00" * 38), 0)

    def test_internal_framing_changes_bytes_and_xof(self):
        for item in self.negative["internal_only"]["framing"]:
            canonical = bytes.fromhex(item["canonical_frame_hex"])
            altered = bytes.fromhex(item["altered_frame_hex"])
            self.assertNotEqual(canonical, altered, item["id"])
            self.assertEqual(sig._shake256(canonical).hex(), item["canonical_xof64_hex"])
            self.assertEqual(sig._shake256(altered).hex(), item["altered_xof64_hex"])
            self.assertNotEqual(item["canonical_xof64_hex"], item["altered_xof64_hex"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
