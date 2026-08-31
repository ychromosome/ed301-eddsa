extern crate std;

use std::{string::String, vec::Vec};

use super::{
    edwards::EdwardsPoint,
    parameters::{HASH_BYTES, PUBLIC_KEY_BYTES, SEED_BYTES, SIGNATURE_BYTES},
    scalar::Scalar,
    signature::{Signature, SigningKey, VerifyingKey, test_support::trace},
    signature_hash::{Domain, challenge_hash, hash_to_scalar},
    validate_public_key, verify, verify_with_context,
};

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid fixture hex"),
    }
}

fn array<const N: usize>(value: &str) -> [u8; N] {
    decode_hex(value).try_into().expect("fixture length")
}

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../inputs/v1/ed301-eddsa-v1.json"))
        .expect("positive vectors parse")
}

fn edges() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../inputs/v1/ed301-eddsa-edge-v1.json"))
        .expect("edge vectors parse")
}

fn blind_oracle_vectors() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../provider-tests/oracle/blind-0c482948/blind_oracle_vectors.json"
    ))
    .expect("blind differential vectors parse")
}

fn by_id<'a>(items: &'a [serde_json::Value], id: &str) -> &'a serde_json::Value {
    items
        .iter()
        .find(|item| item["id"] == id)
        .unwrap_or_else(|| panic!("missing fixture id {id}"))
}

#[test]
fn all_positive_vectors_and_intermediates_match() {
    let document = fixture();
    assert_eq!(document["specification"], "Ed301-EdDSA-v1");
    assert_eq!(document["parameters"]["domain_prefix_ascii"], "SigEd301-v1");
    assert_eq!(document["parameters"]["phflag"], 0);
    assert_eq!(document["parameters"]["max_context_bytes"], 255);
    assert_eq!(document["parameters"]["hash_output_bytes"], HASH_BYTES);
    assert_eq!(document["parameters"]["seed_bytes"], SEED_BYTES);
    assert_eq!(document["parameters"]["public_key_bytes"], PUBLIC_KEY_BYTES);
    assert_eq!(document["parameters"]["signature_bytes"], SIGNATURE_BYTES);

    let cases = document["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 4);
    for case in cases {
        let string = |name: &str| case[name].as_str().expect("fixture string");
        let seed = array::<38>(string("seed_hex"));
        let message = decode_hex(string("message_hex"));
        let expected_public = array::<38>(string("public_key_hex"));
        let expected_signature = array::<76>(string("signature_hex"));
        let actual = trace(&seed, &message);

        assert_eq!(
            actual.expanded_hash,
            array::<76>(string("expanded_hash_hex"))
        );
        assert_eq!(
            actual.pruned_scalar,
            array::<38>(string("pruned_secret_scalar_le_hex"))
        );
        assert_eq!(actual.prefix, array::<38>(string("prefix_hex")));
        assert_eq!(actual.public_key, expected_public);
        assert_eq!(actual.nonce_hash, array::<76>(string("nonce_hash_hex")));
        assert_eq!(
            actual.nonce_scalar,
            array::<38>(string("nonce_mod_L_le_hex"))
        );
        assert_eq!(actual.commitment, array::<38>(string("commitment_R_hex")));
        assert_eq!(
            actual.challenge_hash,
            array::<76>(string("challenge_hash_hex"))
        );
        assert_eq!(
            actual.challenge_scalar,
            array::<38>(string("challenge_mod_L_le_hex"))
        );
        assert_eq!(actual.response, array::<38>(string("response_S_le_hex")));
        assert_eq!(actual.signature, expected_signature);

        let signing_key = SigningKey::from_seed(&seed).expect("valid seed");
        assert_eq!(
            signing_key.verifying_key().expect("public key").to_bytes(),
            expected_public
        );
        assert_eq!(
            signing_key.sign(&message).expect("signature").to_bytes(),
            expected_signature
        );
        assert!(verify(&expected_public, &message, &expected_signature));
        assert_eq!(
            signing_key
                .sign(&message)
                .expect("deterministic")
                .to_bytes(),
            expected_signature
        );
    }
}

#[test]
fn frozen_draft00_blind_oracle_is_separated_from_v1() {
    let document = blind_oracle_vectors();
    assert_eq!(document["schema"], "ed301-eddsa-blind-differential-v1");
    assert_eq!(
        document["blind_source_sha256"],
        "2364f483696c81dba7b81f0cc37f4037983a2c6795c204586e6c09f6a3669bf3"
    );

    let cases = document["cases"].as_array().expect("blind cases");
    assert_eq!(cases.len(), 8);
    for case in cases {
        let seed = array::<38>(case["seed_hex"].as_str().expect("seed"));
        let message = decode_hex(case["message_hex"].as_str().expect("message"));
        let expected_public = array::<38>(case["public_key_hex"].as_str().expect("public key"));
        let expected_signature = array::<76>(case["signature_hex"].as_str().expect("signature"));
        let signing_key = SigningKey::from_seed(&seed).expect("valid blind seed");

        assert_eq!(
            signing_key
                .verifying_key()
                .expect("blind public key")
                .to_bytes(),
            expected_public,
            "{} public key",
            case["id"]
        );
        let v1_signature = signing_key.sign(&message).expect("v1 signature").to_bytes();
        assert_ne!(v1_signature, expected_signature, "{} signature", case["id"]);
        assert!(!verify(&expected_public, &message, &expected_signature));
        assert!(verify(&expected_public, &message, &v1_signature));
    }
}

#[test]
fn native_context_vectors_and_boundaries_match() {
    let document = fixture();
    let cases = document["context_cases"].as_array().expect("context cases");
    assert_eq!(cases.len(), 3);
    for case in cases {
        let seed = array::<38>(case["seed_hex"].as_str().expect("seed"));
        let message = decode_hex(case["message_hex"].as_str().expect("message"));
        let context = decode_hex(case["context_hex"].as_str().expect("context"));
        let public_key = array::<38>(case["public_key_hex"].as_str().expect("public key"));
        let signature = array::<76>(case["signature_hex"].as_str().expect("signature"));
        let key = SigningKey::from_seed(&seed).expect("seed");

        assert_eq!(
            key.sign_with_context(&message, &context)
                .expect("context signature")
                .to_bytes(),
            signature,
            "{}",
            case["id"]
        );
        assert!(verify_with_context(
            &public_key,
            &message,
            &context,
            &signature
        ));
        let mut different_context = context.clone();
        different_context[0] ^= 1;
        assert!(!verify_with_context(
            &public_key,
            &message,
            &different_context,
            &signature
        ));
        assert!(!verify(&public_key, &message, &signature));
    }

    let seed = [0x42_u8; 38];
    let key = SigningKey::from_seed(&seed).expect("seed");
    assert!(key.sign_with_context(b"message", &[0x5a; 255]).is_ok());
    assert!(matches!(
        key.sign_with_context(b"message", &[0x5a; 256]),
        Err(super::signature::SignatureError::InvalidContextLength)
    ));
    let public_key = key.verifying_key().expect("public key").to_bytes();
    let signature = key.sign(b"message").expect("signature").to_bytes();
    assert!(!verify_with_context(
        &public_key,
        b"message",
        &[0x5a; 256],
        &signature
    ));
}

#[test]
fn verify_rejects_a_noncanonical_commitment_encoding() {
    let positives = fixture();
    let points = edges();
    let case = &positives["cases"][0];
    let point_cases = points["point_cases"].as_array().expect("point cases");
    let mut signature = array::<76>(case["signature_hex"].as_str().expect("positive signature"));
    let noncanonical = array::<38>(
        by_id(point_cases, "y-equals-p")["encoding_hex"]
            .as_str()
            .expect("noncanonical point"),
    );
    signature[..38].copy_from_slice(&noncanonical);

    assert!(!verify(
        &array::<38>(
            case["public_key_hex"]
                .as_str()
                .expect("positive public key"),
        ),
        &decode_hex(case["message_hex"].as_str().expect("positive message")),
        &signature,
    ));
}

#[test]
fn complete_point_and_scalar_acceptance_matrices_match() {
    let document = edges();
    let points = document["point_cases"].as_array().expect("point cases");
    assert_eq!(points.len(), 14);
    let mut decode_accept = 0;
    let mut public_accept = 0;
    let mut commitment_accept = 0;
    for case in points {
        let encoded = decode_hex(case["encoding_hex"].as_str().expect("point hex"));
        let exact: Option<&[u8; 38]> = encoded.as_slice().try_into().ok();
        let decoded = exact.is_some_and(|bytes| EdwardsPoint::decode(bytes).is_ok());
        let public = validate_public_key(&encoded);
        let commitment = exact.is_some_and(|bytes| EdwardsPoint::decode(bytes).is_ok());
        let expected = &case["expected"];
        assert_eq!(
            decoded,
            expected["decode"] == "accept",
            "{} decode",
            case["id"]
        );
        assert_eq!(
            public,
            expected["public_key_policy"] == "accept",
            "{} public policy",
            case["id"]
        );
        assert_eq!(
            commitment,
            expected["commitment_policy"] == "accept",
            "{} commitment policy",
            case["id"]
        );
        decode_accept += usize::from(decoded);
        public_accept += usize::from(public);
        commitment_accept += usize::from(commitment);
    }
    assert_eq!((decode_accept, public_accept, commitment_accept), (7, 1, 7));

    let scalars = document["scalar_cases"].as_array().expect("scalar cases");
    assert_eq!(scalars.len(), 6);
    let mut accepted = 0;
    for case in scalars {
        let encoded = decode_hex(case["encoding_hex"].as_str().expect("scalar hex"));
        let parsed = encoded
            .as_slice()
            .try_into()
            .ok()
            .is_some_and(|bytes: &[u8; 38]| {
                Scalar::from_canonical_bytes(bytes).is_some().to_bool()
            });
        assert_eq!(parsed, case["expected"] == "accept", "{}", case["id"]);
        accepted += usize::from(parsed);
    }
    assert_eq!(accepted, 2);
}

#[test]
fn all_twenty_two_verification_edges_match() {
    let positives = fixture();
    let edges = edges();
    let positive_cases = positives["cases"].as_array().expect("positive cases");
    let point_cases = edges["point_cases"].as_array().expect("point cases");
    let scalar_cases = edges["scalar_cases"].as_array().expect("scalar cases");
    let verification_cases = edges["verification_cases"]
        .as_array()
        .expect("verification cases");
    assert_eq!(verification_cases.len(), 22);
    let mut accepted = 0;

    for case in verification_cases {
        let id = case["id"].as_str().expect("verification id");
        let (mut public_key, mut message, mut signature) = if let Some(input) = case.get("input") {
            (
                decode_hex(input["public_key_hex"].as_str().expect("input public key")),
                decode_hex(input["message_hex"].as_str().expect("input message")),
                decode_hex(input["signature_hex"].as_str().expect("input signature")),
            )
        } else {
            let base_id = case["base_case"].as_str().expect("base case");
            let base = by_id(positive_cases, base_id);
            (
                decode_hex(base["public_key_hex"].as_str().expect("base public key")),
                decode_hex(base["message_hex"].as_str().expect("base message")),
                decode_hex(base["signature_hex"].as_str().expect("base signature")),
            )
        };

        if let Some(mutation) = case.get("mutation") {
            let operation = mutation["operation"].as_str().expect("mutation operation");
            match operation {
                "none" => {}
                "append-byte" => {
                    let byte = decode_hex(mutation["byte_hex"].as_str().expect("append byte"))[0];
                    match mutation["field"].as_str().expect("append field") {
                        "message" => message.push(byte),
                        "signature" => signature.push(byte),
                        "public_key" => public_key.push(byte),
                        other => panic!("unsupported append field {other}"),
                    }
                }
                "xor-byte" => {
                    let offset = mutation["offset"].as_u64().expect("xor offset") as usize;
                    let mask = mutation["mask"].as_u64().expect("xor mask") as u8;
                    match mutation["field"].as_str().expect("xor field") {
                        "signature" => signature[offset] ^= mask,
                        "public_key" => public_key[offset] ^= mask,
                        other => panic!("unsupported xor field {other}"),
                    }
                }
                "replace-response" => {
                    let replacement = by_id(
                        scalar_cases,
                        mutation["scalar_case"].as_str().expect("scalar case"),
                    );
                    let encoded = decode_hex(
                        replacement["encoding_hex"]
                            .as_str()
                            .expect("replacement scalar"),
                    );
                    signature.truncate(38);
                    signature.extend_from_slice(&encoded);
                }
                "replace-commitment" => {
                    let replacement = by_id(
                        point_cases,
                        mutation["point_case"].as_str().expect("point case"),
                    );
                    let encoded = decode_hex(
                        replacement["encoding_hex"]
                            .as_str()
                            .expect("replacement point"),
                    );
                    signature[..38].copy_from_slice(&encoded);
                }
                "replace-public-key" => {
                    let replacement = by_id(
                        point_cases,
                        mutation["point_case"].as_str().expect("point case"),
                    );
                    public_key = decode_hex(
                        replacement["encoding_hex"]
                            .as_str()
                            .expect("replacement public key"),
                    );
                }
                "truncate" => {
                    let count = mutation["bytes"].as_u64().expect("truncate bytes") as usize;
                    match mutation["field"].as_str().expect("truncate field") {
                        "signature" => signature.truncate(signature.len() - count),
                        "public_key" => public_key.truncate(public_key.len() - count),
                        other => panic!("unsupported truncate field {other}"),
                    }
                }
                "replace-signature" => {
                    let source = by_id(
                        positive_cases,
                        mutation["source_case"].as_str().expect("source case"),
                    );
                    signature =
                        decode_hex(source["signature_hex"].as_str().expect("source signature"));
                }
                other => panic!("unsupported mutation {other}"),
            }
        }

        let actual = verify(&public_key, &message, &signature);
        let expected = case["expected"] == "accept";
        assert_eq!(actual, expected, "verification case {id}");
        accepted += usize::from(actual);
    }
    assert_eq!(accepted, 6);
}

#[test]
fn adding_the_group_order_to_s_is_rejected_as_noncanonical() {
    let document = fixture();
    let order =
        array::<38>("0396bed0a1e30226314afb4798809208c8dc1600000000000000000000000000000000000008");
    for case in document["cases"].as_array().expect("cases") {
        let public_key = decode_hex(case["public_key_hex"].as_str().expect("public key"));
        let message = decode_hex(case["message_hex"].as_str().expect("message"));
        let mut signature = decode_hex(case["signature_hex"].as_str().expect("signature"));
        let mut carry = 0_u16;
        for index in 0..38 {
            let sum = signature[38 + index] as u16 + order[index] as u16 + carry;
            signature[38 + index] = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "fixture S+L must fit in 304 bits");
        assert!(Signature::from_bytes(&signature).is_err());
        assert!(!verify(&public_key, &message, &signature));
    }
}

#[test]
fn parsers_fail_closed_for_adjacent_lengths() {
    let positive = &fixture()["cases"][0];
    let public_key = decode_hex(positive["public_key_hex"].as_str().expect("public key"));
    let signature = decode_hex(positive["signature_hex"].as_str().expect("signature"));
    let message = decode_hex(positive["message_hex"].as_str().expect("message"));
    for length in [0_usize, 1, 37, 39, 75, 77, 512] {
        let bytes = std::vec![0_u8; length];
        if length != 38 {
            assert!(VerifyingKey::from_bytes(&bytes).is_err());
        }
        if length != 76 {
            assert!(Signature::from_bytes(&bytes).is_err());
        }
        assert!(!verify(&bytes, &message, &signature));
        assert!(!verify(&public_key, &message, &bytes));
    }
}

#[test]
fn fixture_ids_are_the_expected_stable_set() {
    let document = fixture();
    let ids: Vec<String> = document["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| case["id"].as_str().expect("id").into())
        .collect();
    assert_eq!(ids, ["empty", "short-ascii", "binary", "long-binary-4096"]);
}

fn cofactor_equation(
    public_key: &[u8; 38],
    message: &[u8],
    signature: &[u8; 76],
    doublings: usize,
) -> bool {
    let public = EdwardsPoint::decode_strict_subgroup(public_key).expect("valid test key");
    let commitment_encoding: &[u8; 38] = signature[..38].try_into().expect("R");
    let response_encoding: &[u8; 38] = signature[38..].try_into().expect("S");
    let commitment = EdwardsPoint::decode(commitment_encoding).expect("valid test R");
    let response = Scalar::from_canonical_bytes(response_encoding).expect_copied("valid test S");
    let digest = challenge_hash(Domain::EMPTY, commitment_encoding, public_key, message);
    let challenge = hash_to_scalar(digest);
    let mut left = EdwardsPoint::BASEPOINT.scalar_mul(&response);
    let mut right = commitment.add(public.scalar_mul(&challenge));
    for _ in 0..doublings {
        left = left.double();
        right = right.double();
    }
    left.ct_eq(&right).to_bool()
}

#[test]
fn pure_torsion_commitments_are_accepted_only_by_the_factor_four_language() {
    let seed =
        array::<38>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425");
    let public_trace = trace(&seed, b"");
    let secret = Scalar::reduce_pruned_le(&public_trace.pruned_scalar);
    let order_two =
        array::<38>("b20300000000000000000000f8ffffffffffffffffffffffffffffffffffffffffffffffff1f");
    let order_four =
        array::<38>("0000000000000000000000000000000000000000000000000000000000000000000000000080");
    let minus_order_four = [0_u8; 38];

    for (label, commitment, factor_one, factor_two) in [
        ("order-two", order_two, false, true),
        ("order-four", order_four, false, false),
        ("minus-order-four", minus_order_four, false, false),
    ] {
        let message = label.as_bytes();
        let digest = challenge_hash(
            Domain::EMPTY,
            &commitment,
            &public_trace.public_key,
            message,
        );
        let challenge = hash_to_scalar(digest);
        let response = challenge.mul(&secret).canonical_bytes();
        let mut signature = [0_u8; 76];
        signature[..38].copy_from_slice(&commitment);
        signature[38..].copy_from_slice(&response[..]);
        assert!(Signature::from_bytes(&signature).is_ok(), "{label} syntax");
        assert_eq!(
            cofactor_equation(&public_trace.public_key, message, &signature, 0),
            factor_one,
            "{label} factor one"
        );
        assert_eq!(
            cofactor_equation(&public_trace.public_key, message, &signature, 1),
            factor_two,
            "{label} factor two"
        );
        assert!(
            cofactor_equation(&public_trace.public_key, message, &signature, 2),
            "{label} factor four"
        );
        assert!(
            verify(&public_trace.public_key, message, &signature),
            "{label}"
        );
    }
}

#[test]
fn mixed_torsion_matrix_distinguishes_factors_one_two_and_four() {
    let seed =
        array::<38>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425");
    let base = trace(&seed, b"torsion-matrix");
    let secret = Scalar::reduce_pruned_le(&base.pruned_scalar);
    let nonce = Scalar::from_canonical_bytes(&base.nonce_scalar).expect_copied("nonce");
    let prime_commitment = EdwardsPoint::decode(&base.commitment).expect("prime R");
    let identity = EdwardsPoint::IDENTITY;
    let order_two = EdwardsPoint::decode(&array::<38>(
        "b20300000000000000000000f8ffffffffffffffffffffffffffffffffffffffffffffffff1f",
    ))
    .expect("T2");
    let order_four = EdwardsPoint::decode(&array::<38>(
        "0000000000000000000000000000000000000000000000000000000000000000000000000080",
    ))
    .expect("T4");
    let minus_order_four = order_four.negate();

    for (label, torsion, expected) in [
        ("identity", identity, [true, true, true]),
        ("order-two", order_two, [false, true, true]),
        ("order-four", order_four, [false, false, true]),
        ("minus-order-four", minus_order_four, [false, false, true]),
    ] {
        let commitment = prime_commitment
            .add(torsion)
            .encode()
            .expect("mixed commitment encoding");
        let digest = challenge_hash(
            Domain::EMPTY,
            &commitment,
            &base.public_key,
            b"torsion-matrix",
        );
        let challenge = hash_to_scalar(digest);
        let secret_response_term = challenge.mul(&secret);
        let response = nonce.add(&secret_response_term).canonical_bytes();
        let mut signature = [0_u8; 76];
        signature[..38].copy_from_slice(&commitment);
        signature[38..].copy_from_slice(&response[..]);
        for (doublings, expected_result) in expected.into_iter().enumerate() {
            assert_eq!(
                cofactor_equation(&base.public_key, b"torsion-matrix", &signature, doublings),
                expected_result,
                "{label} factor {}",
                1 << doublings
            );
        }
        assert!(verify(&base.public_key, b"torsion-matrix", &signature));
    }
}

#[test]
fn point_sign_and_reserved_bit_boundaries_are_explicit() {
    let mut negative_base =
        array::<38>("6bf73f755a0c80653ce83fcf6d6ff7d7f347b1929224ac67552273419e6cf2c8a88a02d38898");
    negative_base[37] ^= 0x80;
    assert!(EdwardsPoint::decode_strict_subgroup(&negative_base).is_ok());
    assert!(validate_public_key(&negative_base));

    let order_four_positive = [0_u8; 38];
    let mut order_four_negative = order_four_positive;
    order_four_negative[37] = 0x80;
    assert!(EdwardsPoint::decode(&order_four_positive).is_ok());
    assert!(EdwardsPoint::decode(&order_four_negative).is_ok());

    let mut negative_zero_at_minus_one =
        array::<38>("b20300000000000000000000f8ffffffffffffffffffffffffffffffffffffffffffffffff1f");
    negative_zero_at_minus_one[37] |= 0x80;
    assert!(EdwardsPoint::decode(&negative_zero_at_minus_one).is_err());

    for sign in [0_u8, 0x80] {
        let mut nonsquare = [0_u8; 38];
        nonsquare[0] = 3;
        nonsquare[37] = sign;
        assert!(EdwardsPoint::decode(&nonsquare).is_err());
    }
    for reserved in [0x20_u8, 0x40, 0x60] {
        let mut encoded = [0_u8; 38];
        encoded[0] = 1;
        encoded[37] = reserved;
        assert!(EdwardsPoint::decode(&encoded).is_err());
    }
}

#[test]
fn deterministic_single_byte_mutations_fail_closed() {
    let document = fixture();
    let case = by_id(document["cases"].as_array().expect("cases"), "short-ascii");
    let public_key = decode_hex(case["public_key_hex"].as_str().expect("public key"));
    let message = decode_hex(case["message_hex"].as_str().expect("message"));
    let signature = decode_hex(case["signature_hex"].as_str().expect("signature"));

    for index in 0..public_key.len() {
        let mut changed = public_key.clone();
        changed[index] ^= 1;
        assert!(
            !verify(&changed, &message, &signature),
            "public byte {index}"
        );
    }
    for index in 0..signature.len() {
        let mut changed = signature.clone();
        changed[index] ^= 1;
        assert!(
            !verify(&public_key, &message, &changed),
            "signature byte {index}"
        );
    }
    for index in 0..message.len() {
        let mut changed = message.clone();
        changed[index] ^= 1;
        assert!(
            !verify(&public_key, &changed, &signature),
            "message byte {index}"
        );
    }
}
