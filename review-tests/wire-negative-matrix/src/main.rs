use ed301_eddsa::{Signature, SigningKey, validate_public_key, verify};

fn main() {
    let seed: [u8; 38] = core::array::from_fn(|index| index as u8);
    let key = SigningKey::from_seed(&seed).expect("fixed-size seed");
    let public_key = key.verifying_key().expect("public derivation").to_bytes();
    let message = b"wire and malleability matrix";
    let signature = key.sign(message).expect("signing").to_bytes();

    assert!(validate_public_key(&public_key));
    assert!(verify(&public_key, message, &signature));
    assert_eq!(
        Signature::from_bytes(&signature)
            .expect("canonical signature")
            .to_bytes(),
        signature
    );

    let mut mutation_checks = 0_usize;
    for bit in 0..public_key.len() * 8 {
        let mut mutated = public_key;
        mutated[bit / 8] ^= 1 << (bit % 8);
        assert!(
            !verify(&mutated, message, &signature),
            "one-bit public-key mutation {bit} verified"
        );
        mutation_checks += 1;
    }
    for bit in 0..signature.len() * 8 {
        let mut mutated = signature;
        mutated[bit / 8] ^= 1 << (bit % 8);
        assert!(
            !verify(&public_key, message, &mutated),
            "one-bit signature mutation {bit} verified"
        );
        mutation_checks += 1;
    }
    for bit in 0..message.len() * 8 {
        let mut mutated = message.to_vec();
        mutated[bit / 8] ^= 1 << (bit % 8);
        assert!(
            !verify(&public_key, &mutated, &signature),
            "one-bit message mutation {bit} verified"
        );
        mutation_checks += 1;
    }

    for length in 0..=77 {
        if length != 38 {
            let candidate = vec![0_u8; length];
            assert!(!validate_public_key(&candidate));
            assert!(!verify(&candidate, message, &signature));
        }
        if length != 76 {
            let candidate = vec![0_u8; length];
            assert!(Signature::from_bytes(&candidate).is_err());
            assert!(!verify(&public_key, message, &candidate));
        }
    }
    assert!(SigningKey::from_seed(&[0_u8; 37]).is_err());
    assert!(SigningKey::from_seed(&[0_u8; 39]).is_err());

    let message_lengths = [0_usize, 1, 37, 38, 75, 76, 255, 256, 1024];
    for length in message_lengths {
        let candidate: Vec<u8> = (0..length)
            .map(|index| (index as u8).wrapping_mul(0x9d).wrapping_add(0x37))
            .collect();
        let first = key.sign(&candidate).expect("boundary signing").to_bytes();
        let second = key.sign(&candidate).expect("repeat signing").to_bytes();
        assert_eq!(
            first, second,
            "nondeterministic signature at length {length}"
        );
        assert!(verify(&public_key, &candidate, &first));
        if !candidate.is_empty() {
            let mut changed = candidate.clone();
            changed[length / 2] ^= 0x80;
            assert!(!verify(&public_key, &changed, &first));
        }
    }

    let mut state = 0x6a09_e667_f3bc_c909_u64;
    let mut arbitrary_checks = 0_usize;
    for case_index in 0..20_000_usize {
        let mut random_public = [0_u8; 38];
        let mut random_signature = [0_u8; 76];
        fill(&mut state, &mut random_public);
        fill(&mut state, &mut random_signature);
        let message_length = (splitmix64(&mut state) as usize) & 0x1ff;
        let mut random_message = vec![0_u8; message_length];
        fill(&mut state, &mut random_message);

        if let Ok(parsed) = Signature::from_bytes(&random_signature) {
            assert_eq!(parsed.to_bytes(), random_signature);
        }
        let _ = validate_public_key(&random_public);
        assert!(
            !verify(&random_public, &random_message, &random_signature),
            "arbitrary triple {case_index} unexpectedly verified"
        );
        arbitrary_checks += 1;
    }

    println!(
        "wire_negative_matrix=PASS mutation_checks={mutation_checks} arbitrary_checks={arbitrary_checks}"
    );
}

fn fill(state: &mut u64, output: &mut [u8]) {
    for chunk in output.chunks_mut(8) {
        let block = splitmix64(state).to_le_bytes();
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}
