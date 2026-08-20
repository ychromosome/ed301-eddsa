use ed301_eddsa::{SigningKey, verify};

fn main() {
    run_known_answer_check();
}

fn run_known_answer_check() {
    let seed = hex_array::<38>(
        b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425",
    );
    let expected_public_key = hex_array::<38>(
        b"8cad07b4f9a308523a8df9bee22a721b8ff5e597c1ce47e39df67f97a475fd018013fc188890",
    );
    let expected_signature = hex_array::<76>(
        b"2964a4e22d5ed6e41ad5d5bbfdf4d518bb067b8982f3f8f5900d074a6bee97567b95810336944dfdce74dd889ee9d9db3c10bd1f9da0799bad501c8f3e9260020ad64fa6b02a8c27ce837d00",
    );
    let key = SigningKey::from_seed(&seed).expect("fixed seed length");
    let public_key = key
        .verifying_key()
        .expect("public-key derivation")
        .to_bytes();
    let signature = key.sign(b"").expect("empty-message signature").to_bytes();

    assert_eq!(public_key, expected_public_key);
    assert_eq!(signature, expected_signature);
    assert!(verify(&public_key, b"", &signature));
}

fn hex_array<const N: usize>(hex: &[u8]) -> [u8; N] {
    assert_eq!(hex.len(), N * 2);
    let mut output = [0_u8; N];
    let mut index = 0;
    while index < N {
        output[index] = (nibble(hex[index * 2]) << 4) | nibble(hex[index * 2 + 1]);
        index += 1;
    }
    output
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid hexadecimal KAT"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn downstream_release_workspace_matches_the_empty_message_kat() {
        run_known_answer_check();
    }
}
