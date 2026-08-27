//! Exact SHAKE256 transcript operations for `Ed301-EdDSA-v1`.

use crate::{
    parameters::{FIELD_BYTES, HASH_BYTES, SEED_BYTES, SIGNATURE_DOMAIN},
    scalar::Scalar,
    secret::{Secret, secret},
};
use shake::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

/// RFC 8032 Ed448-style domain prefix for the versioned Ed301 instance.
///
/// The complete domain is `"SigEd301-v1" || octet(0) ||
/// octet(context.len()) || context`. The zero octet is the fixed PureEdDSA
/// prehash flag; Ed301-EdDSA-v1 defines no prehash instance.
#[derive(Clone, Copy)]
pub(crate) struct Domain<'a> {
    context: &'a [u8],
    context_len: u8,
}

impl<'a> Domain<'a> {
    #[cfg(test)]
    pub(crate) const EMPTY: Self = Self {
        context: b"",
        context_len: 0,
    };

    pub(crate) fn new(context: &'a [u8]) -> Option<Self> {
        let context_len = u8::try_from(context.len()).ok()?;
        Some(Self {
            context,
            context_len,
        })
    }

    fn update(self, state: &mut Shake256) {
        state.update(SIGNATURE_DOMAIN);
        state.update(&[0, self.context_len]);
        state.update(self.context);
    }
}

pub(crate) fn expand_seed(seed: &[u8; SEED_BYTES]) -> Secret<[u8; HASH_BYTES]> {
    hash_parts(&[seed])
}

pub(crate) fn nonce_hash(
    domain: Domain<'_>,
    prefix: &[u8; FIELD_BYTES],
    message: &[u8],
) -> Secret<[u8; HASH_BYTES]> {
    hash_domain_parts(domain, &[prefix, message])
}

pub(crate) fn challenge_hash(
    domain: Domain<'_>,
    commitment: &[u8; FIELD_BYTES],
    public_key: &[u8; FIELD_BYTES],
    message: &[u8],
) -> Secret<[u8; HASH_BYTES]> {
    hash_domain_parts(domain, &[commitment, public_key, message])
}

pub(crate) fn hash_to_scalar(hash: Secret<[u8; HASH_BYTES]>) -> Secret<Scalar> {
    Scalar::reduce_hash_le(&hash)
}

fn hash_parts(parts: &[&[u8]]) -> Secret<[u8; HASH_BYTES]> {
    let mut state = Shake256::default();
    for part in parts {
        state.update(part);
    }
    let mut output = secret([0_u8; HASH_BYTES]);
    state.finalize_xof().read(&mut output[..]);
    output
}

fn hash_domain_parts(domain: Domain<'_>, parts: &[&[u8]]) -> Secret<[u8; HASH_BYTES]> {
    let mut state = Shake256::default();
    domain.update(&mut state);
    for part in parts {
        state.update(part);
    }
    let mut output = secret([0_u8; HASH_BYTES]);
    state.finalize_xof().read(&mut output[..]);
    output
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::test_support::decode_hex_array;
    use std::vec::Vec;

    const EMPTY_SHAKE256_76: [u8; HASH_BYTES] = decode_hex_array(
        b"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7ed",
    );

    fn single_update(data: &[u8]) -> [u8; HASH_BYTES] {
        let mut state = Shake256::default();
        state.update(data);
        let mut output = [0_u8; HASH_BYTES];
        state.finalize_xof().read(&mut output);
        output
    }

    #[test]
    fn empty_input_matches_the_fips202_shake256_value() {
        assert_eq!(*hash_parts(&[b""]), EMPTY_SHAKE256_76);
    }

    #[test]
    fn nonce_and_challenge_rate_boundaries_match_single_update() {
        let domain = Domain::new(b"binary\x00context").expect("short context");
        let mut domain_prefix = Vec::from(SIGNATURE_DOMAIN.as_slice());
        domain_prefix.extend_from_slice(&[0, 14]);
        domain_prefix.extend_from_slice(b"binary\x00context");
        let prefix = [0x5a_u8; FIELD_BYTES];
        for message_length in [96_usize, 97, 98, 99] {
            let message: Vec<u8> = (0..message_length).map(|i| i as u8).collect();
            let mut concatenated = domain_prefix.clone();
            concatenated.extend_from_slice(&prefix);
            concatenated.extend_from_slice(&message);
            assert_eq!(
                *nonce_hash(domain, &prefix, &message),
                single_update(&concatenated)
            );
        }

        let commitment = [0xa5_u8; FIELD_BYTES];
        let public_key = [0x3c_u8; FIELD_BYTES];
        for message_length in [58_usize, 59, 60, 61] {
            let message: Vec<u8> = (0..message_length).map(|i| (i * 3) as u8).collect();
            let mut concatenated = domain_prefix.clone();
            concatenated.extend_from_slice(&commitment);
            concatenated.extend_from_slice(&public_key);
            concatenated.extend_from_slice(&message);
            assert_eq!(
                *challenge_hash(domain, &commitment, &public_key, &message),
                single_update(&concatenated)
            );
        }
    }

    #[test]
    fn context_length_is_an_exact_single_octet() {
        assert!(Domain::new(&[0x5a; 255]).is_some());
        assert!(Domain::new(&[0x5a; 256]).is_none());
        assert_eq!(Domain::new(b"").expect("empty context").context_len, 0);
    }
}
