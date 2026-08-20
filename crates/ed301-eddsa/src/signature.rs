//! Context-free, one-shot `Ed301-EdDSA-draft-00` signatures.

#[cfg(test)]
extern crate std;

use crate::{
    edwards::EdwardsPoint,
    parameters::{FIELD_BYTES, PUBLIC_KEY_BYTES, SEED_BYTES, SIGNATURE_BYTES},
    scalar::Scalar,
    secret::{Secret, secret},
    secret_taint::declassify,
    signature_hash::{challenge_hash, expand_seed, hash_to_scalar, nonce_hash},
};

/// A deterministic key, parse or signing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureError {
    /// The seed was not exactly 38 bytes.
    InvalidSeedLength,
    /// The public key was not a canonical, nonidentity prime-subgroup point.
    InvalidPublicKey,
    /// The signature length, commitment point or scalar was noncanonical.
    InvalidSignature,
    /// A secret-derived invariant or signing self-check failed.
    InternalFailure,
}

/// Owning 38-byte signing seed.
///
/// The owner is deliberately neither `Copy` nor `Clone` and zeroizes its seed
/// on drop. Seed generation remains the caller's CSPRNG responsibility.
pub struct SigningKey {
    seed: Secret<[u8; SEED_BYTES]>,
}

impl SigningKey {
    /// Import an exact 38-byte seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self, SignatureError> {
        let seed: &[u8; SEED_BYTES] = seed
            .try_into()
            .map_err(|_| SignatureError::InvalidSeedLength)?;
        Ok(Self {
            seed: secret(*seed),
        })
    }

    /// Derive the public verification key.
    pub fn verifying_key(&self) -> Result<VerifyingKey, SignatureError> {
        let expanded = ExpandedSecret::derive(&self.seed)?;
        VerifyingKey::from_bytes(&expanded.public_key).map_err(|_| SignatureError::InternalFailure)
    }

    /// Sign one opaque message with the exact context-free draft transcript.
    pub fn sign(&self, message: &[u8]) -> Result<Signature, SignatureError> {
        let expanded = ExpandedSecret::derive(&self.seed)?;
        sign_expanded(&expanded, message)
    }
}

/// Fully validated public verification key.
#[derive(Clone, Copy)]
pub struct VerifyingKey {
    encoded: [u8; PUBLIC_KEY_BYTES],
    point: EdwardsPoint,
}

impl VerifyingKey {
    /// Parse and fully validate a 38-byte public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let encoded: &[u8; PUBLIC_KEY_BYTES] = bytes
            .try_into()
            .map_err(|_| SignatureError::InvalidPublicKey)?;
        let point = EdwardsPoint::decode_strict_subgroup(encoded)
            .map_err(|_| SignatureError::InvalidPublicKey)?;
        Ok(Self {
            encoded: *encoded,
            point,
        })
    }

    /// Return the canonical public-key bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; PUBLIC_KEY_BYTES] {
        self.encoded
    }

    /// Verify a parsed signature over one opaque message.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let digest = challenge_hash(&signature.commitment_encoding, &self.encoded, message);
        let challenge = hash_to_scalar(digest);
        let left = EdwardsPoint::BASEPOINT
            .scalar_mul(&signature.response)
            .multiply_by_cofactor();
        let right = signature
            .commitment
            .add(self.point.scalar_mul(&challenge))
            .multiply_by_cofactor();
        left.ct_eq(&right).to_bool()
    }
}

/// Parsed canonical 76-byte signature.
#[derive(Clone, Copy)]
pub struct Signature {
    encoded: [u8; SIGNATURE_BYTES],
    commitment_encoding: [u8; FIELD_BYTES],
    commitment: EdwardsPoint,
    response: Scalar,
}

impl Signature {
    /// Parse the exact 76-byte signature syntax.
    ///
    /// `R` must be a canonical curve point, but identity, pure torsion and
    /// mixed-torsion points are intentionally not rejected here. `S` must be
    /// the canonical 38-byte integer in `0 <= S < L`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let encoded: &[u8; SIGNATURE_BYTES] = bytes
            .try_into()
            .map_err(|_| SignatureError::InvalidSignature)?;
        let commitment_encoding: &[u8; FIELD_BYTES] = encoded[..FIELD_BYTES]
            .try_into()
            .map_err(|_| SignatureError::InvalidSignature)?;
        let response_encoding: &[u8; FIELD_BYTES] = encoded[FIELD_BYTES..]
            .try_into()
            .map_err(|_| SignatureError::InvalidSignature)?;
        let commitment = EdwardsPoint::decode(commitment_encoding)
            .map_err(|_| SignatureError::InvalidSignature)?;
        let response = Scalar::from_canonical_bytes(response_encoding)
            .into_option_copied()
            .ok_or(SignatureError::InvalidSignature)?;
        Ok(Self {
            encoded: *encoded,
            commitment_encoding: *commitment_encoding,
            commitment,
            response,
        })
    }

    /// Return the canonical wire representation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; SIGNATURE_BYTES] {
        self.encoded
    }
}

/// Sign one opaque message from an exact seed.
pub fn sign(seed: &[u8], message: &[u8]) -> Result<[u8; SIGNATURE_BYTES], SignatureError> {
    let key = SigningKey::from_seed(seed)?;
    Ok(key.sign(message)?.to_bytes())
}

/// Apply the full draft public-key validation rule.
#[must_use]
pub fn validate_public_key(public_key: &[u8]) -> bool {
    VerifyingKey::from_bytes(public_key).is_ok()
}

/// Parse and verify a signature, returning one fail-closed boolean.
#[must_use]
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let public_key = match VerifyingKey::from_bytes(public_key) {
        Ok(public_key) => public_key,
        Err(_) => return false,
    };
    let signature = match Signature::from_bytes(signature) {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    public_key.verify(message, &signature)
}

fn sign_expanded(expanded: &ExpandedSecret, message: &[u8]) -> Result<Signature, SignatureError> {
    let nonce_digest = nonce_hash(&expanded.prefix, message);
    let nonce = hash_to_scalar(nonce_digest);
    let commitment_point = EdwardsPoint::BASEPOINT.scalar_mul(&nonce);

    let mut commitment_is_subgroup = commitment_point.is_prime_subgroup();
    declassify(&mut commitment_is_subgroup);
    if !commitment_is_subgroup.to_bool() {
        return Err(SignatureError::InternalFailure);
    }

    let mut commitment = match commitment_point.encode_public_artifact() {
        Ok(commitment) => commitment,
        Err(_) => return Err(SignatureError::InternalFailure),
    };
    declassify(&mut commitment);

    let challenge_digest = challenge_hash(&commitment, &expanded.public_key, message);
    let challenge = hash_to_scalar(challenge_digest);
    let secret_response_term = challenge.mul(&expanded.reduced_scalar);
    let response = nonce.add(&secret_response_term);

    let mut encoded = secret([0_u8; SIGNATURE_BYTES]);
    encoded[..FIELD_BYTES].copy_from_slice(&commitment);
    let mut response_bytes = secret([0_u8; FIELD_BYTES]);
    response.write_canonical_bytes(&mut response_bytes);
    encoded[FIELD_BYTES..].copy_from_slice(&response_bytes[..]);
    #[cfg(test)]
    hit_secret_failpoint(SecretFailpoint::SignIntermediates);
    declassify(&mut encoded);

    let signature =
        Signature::from_bytes(&encoded[..]).map_err(|_| SignatureError::InternalFailure)?;
    let mut serialized_commitment_is_subgroup = signature.commitment.is_prime_subgroup();
    declassify(&mut serialized_commitment_is_subgroup);
    if !serialized_commitment_is_subgroup.to_bool() {
        return Err(SignatureError::InternalFailure);
    }
    let verifying_key = VerifyingKey::from_bytes(&expanded.public_key)
        .map_err(|_| SignatureError::InternalFailure)?;
    if !verifying_key.verify(message, &signature) {
        return Err(SignatureError::InternalFailure);
    }
    Ok(signature)
}

struct ExpandedSecret {
    reduced_scalar: Secret<Scalar>,
    prefix: Secret<[u8; FIELD_BYTES]>,
    public_key: [u8; PUBLIC_KEY_BYTES],
}

impl ExpandedSecret {
    fn derive(seed: &[u8; SEED_BYTES]) -> Result<Self, SignatureError> {
        let expanded_hash = expand_seed(seed);
        let mut pruned_scalar = secret([0_u8; FIELD_BYTES]);
        pruned_scalar.copy_from_slice(&expanded_hash[..FIELD_BYTES]);
        pruned_scalar[0] &= 0xfc;
        pruned_scalar[FIELD_BYTES - 1] = (pruned_scalar[FIELD_BYTES - 1] & 0x0f) | 0x10;
        let mut prefix = secret([0_u8; FIELD_BYTES]);
        prefix.copy_from_slice(&expanded_hash[FIELD_BYTES..]);

        let reduced_scalar = Scalar::reduce_pruned_le(&pruned_scalar);
        #[cfg(test)]
        hit_secret_failpoint(SecretFailpoint::ExpandedSecret);
        let public_point = EdwardsPoint::BASEPOINT.scalar_mul_pruned(&pruned_scalar);
        let mut public_is_valid = public_point.is_prime_subgroup_nonidentity();
        declassify(&mut public_is_valid);
        if !public_is_valid.to_bool() {
            return Err(SignatureError::InternalFailure);
        }

        let mut public_key = match public_point.encode_public_artifact() {
            Ok(public_key) => public_key,
            Err(_) => return Err(SignatureError::InternalFailure),
        };
        declassify(&mut public_key);

        Ok(Self {
            reduced_scalar,
            prefix,
            public_key,
        })
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum SecretFailpoint {
    ExpandedSecret,
    SignIntermediates,
}

#[cfg(test)]
std::thread_local! {
    static SECRET_FAILPOINT: core::cell::Cell<Option<SecretFailpoint>> = const {
        core::cell::Cell::new(None)
    };
}

#[cfg(test)]
fn arm_secret_failpoint(point: SecretFailpoint) {
    SECRET_FAILPOINT.with(|slot| slot.set(Some(point)));
}

#[cfg(test)]
fn hit_secret_failpoint(point: SecretFailpoint) {
    SECRET_FAILPOINT.with(|slot| {
        if slot.get() == Some(point) {
            slot.set(None);
            panic!("controlled panic with live secret owners");
        }
    });
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) struct Trace {
        pub(crate) expanded_hash: [u8; 76],
        pub(crate) pruned_scalar: [u8; 38],
        pub(crate) prefix: [u8; 38],
        pub(crate) public_key: [u8; 38],
        pub(crate) nonce_hash: [u8; 76],
        pub(crate) nonce_scalar: [u8; 38],
        pub(crate) commitment: [u8; 38],
        pub(crate) challenge_hash: [u8; 76],
        pub(crate) challenge_scalar: [u8; 38],
        pub(crate) response: [u8; 38],
        pub(crate) signature: [u8; 76],
    }

    pub(crate) fn trace(seed: &[u8; 38], message: &[u8]) -> Trace {
        let expanded_hash = expand_seed(seed);
        let mut pruned_scalar = secret([0_u8; 38]);
        pruned_scalar.copy_from_slice(&expanded_hash[..38]);
        pruned_scalar[0] &= 0xfc;
        pruned_scalar[37] = (pruned_scalar[37] & 0x0f) | 0x10;
        let mut prefix = secret([0_u8; 38]);
        prefix.copy_from_slice(&expanded_hash[38..]);
        let reduced_secret = Scalar::reduce_pruned_le(&pruned_scalar);
        let public_key = EdwardsPoint::BASEPOINT
            .scalar_mul_pruned(&pruned_scalar)
            .encode()
            .expect("test-derived public key");
        let nonce_digest = nonce_hash(&prefix, message);
        let nonce_hash = *nonce_digest;
        let nonce = hash_to_scalar(nonce_digest);
        let nonce_scalar = nonce.canonical_bytes();
        let commitment = EdwardsPoint::BASEPOINT
            .scalar_mul(&nonce)
            .encode()
            .expect("test-derived commitment");
        let challenge_digest = challenge_hash(&commitment, &public_key, message);
        let challenge_hash = *challenge_digest;
        let challenge = hash_to_scalar(challenge_digest);
        let challenge_scalar = challenge.canonical_bytes();
        let secret_response_term = challenge.mul(&reduced_secret);
        let response_scalar = nonce.add(&secret_response_term);
        let response = response_scalar.canonical_bytes();
        let mut signature = [0_u8; 76];
        signature[..38].copy_from_slice(&commitment);
        signature[38..].copy_from_slice(&response[..]);
        Trace {
            expanded_hash: *expanded_hash,
            pruned_scalar: *pruned_scalar,
            prefix: *prefix,
            public_key,
            nonce_hash,
            nonce_scalar,
            commitment,
            challenge_hash,
            challenge_scalar,
            response,
            signature,
        }
    }

    #[cfg(panic = "unwind")]
    #[test]
    fn actual_secret_scopes_unwind_and_subsequent_signing_recovers() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let seed = [0x5a_u8; 38];
        let key = SigningKey::from_seed(&seed).expect("fixed seed length");
        let expected = key.sign(b"after-unwind").expect("baseline signature");

        for point in [
            SecretFailpoint::ExpandedSecret,
            SecretFailpoint::SignIntermediates,
        ] {
            arm_secret_failpoint(point);
            let outcome = catch_unwind(AssertUnwindSafe(|| key.sign(b"after-unwind")));
            assert!(outcome.is_err());
            assert_eq!(
                key.sign(b"after-unwind")
                    .expect("signing after controlled unwind")
                    .to_bytes(),
                expected.to_bytes()
            );
        }

        assert!(core::mem::needs_drop::<ExpandedSecret>());
    }
}
