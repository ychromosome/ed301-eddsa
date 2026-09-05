//! Public identifiers and sizes fixed by `Ed301-EdDSA-v1`.

/// Versioned identifier of this signature profile.
pub const SPECIFICATION: &str = "Ed301-EdDSA-v1";

/// Native signature-domain label, following the RFC 8032 Ed448 `dom4` shape.
pub const SIGNATURE_DOMAIN: &[u8; 11] = b"SigEd301-v1";

/// Maximum native context length encoded by the one-octet domain field.
pub const MAX_CONTEXT_BYTES: usize = u8::MAX as usize;

/// Versioned identifier of the underlying curve and encoding parameter set.
pub const PARAMETER_SET: &str = "ED301-v1";

/// Bit length of the prime field modulus.
pub const FIELD_BITS: usize = 301;

/// Canonical byte length of field elements, points and signature scalars.
pub const FIELD_BYTES: usize = 38;

/// Canonical byte length of signature scalars.
pub const SCALAR_BYTES: usize = FIELD_BYTES;

/// Required seed length.
pub const SEED_BYTES: usize = FIELD_BYTES;

/// Required public-key length.
pub const PUBLIC_KEY_BYTES: usize = FIELD_BYTES;

/// Required signature length, `ENC(R) || ENC_SCALAR(S)`.
pub const SIGNATURE_BYTES: usize = 2 * FIELD_BYTES;

/// Exact SHAKE256 output length used by Ed301-EdDSA-v1.
pub const HASH_BYTES: usize = 2 * FIELD_BYTES;

/// Cofactor used by the sole verification equation.
pub const COFACTOR: usize = 4;

/// Twisted-Edwards coefficient `a`.
pub const EDWARDS_A: u32 = 2_086_388_329;

/// Twisted-Edwards coefficient `d`.
pub const EDWARDS_D: u16 = 301;

const _: () = {
    assert!(FIELD_BYTES * 8 == 304);
    assert!(HASH_BYTES == 76);
    assert!(SIGNATURE_BYTES == 76);
    assert!(COFACTOR == 4);
};
