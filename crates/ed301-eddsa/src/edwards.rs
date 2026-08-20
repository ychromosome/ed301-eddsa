//! Internal extended-coordinate arithmetic for the ED301-v1 Edwards group.
//!
//! The formulas in this module are the complete formulas for a general
//! twisted-Edwards curve with square `a` and nonsquare `d`. Secret scalar
//! multiplication executes a fixed 301-round double-and-add-always schedule.

#![allow(
    dead_code,
    reason = "the point core is consumed by the forthcoming signature API"
)]

use crypto_bigint::Choice;

use crate::{
    field::FieldElement,
    parameters::{FIELD_BITS, FIELD_BYTES},
    scalar::Scalar,
    secret_taint::declassify,
};

const EDWARDS_A: FieldElement = FieldElement::from_u64(2_086_388_329);
const EDWARDS_D: FieldElement = FieldElement::from_u64(301);
const TWO: FieldElement = FieldElement::from_u64(2);

/// Canonical compressed encoding of the ED301-v1 base point.
pub(crate) const BASEPOINT_ENCODING: [u8; FIELD_BYTES] = [
    0x6b, 0xf7, 0x3f, 0x75, 0x5a, 0x0c, 0x80, 0x65, 0x3c, 0xe8, 0x3f, 0xcf, 0x6d, 0x6f, 0xf7, 0xd7,
    0xf3, 0x47, 0xb1, 0x92, 0x92, 0x24, 0xac, 0x67, 0x55, 0x22, 0x73, 0x41, 0x9e, 0x6c, 0xf2, 0xc8,
    0xa8, 0x8a, 0x02, 0xd3, 0x88, 0x98,
];

const PRIME_ORDER_BYTES: [u8; FIELD_BYTES] = [
    0x03, 0x96, 0xbe, 0xd0, 0xa1, 0xe3, 0x02, 0x26, 0x31, 0x4a, 0xfb, 0x47, 0x98, 0x80, 0x92, 0x08,
    0xc8, 0xdc, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
];

/// Generic failure from strict Edwards point decoding or encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EdwardsPointError;

/// ED301-v1 point in extended coordinates `(X:Y:Z:T)` with `XY = ZT`.
#[derive(Clone, Copy)]
pub(crate) struct EdwardsPoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    t: FieldElement,
}

impl EdwardsPoint {
    /// Edwards identity `(0, 1)`.
    pub(crate) const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
        t: FieldElement::ZERO,
    };

    /// Deterministically derived ED301-v1 base point of exact order `q`.
    pub(crate) const BASEPOINT: Self = Self {
        x: FieldElement::from_canonical_words([
            0x76e2_adfb_00c0_3d1f,
            0x4942_cad7_bf84_1f3f,
            0x5cdb_b15e_84b5_2add,
            0x3be0_acb6_161a_2783,
            0x0000_0000_3aee_6839,
        ]),
        y: FieldElement::from_canonical_words([
            0x6580_0c5a_753f_f76b,
            0xd7f7_6f6d_cf3f_e83c,
            0x67ac_2492_92b1_47f3,
            0xc8f2_6c9e_4173_2255,
            0x0000_1888_d302_8aa8,
        ]),
        z: FieldElement::ONE,
        t: FieldElement::from_canonical_words([
            0xf743_65f4_4b45_598d,
            0x215c_9ee6_a9b1_002e,
            0xc602_cc68_7276_039c,
            0xb024_6816_daaa_5ae2,
            0x0000_01db_90e5_effb,
        ]),
    };

    fn from_affine(x: FieldElement, y: FieldElement) -> Self {
        Self {
            x,
            y,
            z: FieldElement::ONE,
            t: x.mul(y),
        }
    }

    /// Add two valid extended points with the complete twisted-Edwards formula.
    pub(crate) fn add(self, rhs: Self) -> Self {
        let xx = self.x.mul(rhs.x);
        let yy = self.y.mul(rhs.y);
        let dt = EDWARDS_D.mul(self.t).mul(rhs.t);
        let zz = self.z.mul(rhs.z);
        let cross = self.x.add(self.y).mul(rhs.x.add(rhs.y)).sub(xx).sub(yy);
        let difference = zz.sub(dt);
        let sum = zz.add(dt);
        let twisted = yy.sub(EDWARDS_A.mul(xx));

        Self {
            x: cross.mul(difference),
            y: sum.mul(twisted),
            z: difference.mul(sum),
            t: cross.mul(twisted),
        }
    }

    /// Double a valid extended point with the complete dedicated formula.
    pub(crate) fn double(self) -> Self {
        let xx = self.x.square();
        let yy = self.y.square();
        let two_zz = TWO.mul(self.z.square());
        let twisted_xx = EDWARDS_A.mul(xx);
        let cross = self.x.add(self.y).square().sub(xx).sub(yy);
        let sum = twisted_xx.add(yy);
        let difference = sum.sub(two_zz);
        let twisted_difference = twisted_xx.sub(yy);

        Self {
            x: cross.mul(difference),
            y: sum.mul(twisted_difference),
            z: difference.mul(sum),
            t: cross.mul(twisted_difference),
        }
    }

    /// Return the Edwards inverse `(-x, y)`.
    pub(crate) fn negate(self) -> Self {
        Self {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    /// Multiply by a canonical scalar in exactly 301 rounds.
    pub(crate) fn scalar_mul(self, scalar: &Scalar) -> Self {
        self.scalar_mul_with(|bit_index| scalar.bit(bit_index))
    }

    fn scalar_mul_encoded(self, scalar: &[u8; FIELD_BYTES]) -> Self {
        self.scalar_mul_with(|bit_index| {
            Choice::from_u8_lsb(scalar[bit_index >> 3] >> (bit_index & 7))
        })
    }

    /// Multiply by the exact pruned 301-bit secret encoding.
    ///
    /// Unlike [`Self::scalar_mul`], this path intentionally does not require
    /// the input to be canonical modulo `L`; the draft's pruned secret lies in
    /// `2^300 <= s < 2^301` and is consumed in exactly 301 rounds.
    pub(crate) fn scalar_mul_pruned(self, scalar: &[u8; FIELD_BYTES]) -> Self {
        self.scalar_mul_encoded(scalar)
    }

    fn scalar_mul_with(self, mut scalar_bit: impl FnMut(usize) -> Choice) -> Self {
        let mut accumulator = Self::IDENTITY;
        let mut bit_index = FIELD_BITS;

        while bit_index != 0 {
            bit_index -= 1;
            let doubled = accumulator.double();
            let added = doubled.add(self);
            let bit = scalar_bit(bit_index);
            accumulator = Self::conditional_select(doubled, added, bit);
        }

        accumulator
    }

    /// Encode a valid point as the canonical 38-byte compressed representation.
    pub(crate) fn encode(self) -> Result<[u8; FIELD_BYTES], EdwardsPointError> {
        self.encode_inner(false)
    }

    /// Encode a secret-derived point whose completed bytes are a public wire
    /// artifact, declassifying only impossible invariant-fault predicates in
    /// the Valgrind instrumentation build.
    pub(crate) fn encode_public_artifact(self) -> Result<[u8; FIELD_BYTES], EdwardsPointError> {
        self.encode_inner(true)
    }

    #[inline(always)]
    fn encode_inner(
        self,
        declassify_fault_predicates: bool,
    ) -> Result<[u8; FIELD_BYTES], EdwardsPointError> {
        let mut point_is_valid = self.is_valid();
        if declassify_fault_predicates {
            declassify(&mut point_is_valid);
        }
        if !point_is_valid.to_bool() {
            return Err(EdwardsPointError);
        }
        let inverse = self.z.invert();
        let mut inverse_is_present = inverse.is_some();
        if declassify_fault_predicates {
            declassify(&mut inverse_is_present);
        }
        if !inverse_is_present.to_bool() {
            return Err(EdwardsPointError);
        }
        let inverse = inverse.to_inner_unchecked();
        let affine_x = self.x.mul(inverse);
        let affine_y = self.y.mul(inverse);
        let mut encoded = affine_y.to_canonical_bytes();
        encoded[FIELD_BYTES - 1] |= affine_x.is_odd().to_u8() << 7;
        Ok(encoded)
    }

    /// Decode a canonical compressed ED301-v1 point.
    ///
    /// Identity, torsion and mixed-order points are accepted here. Protocols
    /// requiring a nonidentity prime-subgroup point must use
    /// [`Self::decode_strict_subgroup`].
    pub(crate) fn decode(encoded: &[u8; FIELD_BYTES]) -> Result<Self, EdwardsPointError> {
        if encoded[FIELD_BYTES - 1] & 0x60 != 0 {
            return Err(EdwardsPointError);
        }

        let sign = Choice::from((encoded[FIELD_BYTES - 1] >> 7) & 1);
        let mut y_bytes = *encoded;
        y_bytes[FIELD_BYTES - 1] &= 0x1f;
        let y = FieldElement::from_canonical_bytes(&y_bytes)
            .into_option_copied()
            .ok_or(EdwardsPointError)?;
        let yy = y.square();
        let denominator = EDWARDS_A.sub(EDWARDS_D.mul(yy));
        let denominator_inverse = denominator
            .invert()
            .into_option_copied()
            .ok_or(EdwardsPointError)?;
        let x_squared = FieldElement::ONE.sub(yy).mul(denominator_inverse);
        let root = x_squared
            .sqrt()
            .into_option_copied()
            .ok_or(EdwardsPointError)?;

        if root.is_zero().and(sign).to_bool() {
            return Err(EdwardsPointError);
        }
        let negate = root.is_odd().xor(sign);
        let x = FieldElement::conditional_select(root, root.neg(), negate);
        let point = Self::from_affine(x, y);
        if !point.is_valid().to_bool() {
            return Err(EdwardsPointError);
        }
        Ok(point)
    }

    /// Decode and require a nonidentity point of exact prime order `q`.
    pub(crate) fn decode_strict_subgroup(
        encoded: &[u8; FIELD_BYTES],
    ) -> Result<Self, EdwardsPointError> {
        let point = Self::decode(encoded)?;
        if !point.is_prime_subgroup_nonidentity().to_bool() {
            return Err(EdwardsPointError);
        }
        Ok(point)
    }

    /// Return whether the point is the Edwards identity.
    pub(crate) fn is_identity(&self) -> Choice {
        self.x.is_zero().and(self.y.ct_eq(&self.z))
    }

    /// Return whether the point is nonidentity and satisfies `[q]P = I`.
    pub(crate) fn is_prime_subgroup_nonidentity(&self) -> Choice {
        self.is_identity().not().and(self.is_prime_subgroup())
    }

    /// Return whether `[L]P` is the identity, allowing the identity itself.
    pub(crate) fn is_prime_subgroup(&self) -> Choice {
        self.scalar_mul_encoded(&PRIME_ORDER_BYTES).is_identity()
    }

    /// Multiply by the public cofactor four using two complete doublings.
    pub(crate) fn multiply_by_cofactor(self) -> Self {
        self.double().double()
    }

    /// Compare two valid projective points without affine inversion.
    pub(crate) fn ct_eq(&self, rhs: &Self) -> Choice {
        self.x
            .mul(rhs.z)
            .ct_eq(&rhs.x.mul(self.z))
            .and(self.y.mul(rhs.z).ct_eq(&rhs.y.mul(self.z)))
    }

    fn is_valid(&self) -> Choice {
        let xx = self.x.square();
        let yy = self.y.square();
        let zz = self.z.square();
        let extended_relation = self.x.mul(self.y).ct_eq(&self.z.mul(self.t));
        let left = EDWARDS_A.mul(xx).mul(zz).add(yy.mul(zz));
        let right = zz.square().add(EDWARDS_D.mul(xx).mul(yy));

        self.z
            .is_zero()
            .not()
            .and(extended_relation)
            .and(left.ct_eq(&right))
    }

    fn conditional_select(when_false: Self, when_true: Self, choice: Choice) -> Self {
        Self {
            x: FieldElement::conditional_select(when_false.x, when_true.x, choice),
            y: FieldElement::conditional_select(when_false.y, when_true.y, choice),
            z: FieldElement::conditional_select(when_false.z, when_true.z, choice),
            t: FieldElement::conditional_select(when_false.t, when_true.t, choice),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCALAR_12345: [u8; FIELD_BYTES] =
        hex_38(b"3930000000000000000000000000000000000000000000000000000000000000000000000000");
    const MULTIPLE_12345_ENCODING: [u8; FIELD_BYTES] =
        hex_38(b"9ffa3fbe41c0ee7def76269467f7702cbe30ed930021f90ee241b5b1bdc34a6af128f51db512");
    const DRAFT00_PRUNED_SECRET: [u8; FIELD_BYTES] =
        hex_38(b"686d13326b81a70d3bb299eb137d475b59ddee671f92cdd334883fe6d784fc03813c2542a119");
    const DRAFT00_PUBLIC_ENCODING: [u8; FIELD_BYTES] =
        hex_38(b"8cad07b4f9a308523a8df9bee22a721b8ff5e597c1ce47e39df67f97a475fd018013fc188890");
    const DRAFT00_NONCE_SCALAR: [u8; FIELD_BYTES] =
        hex_38(b"a3c7355a9c1ea903bc4fef22588ce6b75c292ccea514dbe689bacf7e3b3ca64449c9983cbd05");
    const DRAFT00_COMMITMENT_ENCODING: [u8; FIELD_BYTES] =
        hex_38(b"2964a4e22d5ed6e41ad5d5bbfdf4d518bb067b8982f3f8f5900d074a6bee97567b9581033694");
    const FIELD_MODULUS_ENCODING: [u8; FIELD_BYTES] =
        hex_38(b"b30300000000000000000000f8ffffffffffffffffffffffffffffffffffffffffffffffff1f");
    const ORDER_TWO_ENCODING: [u8; FIELD_BYTES] =
        hex_38(b"b20300000000000000000000f8ffffffffffffffffffffffffffffffffffffffffffffffff1f");

    const fn hex_38(hex: &[u8; FIELD_BYTES * 2]) -> [u8; FIELD_BYTES] {
        let mut output = [0_u8; FIELD_BYTES];
        let mut index = 0;
        while index < FIELD_BYTES {
            output[index] = (hex_nibble(hex[index * 2]) << 4) | hex_nibble(hex[index * 2 + 1]);
            index += 1;
        }
        output
    }

    const fn hex_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid test hex"),
        }
    }

    fn scalar(bytes: &[u8; FIELD_BYTES]) -> Scalar {
        Scalar::from_canonical_bytes(bytes)
            .expect_copied("test scalar must be canonically encoded below q")
    }

    #[test]
    fn basepoint_constant_roundtrips_and_has_exact_prime_order() {
        assert!(EdwardsPoint::BASEPOINT.is_valid().to_bool());
        assert_eq!(EdwardsPoint::BASEPOINT.encode(), Ok(BASEPOINT_ENCODING));

        let decoded = EdwardsPoint::decode_strict_subgroup(&BASEPOINT_ENCODING)
            .expect("the basepoint encoding must be a strict subgroup point");
        assert!(decoded.ct_eq(&EdwardsPoint::BASEPOINT).to_bool());
        assert!(
            EdwardsPoint::BASEPOINT
                .scalar_mul_encoded(&PRIME_ORDER_BYTES)
                .is_identity()
                .to_bool()
        );
    }

    #[test]
    fn complete_group_formulas_cover_identity_negation_and_doubling() {
        let base = EdwardsPoint::BASEPOINT;
        assert!(base.add(EdwardsPoint::IDENTITY).ct_eq(&base).to_bool());
        assert!(EdwardsPoint::IDENTITY.add(base).ct_eq(&base).to_bool());
        assert!(base.add(base.negate()).is_identity().to_bool());
        assert!(base.double().ct_eq(&base.add(base)).to_bool());
        assert!(base.scalar_mul(&Scalar::ZERO).is_identity().to_bool());
        assert!(base.scalar_mul(&Scalar::ONE).ct_eq(&base).to_bool());

        let mut two = [0_u8; FIELD_BYTES];
        two[0] = 2;
        assert!(
            base.scalar_mul(&scalar(&two))
                .ct_eq(&base.double())
                .to_bool()
        );
    }

    #[test]
    fn scalar_multiplication_calls_exactly_301_fixed_rounds() {
        let mut rounds = 0_usize;
        let result = EdwardsPoint::BASEPOINT.scalar_mul_with(|_| {
            rounds += 1;
            Choice::FALSE
        });

        assert_eq!(rounds, 301);
        assert!(result.is_identity().to_bool());
    }

    #[test]
    fn fixed_12345_multiple_matches_the_curve_reference() {
        let multiple = EdwardsPoint::BASEPOINT.scalar_mul(&scalar(&SCALAR_12345));
        assert_eq!(multiple.encode(), Ok(MULTIPLE_12345_ENCODING));
        assert!(multiple.is_prime_subgroup_nonidentity().to_bool());
    }

    #[test]
    fn draft00_vector_points_match_scalar_multiplication() {
        let public = EdwardsPoint::BASEPOINT.scalar_mul_pruned(&DRAFT00_PRUNED_SECRET);
        let commitment = EdwardsPoint::BASEPOINT.scalar_mul(&scalar(&DRAFT00_NONCE_SCALAR));
        assert_eq!(public.encode(), Ok(DRAFT00_PUBLIC_ENCODING));
        assert_eq!(commitment.encode(), Ok(DRAFT00_COMMITMENT_ENCODING));

        for encoded in [DRAFT00_PUBLIC_ENCODING, DRAFT00_COMMITMENT_ENCODING] {
            let decoded = EdwardsPoint::decode_strict_subgroup(&encoded)
                .expect("draft-00 signer output must pass strict subgroup decoding");
            assert_eq!(decoded.encode(), Ok(encoded));
        }
    }

    #[test]
    fn strict_decoding_rejects_identity_torsion_and_mixed_order() {
        let mut identity_encoding = [0_u8; FIELD_BYTES];
        identity_encoding[0] = 1;
        let identity = EdwardsPoint::decode(&identity_encoding)
            .expect("the identity has a canonical general point encoding");
        assert!(identity.is_identity().to_bool());
        assert!(EdwardsPoint::decode_strict_subgroup(&identity_encoding).is_err());

        let order_two = EdwardsPoint::decode(&ORDER_TWO_ENCODING)
            .expect("the rational order-two point has a canonical encoding");
        assert!(EdwardsPoint::decode_strict_subgroup(&ORDER_TWO_ENCODING).is_err());

        let mixed = EdwardsPoint::BASEPOINT.add(order_two);
        let mixed_encoding = mixed.encode().expect("a mixed-order point must encode");
        assert!(EdwardsPoint::decode(&mixed_encoding).is_ok());
        assert!(EdwardsPoint::decode_strict_subgroup(&mixed_encoding).is_err());
    }

    #[test]
    fn decoding_rejects_noncanonical_and_nonpoint_encodings() {
        let mut reserved_301 = BASEPOINT_ENCODING;
        reserved_301[FIELD_BYTES - 1] |= 0x20;
        assert!(EdwardsPoint::decode(&reserved_301).is_err());

        let mut reserved_302 = BASEPOINT_ENCODING;
        reserved_302[FIELD_BYTES - 1] |= 0x40;
        assert!(EdwardsPoint::decode(&reserved_302).is_err());
        assert!(EdwardsPoint::decode(&FIELD_MODULUS_ENCODING).is_err());

        let mut nonpoint = [0_u8; FIELD_BYTES];
        nonpoint[0] = 3;
        assert!(EdwardsPoint::decode(&nonpoint).is_err());

        let mut noncanonical_identity = [0_u8; FIELD_BYTES];
        noncanonical_identity[0] = 1;
        noncanonical_identity[FIELD_BYTES - 1] = 0x80;
        assert!(EdwardsPoint::decode(&noncanonical_identity).is_err());
    }
}
