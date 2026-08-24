//! Constant-time baseline arithmetic for the ED301 prime field.
//!
//! This module deliberately uses a generic Montgomery backend. A future
//! backend may exploit the sparse shape of the modulus, but it must remain
//! differentially equivalent to this implementation.

#![allow(
    dead_code,
    reason = "retained Montgomery oracle also supplies optimized-backend inversion"
)]

use crypto_bigint::{
    Choice, CtAssign, CtEq, CtLt, CtOption, U320, const_monty_form, const_monty_params,
    modular::ConstMontyParams,
};

use crate::parameters::FIELD_BYTES;

// (p + 1) / 4 for p = 2^301 - 2^99 + 947. Since p = 3 (mod 4), raising a
// square to this exponent yields one of its two square roots.
#[allow(
    dead_code,
    reason = "used by the internal Edwards point decoder before the signature API"
)]
const SQRT_EXPONENT_BITS: u32 = 301;
const SQRT_EXPONENT: U320 = U320::from_be_hex(
    "000007fffffffffffffffffffffffffffffffffffffffffffffffffe0000000000000000000000ed",
);

// (p - 3) / 4.  For p = 3 (mod 4), a square root of u / v can be
// computed as u * (u * v)^((p - 3) / 4).  This combines the inversion and
// square-root exponentiations needed by compressed Edwards-point decoding.
const SQRT_RATIO_EXPONENT: U320 = U320::from_be_hex(
    "000007fffffffffffffffffffffffffffffffffffffffffffffffffe0000000000000000000000ec",
);

const_monty_params!(
    FieldModulus,
    U320,
    "00001ffffffffffffffffffffffffffffffffffffffffffffffffff80000000000000000000003b3",
    "The ED301-v1 prime field modulus"
);
const_monty_form!(
    MontgomeryFieldElement,
    FieldModulus,
    "An element of the ED301-v1 prime field in Montgomery form"
);

const MODULUS: U320 = U320::from_be_hex(
    "00001ffffffffffffffffffffffffffffffffffffffffffffffffff80000000000000000000003b3",
);

/// Internal prime-field element in Montgomery form.
#[derive(Clone, Copy)]
pub(crate) struct FieldElement(MontgomeryFieldElement);

impl FieldElement {
    /// Additive identity.
    pub(crate) const ZERO: Self = Self(MontgomeryFieldElement::ZERO);

    /// Multiplicative identity.
    pub(crate) const ONE: Self = Self(MontgomeryFieldElement::ONE);

    /// Decode an exact 38-byte canonical little-endian field element.
    ///
    /// The returned value is absent when the integer is greater than or equal
    /// to the field modulus. This also rejects all three reserved high bits.
    pub(crate) fn from_canonical_bytes(bytes: &[u8; FIELD_BYTES]) -> CtOption<Self> {
        let mut widened = [0_u8; U320::BYTES];
        widened[..FIELD_BYTES].copy_from_slice(bytes);
        let integer = U320::from_le_slice(&widened);
        let is_canonical = integer.ct_lt(&MODULUS);

        CtOption::new(Self(MontgomeryFieldElement::new(&integer)), is_canonical)
    }

    /// Construct a field element from a small canonical integer.
    #[allow(dead_code, reason = "used by the forthcoming Edwards implementation")]
    pub(crate) const fn from_u64(value: u64) -> Self {
        Self(MontgomeryFieldElement::new(&U320::from_u64(value)))
    }

    /// Construct from an internal integer known to be canonical.
    pub(crate) const fn from_canonical_uint(value: U320) -> Self {
        Self(MontgomeryFieldElement::new(&value))
    }

    /// Construct from five little-endian words known to be canonical.
    pub(crate) const fn from_canonical_words(words: [u64; 5]) -> Self {
        Self::from_canonical_uint(U320::from_words(words))
    }

    /// Encode as an exact canonical 38-byte little-endian field element.
    pub(crate) fn to_canonical_bytes(self) -> [u8; FIELD_BYTES] {
        let encoded = self.0.retrieve().to_le_bytes();
        let mut output = [0_u8; FIELD_BYTES];
        output.copy_from_slice(&encoded.as_slice()[..FIELD_BYTES]);
        output
    }

    /// Add two field elements.
    pub(crate) const fn add(self, rhs: Self) -> Self {
        Self(self.0.add(&rhs.0))
    }

    /// Subtract two field elements.
    pub(crate) const fn sub(self, rhs: Self) -> Self {
        Self(self.0.sub(&rhs.0))
    }

    /// Negate a field element.
    #[allow(dead_code, reason = "used by the forthcoming Edwards implementation")]
    pub(crate) const fn neg(self) -> Self {
        Self(self.0.neg())
    }

    /// Multiply two field elements.
    pub(crate) const fn mul(self, rhs: Self) -> Self {
        Self(self.0.mul(&rhs.0))
    }

    /// Square a field element.
    pub(crate) const fn square(self) -> Self {
        Self(self.0.square())
    }

    /// Compute the multiplicative inverse, or an absent value for zero.
    pub(crate) fn invert(self) -> CtOption<Self> {
        self.0.invert().map(Self)
    }

    /// Return a square root when one exists.
    ///
    /// The exponent and loop bounds are fixed public constants. The candidate
    /// is always computed and verified before the result is exposed.
    #[allow(
        dead_code,
        reason = "used by the internal Edwards point decoder before the signature API"
    )]
    pub(crate) fn sqrt(self) -> CtOption<Self> {
        let candidate = Self(self.0.pow_bounded_exp(&SQRT_EXPONENT, SQRT_EXPONENT_BITS));
        CtOption::new(candidate, candidate.square().ct_eq(&self))
    }

    /// Return a square root of `numerator / denominator` when it exists.
    ///
    /// The result is computed with one fixed-exponent operation and verified
    /// without first inverting `denominator`.  A zero denominator is always
    /// rejected, including the otherwise ambiguous `0 / 0` case.
    pub(crate) fn sqrt_ratio(numerator: Self, denominator: Self) -> CtOption<Self> {
        let product = numerator.mul(denominator);
        let factor = Self(
            product
                .0
                .pow_bounded_exp(&SQRT_RATIO_EXPONENT, SQRT_EXPONENT_BITS),
        );
        let candidate = numerator.mul(factor);
        let is_root = candidate
            .square()
            .mul(denominator)
            .ct_eq(&numerator)
            .and(denominator.is_zero().not());
        CtOption::new(candidate, is_root)
    }

    /// Return whether the canonical representative is odd.
    #[allow(
        dead_code,
        reason = "used by the internal Edwards point encoder before the signature API"
    )]
    pub(crate) fn is_odd(&self) -> Choice {
        Choice::from(self.to_canonical_bytes()[0] & 1)
    }

    /// Compare two field elements without data-dependent short-circuiting.
    pub(crate) fn ct_eq(&self, rhs: &Self) -> Choice {
        self.0.ct_eq(&rhs.0)
    }

    /// Test for the additive identity without data-dependent short-circuiting.
    pub(crate) fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    /// Swap two field elements for the internal constant-time unit test.
    #[cfg(test)]
    pub(crate) fn conditional_swap(left: &mut Self, right: &mut Self, choice: Choice) {
        let original_left = *left;
        left.0.ct_assign(&right.0, choice);
        right.0.ct_assign(&original_left.0, choice);
    }

    /// Select `when_true` when `choice` is true and `when_false` otherwise.
    #[allow(
        dead_code,
        reason = "used by internal Edwards arithmetic before the signature API"
    )]
    pub(crate) fn conditional_select(when_false: Self, when_true: Self, choice: Choice) -> Self {
        let mut selected = when_false;
        selected.0.ct_assign(&when_true.0, choice);
        selected
    }
}

impl Default for FieldElement {
    fn default() -> Self {
        Self::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_U_BYTES: [u8; FIELD_BYTES] =
        hex_le_38(b"5ba6f0f4ccc6ff5f018a2496fe165eb7d1893949fe3d05f79c12d2bd99952cd42d2ae9546308");

    const fn hex_le_38(hex: &[u8; FIELD_BYTES * 2]) -> [u8; FIELD_BYTES] {
        let mut output = [0_u8; FIELD_BYTES];
        let mut i = 0;
        while i < FIELD_BYTES {
            output[i] = (hex_nibble(hex[i * 2]) << 4) | hex_nibble(hex[i * 2 + 1]);
            i += 1;
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

    fn le38(integer: U320) -> [u8; FIELD_BYTES] {
        let encoded = integer.to_le_bytes();
        let mut output = [0_u8; FIELD_BYTES];
        output.copy_from_slice(&encoded.as_slice()[..FIELD_BYTES]);
        output
    }

    fn decode(bytes: &[u8; FIELD_BYTES]) -> FieldElement {
        FieldElement::from_canonical_bytes(bytes)
            .expect_copied("test value must be a canonical field element")
    }

    #[test]
    fn strict_decode_accepts_boundaries_and_basepoint_u() {
        let modulus_minus_one = MODULUS.wrapping_sub(&U320::ONE);
        let values = [[0_u8; FIELD_BYTES], le38(modulus_minus_one), BASE_U_BYTES];

        for bytes in values {
            let element = decode(&bytes);
            assert_eq!(element.to_canonical_bytes(), bytes);
        }
    }

    #[test]
    fn strict_decode_rejects_modulus_and_reserved_bits() {
        let modulus_bytes = le38(MODULUS);
        assert!(
            FieldElement::from_canonical_bytes(&modulus_bytes)
                .is_none()
                .to_bool()
        );

        for high_bit in [0x20_u8, 0x40, 0x80] {
            let mut bytes = [0_u8; FIELD_BYTES];
            bytes[FIELD_BYTES - 1] = high_bit;
            assert!(
                FieldElement::from_canonical_bytes(&bytes)
                    .is_none()
                    .to_bool()
            );
        }
    }

    #[test]
    fn arithmetic_reduces_modulo_p() {
        let five = FieldElement::from_u64(5);
        let seven = FieldElement::from_u64(7);
        assert_eq!(five.add(seven).to_canonical_bytes()[0], 12);
        assert_eq!(five.mul(seven).to_canonical_bytes()[0], 35);
        assert_eq!(five.square().to_canonical_bytes()[0], 25);
        assert_eq!(five.sub(seven).add(seven).to_canonical_bytes()[0], 5);
        assert!(five.neg().add(five).is_zero().to_bool());

        let modulus_minus_one = decode(&le38(MODULUS.wrapping_sub(&U320::ONE)));
        assert!(modulus_minus_one.add(FieldElement::ONE).is_zero().to_bool());
    }

    #[test]
    fn inversion_is_total_only_for_nonzero_values() {
        let five = FieldElement::from_u64(5);
        let inverse = five
            .invert()
            .expect_copied("a nonzero field element must be invertible");
        assert!(five.mul(inverse).ct_eq(&FieldElement::ONE).to_bool());
        assert!(FieldElement::ZERO.invert().is_none().to_bool());
    }

    #[test]
    fn conditional_swap_obeys_choice() {
        let one = FieldElement::ONE;
        let two = FieldElement::from_u64(2);

        let (mut left, mut right) = (one, two);
        FieldElement::conditional_swap(&mut left, &mut right, Choice::FALSE);
        assert!(left.ct_eq(&one).to_bool());
        assert!(right.ct_eq(&two).to_bool());

        FieldElement::conditional_swap(&mut left, &mut right, Choice::TRUE);
        assert!(left.ct_eq(&two).to_bool());
        assert!(right.ct_eq(&one).to_bool());
    }

    #[test]
    fn square_root_is_verified_and_canonical_parity_is_reported() {
        let five = FieldElement::from_u64(5);
        let square = five.square();
        let root = square
            .sqrt()
            .expect_copied("a field square must have a square root");

        assert!(root.square().ct_eq(&square).to_bool());
        assert!(root.ct_eq(&five).to_bool());
        let seven = FieldElement::from_u64(7);
        assert!(
            seven
                .square()
                .sqrt()
                .expect_copied("49 has a square root")
                .ct_eq(&seven)
                .to_bool()
        );
        assert!(
            FieldElement::ZERO
                .sqrt()
                .expect_copied("zero has a square root")
                .is_zero()
                .to_bool()
        );
        assert!(
            FieldElement::ONE
                .sqrt()
                .expect_copied("one has a square root")
                .ct_eq(&FieldElement::ONE)
                .to_bool()
        );
        assert!(five.is_odd().to_bool());
        assert!(!FieldElement::from_u64(6).is_odd().to_bool());

        // Two is a quadratic non-residue for this field.
        assert!(FieldElement::from_u64(2).sqrt().is_none().to_bool());
    }

    #[test]
    fn conditional_selection_obeys_choice() {
        let five = FieldElement::from_u64(5);
        let seven = FieldElement::from_u64(7);

        assert!(
            FieldElement::conditional_select(five, seven, Choice::FALSE)
                .ct_eq(&five)
                .to_bool()
        );
        assert!(
            FieldElement::conditional_select(five, seven, Choice::TRUE)
                .ct_eq(&seven)
                .to_bool()
        );
    }
}
