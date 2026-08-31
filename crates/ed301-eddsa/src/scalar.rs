//! Constant-time scalar arithmetic modulo the ED301 prime subgroup order.

#[cfg(test)]
use crypto_bigint::Choice;
use crypto_bigint::{
    CtLt, CtOption, NonZero, U320, const_monty_form, const_monty_params, modular::ConstMontyParams,
};
use zeroize::Zeroize;

use crate::{
    parameters::{FIELD_BITS, HASH_BYTES, SCALAR_BYTES},
    secret::{Secret, secret},
};

const_monty_params!(
    ScalarModulus,
    U320,
    "00000800000000000000000000000000000000000016dcc80892809847fb4a312602e3a1d0be9603",
    "The ED301 prime subgroup order"
);
const_monty_form!(
    MontgomeryScalar,
    ScalarModulus,
    "An ED301 scalar in Montgomery form"
);

const MODULUS: U320 = U320::from_be_hex(
    "00000800000000000000000000000000000000000016dcc80892809847fb4a312602e3a1d0be9603",
);
const NONZERO_MODULUS: NonZero<U320> = NonZero::<U320>::new_unwrap(MODULUS);
const RADIX_304: MontgomeryScalar =
    MontgomeryScalar::new(&U320::from_words([0, 0, 0, 0, 1_u64 << 48]));

/// Internal canonical scalar in `0 <= x < L`.
#[derive(Clone, Copy)]
pub(crate) struct Scalar(U320);

impl Scalar {
    /// Additive identity.
    pub(crate) const ZERO: Self = Self(U320::ZERO);

    /// Multiplicative identity.
    #[cfg(test)]
    pub(crate) const ONE: Self = Self(U320::ONE);

    /// Decode an exact canonical signature scalar, accepting zero.
    pub(crate) fn from_canonical_bytes(bytes: &[u8; SCALAR_BYTES]) -> CtOption<Self> {
        let integer = uint_from_le38(bytes);
        CtOption::new(Self(integer), integer.ct_lt(&MODULUS))
    }

    /// Reduce an exact pruned 38-byte little-endian secret scalar modulo `L`.
    pub(crate) fn reduce_pruned_le(bytes: &[u8; SCALAR_BYTES]) -> Secret<Self> {
        let integer = secret(uint_from_le38(bytes));
        let reduced = secret(MontgomeryScalar::new(&integer));
        secret(Self(reduced.retrieve()))
    }

    /// Reduce the full 76-byte (608-bit) SHAKE256 result modulo `L`.
    ///
    /// The fixed schedule groups the input into two 304-bit chunks and
    /// combines their existing Montgomery reductions without a division
    /// path.
    #[inline(never)]
    pub(crate) fn reduce_hash_le(bytes: &[u8; HASH_BYTES]) -> Secret<Self> {
        let mut low_bytes = secret([0_u8; SCALAR_BYTES]);
        let mut high_bytes = secret([0_u8; SCALAR_BYTES]);
        low_bytes.copy_from_slice(&bytes[..SCALAR_BYTES]);
        high_bytes.copy_from_slice(&bytes[SCALAR_BYTES..]);

        let low = secret(uint_from_le38(&low_bytes));
        let high = secret(uint_from_le38(&high_bytes));
        let low_reduced = secret(MontgomeryScalar::new(&low));
        let high_reduced = secret(MontgomeryScalar::new(&high));
        let high_shifted = secret(high_reduced.mul(&RADIX_304));
        let combined = secret(high_shifted.add(&low_reduced));
        secret(Self(combined.retrieve()))
    }

    /// Encode as the canonical 38-byte little-endian representation.
    #[cfg(test)]
    pub(crate) fn canonical_bytes(&self) -> [u8; SCALAR_BYTES] {
        let mut output = [0_u8; SCALAR_BYTES];
        self.write_canonical_bytes(&mut output);
        output
    }

    /// Write canonical bytes into a caller-owned, potentially guarded buffer.
    pub(crate) fn write_canonical_bytes(&self, output: &mut [u8; SCALAR_BYTES]) {
        let words = secret(self.0.to_words());
        let mut word_index = 0;
        let mut offset = 0;
        while offset < SCALAR_BYTES {
            let encoded = secret(words[word_index].to_le_bytes());
            let remaining = SCALAR_BYTES - offset;
            let take = if remaining < encoded.len() {
                remaining
            } else {
                encoded.len()
            };
            output[offset..offset + take].copy_from_slice(&encoded[..take]);
            offset += take;
            word_index += 1;
        }
    }

    /// Add modulo `L`.
    pub(crate) fn add(&self, rhs: &Self) -> Secret<Self> {
        secret(Self(self.0.add_mod(&rhs.0, &NONZERO_MODULUS)))
    }

    /// Multiply modulo `L`.
    pub(crate) fn mul(&self, rhs: &Self) -> Secret<Self> {
        let left = secret(MontgomeryScalar::new(&self.0));
        let right = secret(MontgomeryScalar::new(&rhs.0));
        let product = secret(left.mul(&right));
        secret(Self(product.retrieve()))
    }

    /// Read one bit for the fixed 301-round scalar multiplier.
    #[cfg(test)]
    pub(crate) const fn bit(&self, index: usize) -> Choice {
        debug_assert!(index < FIELD_BITS);
        self.0.bit(index as u32)
    }

    /// Recode a public scalar as width-`w` non-adjacent form.
    ///
    /// This routine is deliberately variable-time and may only be used by
    /// public verification paths.  Widths used by the point core are fixed
    /// at compile-time call sites and keep every digit within `i8`.
    pub(crate) fn vartime_wnaf(&self, width: u32) -> [i8; FIELD_BITS + 1] {
        assert!(
            (2..=8).contains(&width),
            "wNAF width must keep every digit representable as i8"
        );
        let radix = 1_u64 << width;
        let half = radix >> 1;
        let mask = radix - 1;
        let mut value = self.0;
        let mut digits = [0_i8; FIELD_BITS + 1];
        let mut index = 0;

        while index < digits.len() {
            if value.bit(0).to_bool_vartime() {
                let low = value.to_words()[0] & mask;
                let digit = if low >= half {
                    low as i16 - radix as i16
                } else {
                    low as i16
                };
                digits[index] = digit as i8;
                if digit < 0 {
                    value = value.wrapping_add(&U320::from_u64((-digit) as u64));
                } else {
                    value = value.wrapping_sub(&U320::from_u64(digit as u64));
                }
            }
            value = value.shr_vartime(1);
            index += 1;
        }
        debug_assert!(value.is_zero().to_bool_vartime());
        digits
    }
}

impl Default for Scalar {
    fn default() -> Self {
        Self::ZERO
    }
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

fn uint_from_le38(bytes: &[u8; SCALAR_BYTES]) -> U320 {
    let mut widened = [0_u8; U320::BYTES];
    widened[..SCALAR_BYTES].copy_from_slice(bytes);
    let value = U320::from_le_slice(&widened);
    widened.zeroize();
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{decode_hex_array, splitmix64};

    const L_BYTES: [u8; 38] = decode_hex_array(
        b"0396bed0a1e30226314afb4798809208c8dc1600000000000000000000000000000000000008",
    );
    // Independently reproduced with Python integers and Perl Math::BigInt.
    const RADIX_304_REDUCED: U320 = U320::from_be_hex(
        "000007fffffffffffffffffffffffffffffffffffd3b43c6f6426d8f4892040c65a66f67b8ebd5a3",
    );

    fn division_oracle(bytes: &[u8; HASH_BYTES]) -> U320 {
        let mut low = [0_u8; U320::BYTES];
        let mut high = [0_u8; U320::BYTES];
        low.copy_from_slice(&bytes[..U320::BYTES]);
        high[..HASH_BYTES - U320::BYTES].copy_from_slice(&bytes[U320::BYTES..]);
        U320::rem_wide(
            (U320::from_le_slice(&low), U320::from_le_slice(&high)),
            &NONZERO_MODULUS,
        )
    }

    fn assert_reduction(bytes: &[u8; HASH_BYTES]) {
        assert_eq!(Scalar::reduce_hash_le(bytes).0, division_oracle(bytes));
    }

    fn assert_half_reduction(value: U320) {
        let encoded = value.to_le_bytes();
        assert_eq!(&encoded[SCALAR_BYTES..], &[0_u8; 2]);
        let mut half = [0_u8; SCALAR_BYTES];
        half.copy_from_slice(&encoded[..SCALAR_BYTES]);
        let expected = U320::rem_wide((value, U320::ZERO), &NONZERO_MODULUS);
        assert_eq!(Scalar::reduce_pruned_le(&half).0, expected);
        for offset in [0, SCALAR_BYTES] {
            let mut bytes = [0_u8; HASH_BYTES];
            bytes[offset..offset + SCALAR_BYTES].copy_from_slice(&encoded[..SCALAR_BYTES]);
            assert_reduction(&bytes);
        }
    }

    #[test]
    fn canonical_scalar_boundaries_are_exact() {
        let zero = [0_u8; 38];
        assert!(Scalar::from_canonical_bytes(&zero).is_some().to_bool());
        let mut l_minus_one = L_BYTES;
        l_minus_one[0] -= 1;
        assert!(
            Scalar::from_canonical_bytes(&l_minus_one)
                .is_some()
                .to_bool()
        );
        assert!(Scalar::from_canonical_bytes(&L_BYTES).is_none().to_bool());
    }

    #[test]
    fn fixed_radix_304_reducer_matches_wide_division() {
        let mut cases = [[0_u8; HASH_BYTES]; 12];
        cases[1][0] = 1;
        cases[2][..38].copy_from_slice(&L_BYTES);
        cases[3][..38].copy_from_slice(&L_BYTES);
        cases[3][0] = cases[3][0].wrapping_add(1);
        cases[4][37] = 0x10;
        cases[5][75] = 0x80;
        cases[6].fill(0xff);
        cases[7].fill(0xaa);
        cases[8].fill(0x55);
        cases[9][37] = 0x80;
        cases[10][38] = 0x80;
        cases[11][37] = 0x80;
        cases[11][38] = 0x80;
        for case in &cases {
            assert_reduction(case);
        }

        let l_minus_one = MODULUS.wrapping_sub(&U320::ONE);
        let l_plus_one = MODULUS.wrapping_add(&U320::ONE);
        let two_l = MODULUS.wrapping_add(&MODULUS);
        let two_l_minus_one = two_l.wrapping_sub(&U320::ONE);
        let max_304 = U320::MAX.shr_vartime(16);
        for value in [
            U320::ZERO,
            U320::ONE,
            l_minus_one,
            MODULUS,
            l_plus_one,
            two_l_minus_one,
            two_l,
            max_304,
        ] {
            assert_half_reduction(value);
        }

        let mut state = 0x4544_3330_312d_5231_u64;
        for _ in 0..10_000 {
            let mut bytes = [0_u8; HASH_BYTES];
            for chunk in bytes.chunks_mut(8) {
                let word = splitmix64(&mut state).to_le_bytes();
                chunk.copy_from_slice(&word[..chunk.len()]);
            }
            assert_reduction(&bytes);
        }
    }

    #[test]
    fn radix_304_matches_independently_computed_literal() {
        assert_eq!(RADIX_304.retrieve(), RADIX_304_REDUCED);
    }

    #[test]
    fn bytes_seventy_two_through_seventy_five_are_significant() {
        let base = [0_u8; HASH_BYTES];
        let base_reduced = Scalar::reduce_hash_le(&base).canonical_bytes();
        for index in 72..76 {
            let mut changed = base;
            changed[index] = 1;
            assert_reduction(&changed);
            assert_ne!(
                Scalar::reduce_hash_le(&changed).canonical_bytes(),
                base_reduced
            );
        }
    }

    #[test]
    fn every_one_of_the_608_input_bits_matches_wide_division() {
        for bit in 0..(HASH_BYTES * 8) {
            let mut bytes = [0_u8; HASH_BYTES];
            bytes[bit >> 3] = 1_u8 << (bit & 7);
            assert_reduction(&bytes);
        }
    }

    #[test]
    #[should_panic(expected = "wNAF width must keep every digit representable as i8")]
    fn wnaf_rejects_unrepresentable_width_in_release_builds() {
        let _ = Scalar::ZERO.vartime_wnaf(9);
    }
}
