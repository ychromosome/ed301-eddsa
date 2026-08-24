//! Constant-time scalar arithmetic modulo the ED301 prime subgroup order.

use crypto_bigint::{
    Choice, CtLt, CtOption, NonZero, U320, const_monty_form, const_monty_params,
    modular::ConstMontyParams,
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
const RADIX_64: MontgomeryScalar = MontgomeryScalar::new(&U320::from_words([0, 1, 0, 0, 0]));

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
        let mut words = secret([0_u64; 5]);
        let mut index = 0;
        while index < 4 {
            let offset = index * 8;
            let mut encoded = secret([0_u8; 8]);
            encoded.copy_from_slice(&bytes[offset..offset + 8]);
            words[index] = u64::from_le_bytes(*encoded);
            index += 1;
        }
        let mut high = secret([0_u8; 8]);
        high[..6].copy_from_slice(&bytes[32..38]);
        words[4] = u64::from_le_bytes(*high);
        Self::reduce_words(&words)
    }

    /// Reduce the full 76-byte (608-bit) SHAKE256 result modulo `L`.
    ///
    /// The fixed ten-word schedule processes nine complete little-endian
    /// `u64` words and one top word whose only significant bytes are 72..75.
    #[inline(never)]
    pub(crate) fn reduce_hash_le(bytes: &[u8; HASH_BYTES]) -> Secret<Self> {
        let mut words = secret([0_u64; 10]);
        let mut index = 0;
        while index < 9 {
            let offset = index * 8;
            let mut encoded = secret([0_u8; 8]);
            encoded.copy_from_slice(&bytes[offset..offset + 8]);
            words[index] = u64::from_le_bytes(*encoded);
            index += 1;
        }
        let mut high = secret([0_u8; 8]);
        high[..4].copy_from_slice(&bytes[72..76]);
        words[9] = u64::from_le_bytes(*high);
        Self::reduce_words(&words)
    }

    fn reduce_words<const N: usize>(words: &[u64; N]) -> Secret<Self> {
        let mut accumulator = secret(MontgomeryScalar::ZERO);
        let mut index = N;
        while index != 0 {
            index -= 1;
            let word = secret(words[index]);
            let integer = secret(U320::from_u64(*word));
            let addend = secret(MontgomeryScalar::new(&integer));
            let product = secret(accumulator.mul(&RADIX_64));
            accumulator = secret(product.add(&addend));
        }
        secret(Self(accumulator.retrieve()))
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

    const L_BYTES: [u8; 38] =
        hex_38(b"0396bed0a1e30226314afb4798809208c8dc1600000000000000000000000000000000000008");

    const fn hex_38(hex: &[u8; 76]) -> [u8; 38] {
        let mut output = [0_u8; 38];
        let mut index = 0;
        while index < 38 {
            output[index] = (nibble(hex[index * 2]) << 4) | nibble(hex[index * 2 + 1]);
            index += 1;
        }
        output
    }

    const fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid test hex"),
        }
    }

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

    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = *state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
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
    fn fixed_ten_word_reducer_matches_wide_division() {
        let mut cases = [[0_u8; HASH_BYTES]; 7];
        cases[1][0] = 1;
        cases[2][..38].copy_from_slice(&L_BYTES);
        cases[3][..38].copy_from_slice(&L_BYTES);
        cases[3][0] = cases[3][0].wrapping_add(1);
        cases[4][37] = 0x10;
        cases[5][75] = 0x80;
        cases[6].fill(0xff);
        for case in &cases {
            assert_reduction(case);
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
