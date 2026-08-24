//! Specialized five-limb arithmetic for `p = 2^301 - 2^99 + 947`.
//!
//! Group arithmetic uses this canonical `[u64; 5]` representation and its
//! fixed two-fold pseudo-Mersenne reduction.  The retained crypto-bigint
//! Montgomery implementation in [`crate::field`] remains the independent
//! differential oracle and supplies the variable-time-free inversion used by
//! projective encoding.  Fixed-exponent square-root ratios stay inside this
//! backend, are independently verified, and are differentially tested against
//! the Montgomery oracle.

use crypto_bigint::{Choice, CtAssign, CtEq, CtOption};

use crate::parameters::FIELD_BYTES;

const LIMBS: usize = 5;
const TOP_BITS: u32 = 45;
const TOP_MASK: u64 = (1_u64 << TOP_BITS) - 1;
const FOLD_SUBTRAHEND: u64 = 947;

// p in little-endian radix 2^64.
const MODULUS: [u64; LIMBS] = [
    0x0000_0000_0000_03b3,
    0xffff_fff8_0000_0000,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x0000_1fff_ffff_ffff,
];

// p - 2, used only while constructing immutable affine tables at compile time.
const INVERSION_EXPONENT: [u64; LIMBS] = [
    0x0000_0000_0000_03b1,
    0xffff_fff8_0000_0000,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x0000_1fff_ffff_ffff,
];

// (p - 3) / 4 in little-endian limbs.  This public fixed exponent computes
// square roots of ratios for p = 3 (mod 4).
const SQRT_RATIO_EXPONENT: [u64; LIMBS] = [
    0x0000_0000_0000_00ec,
    0xffff_fffe_0000_0000,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x0000_07ff_ffff_ffff,
];

/// Canonical field element in five little-endian limbs.
#[derive(Clone, Copy)]
pub(crate) struct Fe301([u64; LIMBS]);

impl Fe301 {
    pub(crate) const ZERO: Self = Self([0; LIMBS]);
    pub(crate) const ONE: Self = Self([1, 0, 0, 0, 0]);

    pub(crate) fn from_canonical_bytes(bytes: &[u8; FIELD_BYTES]) -> CtOption<Self> {
        let mut limbs = [0_u64; LIMBS];
        let mut index = 0;
        while index < LIMBS - 1 {
            let mut encoded = [0_u8; 8];
            encoded.copy_from_slice(&bytes[index * 8..(index + 1) * 8]);
            limbs[index] = u64::from_le_bytes(encoded);
            index += 1;
        }
        let mut top = [0_u8; 8];
        top[..FIELD_BYTES - 32].copy_from_slice(&bytes[32..]);
        limbs[4] = u64::from_le_bytes(top);
        let (_, borrow) = subtract_limbs(limbs, MODULUS);
        CtOption::new(Self(limbs), Choice::from_u8_lsb(borrow as u8))
    }

    pub(crate) const fn from_u64(value: u64) -> Self {
        Self([value, 0, 0, 0, 0])
    }

    pub(crate) const fn from_canonical_words(words: [u64; LIMBS]) -> Self {
        Self(words)
    }

    pub(crate) fn to_canonical_bytes(self) -> [u8; FIELD_BYTES] {
        let mut encoded = [0_u8; FIELD_BYTES];
        let mut index = 0;
        while index < LIMBS - 1 {
            encoded[index * 8..(index + 1) * 8].copy_from_slice(&self.0[index].to_le_bytes());
            index += 1;
        }
        encoded[32..].copy_from_slice(&self.0[4].to_le_bytes()[..FIELD_BYTES - 32]);
        encoded
    }

    #[inline(always)]
    pub(crate) fn add(self, rhs: Self) -> Self {
        let (sum, _) = add_limbs(self.0, rhs.0);
        Self(conditional_subtract_modulus_ct(sum))
    }

    #[inline(always)]
    pub(crate) fn sub(self, rhs: Self) -> Self {
        let (difference, borrow) = subtract_limbs(self.0, rhs.0);
        let (corrected, _) = add_limbs(difference, MODULUS);
        let mut output = difference;
        output.ct_assign(&corrected, Choice::from_u8_lsb(borrow as u8));
        Self(output)
    }

    #[inline(always)]
    pub(crate) fn neg(self) -> Self {
        Self::ZERO.sub(self)
    }

    #[inline(always)]
    pub(crate) fn mul(self, rhs: Self) -> Self {
        Self(reduce_wide(multiply_wide(self.0, rhs.0)))
    }

    /// Multiply by a small integer without routing the sparse five-limb
    /// product through the general 602-bit reducer.
    ///
    /// The group formulas use this for the two public curve constants.  For
    /// `value <= u32::MAX`, the product has at most 333 bits, so one fold of
    /// `2^301 = 2^99 - 947` followed by one conditional subtraction is
    /// sufficient.
    #[inline(always)]
    pub(crate) fn mul_small(self, value: u32) -> Self {
        let product = multiply_five_by_u32(self.0, value);
        let high = (product[4] >> TOP_BITS) | (product[5] << (64 - TOP_BITS));
        let mut reduced = [
            product[0],
            product[1],
            product[2],
            product[3],
            product[4] & TOP_MASK,
        ];

        // Add high * 2^99.
        let add_low = high << 35;
        let add_high = high >> 29;
        let sum = reduced[1] as u128 + add_low as u128;
        reduced[1] = sum as u64;
        let sum = reduced[2] as u128 + add_high as u128 + (sum >> 64);
        reduced[2] = sum as u64;
        let mut carry = (sum >> 64) as u64;
        let mut index = 3;
        while index < LIMBS {
            let sum = reduced[index] as u128 + carry as u128;
            reduced[index] = sum as u64;
            carry = (sum >> 64) as u64;
            index += 1;
        }

        // Subtract high * 947 and add p back if that underflowed.
        let penalty = high as u128 * FOLD_SUBTRAHEND as u128;
        let (word, first_borrow) = sub_with_borrow(reduced[0], penalty as u64, 0);
        reduced[0] = word;
        let mut borrow = first_borrow;
        index = 1;
        while index < LIMBS {
            let (word, next_borrow) = sub_with_borrow(reduced[index], 0, borrow);
            reduced[index] = word;
            borrow = next_borrow;
            index += 1;
        }
        let (corrected, _) = add_limbs(reduced, MODULUS);
        reduced.ct_assign(&corrected, Choice::from_u8_lsb(borrow as u8));
        Self(conditional_subtract_modulus_ct(reduced))
    }

    #[inline(always)]
    pub(crate) fn square(self) -> Self {
        Self(reduce_wide(square_wide(self.0)))
    }

    #[inline(always)]
    pub(crate) const fn add_const(self, rhs: Self) -> Self {
        let (sum, _) = add_limbs(self.0, rhs.0);
        Self(conditional_subtract_modulus_const(sum))
    }

    #[inline(always)]
    pub(crate) const fn sub_const(self, rhs: Self) -> Self {
        let (difference, borrow) = subtract_limbs(self.0, rhs.0);
        let mask = 0_u64.wrapping_sub(borrow);
        let mut corrected = [0_u64; LIMBS];
        let mut carry = 0_u64;
        let mut index = 0;
        while index < LIMBS {
            let accumulator =
                difference[index] as u128 + (MODULUS[index] & mask) as u128 + carry as u128;
            corrected[index] = accumulator as u64;
            carry = (accumulator >> 64) as u64;
            index += 1;
        }
        Self(corrected)
    }

    #[inline(always)]
    pub(crate) const fn mul_const(self, rhs: Self) -> Self {
        Self(reduce_wide_const(multiply_wide(self.0, rhs.0)))
    }

    #[inline(always)]
    pub(crate) const fn mul_small_const(self, value: u32) -> Self {
        self.mul_const(Self::from_u64(value as u64))
    }

    #[inline(always)]
    pub(crate) const fn square_const(self) -> Self {
        Self(reduce_wide_const(square_wide(self.0)))
    }

    pub(crate) fn invert(self) -> CtOption<Self> {
        let oracle = crate::field::FieldElement::from_canonical_bytes(&self.to_canonical_bytes())
            .to_inner_unchecked();
        let inverse = oracle.invert();
        let present = inverse.is_some();
        let converted =
            Self::from_canonical_bytes(&inverse.to_inner_unchecked().to_canonical_bytes())
                .to_inner_unchecked();
        CtOption::new(converted, present)
    }

    /// Invert a known-nonzero compile-time table denominator with Fermat's
    /// theorem.  Runtime decoding continues to use the independent
    /// Montgomery/safegcd boundary above; this fixed exponentiation exists so
    /// immutable Niels tables can be batch-normalized during const evaluation.
    pub(crate) const fn invert_const_nonzero(self) -> Self {
        self.pow_fixed_window4_const(INVERSION_EXPONENT, 301)
    }

    #[cfg(test)]
    pub(crate) fn sqrt(self) -> CtOption<Self> {
        let oracle = crate::field::FieldElement::from_canonical_bytes(&self.to_canonical_bytes())
            .to_inner_unchecked();
        let root = oracle.sqrt();
        let present = root.is_some();
        let converted = Self::from_canonical_bytes(&root.to_inner_unchecked().to_canonical_bytes())
            .to_inner_unchecked();
        CtOption::new(converted, present)
    }

    /// Compute and verify a square root of `numerator / denominator`.
    ///
    /// The exponent is public and fixed.  A four-bit table reduces the number
    /// of five-limb multiplications without introducing input-dependent
    /// control flow or table indices.
    pub(crate) fn sqrt_ratio(numerator: Self, denominator: Self) -> CtOption<Self> {
        let product = numerator.mul(denominator);
        let candidate = numerator.mul(product.pow_fixed_window4(SQRT_RATIO_EXPONENT, 299));
        let is_root = candidate
            .square()
            .mul(denominator)
            .ct_eq(&numerator)
            .and(denominator.is_zero().not());
        CtOption::new(candidate, is_root)
    }

    /// Exponentiate by a public compile-time value using four-bit windows.
    fn pow_fixed_window4(self, exponent: [u64; LIMBS], exponent_bits: usize) -> Self {
        let mut powers = [Self::ONE; 16];
        let mut index = 1;
        while index < powers.len() {
            powers[index] = powers[index - 1].mul(self);
            index += 1;
        }

        let mut result = Self::ONE;
        let mut window = exponent_bits.div_ceil(4);
        while window != 0 {
            window -= 1;
            result = result.square().square().square().square();
            let digit = ((exponent[window >> 4] >> ((window & 15) << 2)) & 15) as usize;
            if digit != 0 {
                result = result.mul(powers[digit]);
            }
        }
        result
    }

    const fn pow_fixed_window4_const(self, exponent: [u64; LIMBS], exponent_bits: usize) -> Self {
        let mut powers = [Self::ONE; 16];
        let mut index = 1;
        while index < powers.len() {
            powers[index] = powers[index - 1].mul_const(self);
            index += 1;
        }

        let mut result = Self::ONE;
        let mut window = exponent_bits.div_ceil(4);
        while window != 0 {
            window -= 1;
            result = result
                .square_const()
                .square_const()
                .square_const()
                .square_const();
            let digit = ((exponent[window >> 4] >> ((window & 15) << 2)) & 15) as usize;
            if digit != 0 {
                result = result.mul_const(powers[digit]);
            }
        }
        result
    }

    pub(crate) fn is_odd(&self) -> Choice {
        Choice::from_u8_lsb(self.0[0] as u8)
    }

    pub(crate) fn ct_eq(&self, rhs: &Self) -> Choice {
        let mut different = 0_u64;
        let mut index = 0;
        while index < LIMBS {
            different |= self.0[index] ^ rhs.0[index];
            index += 1;
        }
        different.ct_eq(&0)
    }

    pub(crate) fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    pub(crate) fn conditional_select(when_false: Self, when_true: Self, choice: Choice) -> Self {
        let mut selected = when_false.0;
        selected.ct_assign(&when_true.0, choice);
        Self(selected)
    }
}

impl Default for Fe301 {
    fn default() -> Self {
        Self::ZERO
    }
}

const fn add_limbs(left: [u64; LIMBS], right: [u64; LIMBS]) -> ([u64; LIMBS], u64) {
    let mut output = [0_u64; LIMBS];
    let mut carry = 0_u64;
    let mut index = 0;
    while index < LIMBS {
        let accumulator = left[index] as u128 + right[index] as u128 + carry as u128;
        output[index] = accumulator as u64;
        carry = (accumulator >> 64) as u64;
        index += 1;
    }
    (output, carry)
}

const fn subtract_limbs(left: [u64; LIMBS], right: [u64; LIMBS]) -> ([u64; LIMBS], u64) {
    let mut output = [0_u64; LIMBS];
    let mut borrow = 0_u64;
    let mut index = 0;
    while index < LIMBS {
        let (difference, next_borrow) = sub_with_borrow(left[index], right[index], borrow);
        output[index] = difference;
        borrow = next_borrow;
        index += 1;
    }
    (output, borrow)
}

/// Subtract two words and an incoming 0/1 borrow using only wrapping and
/// bitwise operations.
///
/// This is the unsigned less-than identity from Hacker's Delight, section
/// 2-12.  It avoids the compiler-dependent lowering of `overflowing_sub`
/// which produced secret-tainted control flow under the pinned Rust codegen.
#[inline(always)]
const fn sub_with_borrow(left: u64, right: u64, borrow: u64) -> (u64, u64) {
    let first = left.wrapping_sub(right);
    let first_borrow = (((!left & right) | ((!left | right) & first)) >> 63) & 1;
    let difference = first.wrapping_sub(borrow);
    let second_borrow = (((!first & borrow) | ((!first | borrow) & difference)) >> 63) & 1;
    (difference, first_borrow | second_borrow)
}

const fn conditional_subtract_modulus_const(input: [u64; LIMBS]) -> [u64; LIMBS] {
    let (reduced, borrow) = subtract_limbs(input, MODULUS);
    let mask = 0_u64.wrapping_sub(borrow ^ 1);
    let mut output = [0_u64; LIMBS];
    let mut index = 0;
    while index < LIMBS {
        output[index] = (input[index] & !mask) | (reduced[index] & mask);
        index += 1;
    }
    output
}

#[inline(always)]
fn conditional_subtract_modulus_ct(input: [u64; LIMBS]) -> [u64; LIMBS] {
    let (reduced, borrow) = subtract_limbs(input, MODULUS);
    let mut output = input;
    output.ct_assign(&reduced, Choice::from_u8_lsb((borrow as u8) ^ 1));
    output
}

const fn multiply_wide(left: [u64; LIMBS], right: [u64; LIMBS]) -> [u64; LIMBS * 2] {
    let mut output = [0_u64; LIMBS * 2];
    let mut left_index = 0;
    while left_index < LIMBS {
        let mut carry = 0_u64;
        let mut right_index = 0;
        while right_index < LIMBS {
            let output_index = left_index + right_index;
            let accumulator = left[left_index] as u128 * right[right_index] as u128
                + output[output_index] as u128
                + carry as u128;
            output[output_index] = accumulator as u64;
            carry = (accumulator >> 64) as u64;
            right_index += 1;
        }
        output[left_index + LIMBS] = carry;
        left_index += 1;
    }
    output
}

const fn multiply_five_by_u32(value: [u64; LIMBS], multiplier: u32) -> [u64; LIMBS + 1] {
    let mut output = [0_u64; LIMBS + 1];
    let mut carry = 0_u64;
    let mut index = 0;
    while index < LIMBS {
        let product = value[index] as u128 * multiplier as u128 + carry as u128;
        output[index] = product as u64;
        carry = (product >> 64) as u64;
        index += 1;
    }
    output[LIMBS] = carry;
    output
}

const fn square_wide(value: [u64; LIMBS]) -> [u64; LIMBS * 2] {
    let mut output = [0_u64; LIMBS * 2];
    let mut accumulator = [0_u64; 3];

    accumulate_product(&mut accumulator, value[0], value[0]);
    emit_square_column(&mut output, 0, &mut accumulator);
    accumulate_double_product(&mut accumulator, value[0], value[1]);
    emit_square_column(&mut output, 1, &mut accumulator);
    accumulate_double_product(&mut accumulator, value[0], value[2]);
    accumulate_product(&mut accumulator, value[1], value[1]);
    emit_square_column(&mut output, 2, &mut accumulator);
    accumulate_double_product(&mut accumulator, value[0], value[3]);
    accumulate_double_product(&mut accumulator, value[1], value[2]);
    emit_square_column(&mut output, 3, &mut accumulator);
    accumulate_double_product(&mut accumulator, value[0], value[4]);
    accumulate_double_product(&mut accumulator, value[1], value[3]);
    accumulate_product(&mut accumulator, value[2], value[2]);
    emit_square_column(&mut output, 4, &mut accumulator);
    accumulate_double_product(&mut accumulator, value[1], value[4]);
    accumulate_double_product(&mut accumulator, value[2], value[3]);
    emit_square_column(&mut output, 5, &mut accumulator);
    accumulate_double_product(&mut accumulator, value[2], value[4]);
    accumulate_product(&mut accumulator, value[3], value[3]);
    emit_square_column(&mut output, 6, &mut accumulator);
    accumulate_double_product(&mut accumulator, value[3], value[4]);
    emit_square_column(&mut output, 7, &mut accumulator);
    accumulate_product(&mut accumulator, value[4], value[4]);
    emit_square_column(&mut output, 8, &mut accumulator);
    output[9] = accumulator[0];
    output
}

const fn accumulate_product(accumulator: &mut [u64; 3], left: u64, right: u64) {
    let product = left as u128 * right as u128;
    accumulate_192(accumulator, product as u64, (product >> 64) as u64, 0);
}

const fn accumulate_double_product(accumulator: &mut [u64; 3], left: u64, right: u64) {
    let product = left as u128 * right as u128;
    let low = product as u64;
    let high = (product >> 64) as u64;
    accumulate_192(accumulator, low << 1, (high << 1) | (low >> 63), high >> 63);
}

const fn accumulate_192(accumulator: &mut [u64; 3], low: u64, middle: u64, high: u64) {
    let sum = accumulator[0] as u128 + low as u128;
    accumulator[0] = sum as u64;
    let sum = accumulator[1] as u128 + middle as u128 + (sum >> 64);
    accumulator[1] = sum as u64;
    accumulator[2] = accumulator[2]
        .wrapping_add(high)
        .wrapping_add((sum >> 64) as u64);
}

const fn emit_square_column(
    output: &mut [u64; LIMBS * 2],
    column: usize,
    accumulator: &mut [u64; 3],
) {
    output[column] = accumulator[0];
    accumulator[0] = accumulator[1];
    accumulator[1] = accumulator[2];
    accumulator[2] = 0;
}

fn reduce_wide(product: [u64; LIMBS * 2]) -> [u64; LIMBS] {
    conditional_subtract_modulus_ct(reduce_wide_unreduced(product))
}

const fn reduce_wide_const(product: [u64; LIMBS * 2]) -> [u64; LIMBS] {
    conditional_subtract_modulus_const(reduce_wide_unreduced(product))
}

/// Fold a wide product into five limbs using the additive identity
/// `2^301 = 2^99 - 947 (mod p)`.
///
/// The subtrahend-free formulation multiplies the high part by the positive
/// two-limb constant `K = 2^99 - 947` and accumulates it onto the low part,
/// so every carry chain is an addition with a fixed trip count. For a
/// reachable wide product below `2^602` the first fold fits seven limbs, the
/// remaining high part fits two limbs, and the final value stays below `2p`,
/// so the callers' single conditional subtraction suffices.
const fn reduce_wide_unreduced(product: [u64; LIMBS * 2]) -> [u64; LIMBS] {
    let low = [
        product[0],
        product[1],
        product[2],
        product[3],
        product[4] & TOP_MASK,
    ];
    let high = [
        (product[4] >> TOP_BITS) | (product[5] << (64 - TOP_BITS)),
        (product[5] >> TOP_BITS) | (product[6] << (64 - TOP_BITS)),
        (product[6] >> TOP_BITS) | (product[7] << (64 - TOP_BITS)),
        (product[7] >> TOP_BITS) | (product[8] << (64 - TOP_BITS)),
        (product[8] >> TOP_BITS) | (product[9] << (64 - TOP_BITS)),
    ];
    let mut first_fold = [0_u64; 7];
    accumulate_fold(&low, &high, &mut first_fold);

    let second_low = [
        first_fold[0],
        first_fold[1],
        first_fold[2],
        first_fold[3],
        first_fold[4] & TOP_MASK,
    ];
    let second_high = [
        (first_fold[4] >> TOP_BITS) | (first_fold[5] << (64 - TOP_BITS)),
        (first_fold[5] >> TOP_BITS) | (first_fold[6] << (64 - TOP_BITS)),
    ];
    let mut reduced = [0_u64; 5];
    accumulate_fold(&second_low, &second_high, &mut reduced);
    reduced
}

/// Low limb of the positive fold constant `K = 2^99 - 947`.
const FOLD_CONSTANT_LOW: u64 = 0_u64.wrapping_sub(FOLD_SUBTRAHEND);
/// High limb of the positive fold constant `K = 2^99 - 947`.
const FOLD_CONSTANT_HIGH: u64 = (1_u64 << 35) - 1;

/// Compute `output = low + high * K` with addition-only carry chains.
///
/// Every loop bound is a compile-time constant and every carry is propagated
/// through the full remaining width, so the instruction schedule is
/// independent of the operand values.
const fn accumulate_fold<const HIGH: usize, const OUTPUT: usize>(
    low: &[u64],
    high: &[u64; HIGH],
    output: &mut [u64; OUTPUT],
) {
    let mut index = 0;
    while index < low.len() {
        output[index] = low[index];
        index += 1;
    }
    let mut carry = 0_u64;
    index = 0;
    while index < HIGH {
        let accumulator =
            output[index] as u128 + high[index] as u128 * FOLD_CONSTANT_LOW as u128 + carry as u128;
        output[index] = accumulator as u64;
        carry = (accumulator >> 64) as u64;
        index += 1;
    }
    while index < OUTPUT {
        let accumulator = output[index] as u128 + carry as u128;
        output[index] = accumulator as u64;
        carry = (accumulator >> 64) as u64;
        index += 1;
    }
    carry = 0;
    index = 0;
    while index < HIGH {
        let accumulator = output[index + 1] as u128
            + high[index] as u128 * FOLD_CONSTANT_HIGH as u128
            + carry as u128;
        output[index + 1] = accumulator as u64;
        carry = (accumulator >> 64) as u64;
        index += 1;
    }
    index += 1;
    while index < OUTPUT {
        let accumulator = output[index] as u128 + carry as u128;
        output[index] = accumulator as u64;
        carry = (accumulator >> 64) as u64;
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldElement as Oracle;

    fn oracle(value: Fe301) -> Oracle {
        Oracle::from_canonical_bytes(&value.to_canonical_bytes())
            .expect_copied("Fe301 values are canonical")
    }

    fn generated(state: &mut u64) -> Fe301 {
        let mut words = [0_u64; LIMBS];
        let mut index = 0;
        while index < LIMBS {
            *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut value = *state;
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            words[index] = value ^ (value >> 31);
            index += 1;
        }
        words[4] &= TOP_MASK;
        Fe301(conditional_subtract_modulus_const(words))
    }

    fn split_mix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = *state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    /// Reduce an arbitrary wide value with the independent Montgomery oracle:
    /// `value = low + high * 2^301` with both halves fed through the oracle.
    fn oracle_reduce_wide(wide: [u64; LIMBS * 2]) -> [u8; FIELD_BYTES] {
        fn oracle_from_limbs(limbs: [u64; LIMBS]) -> Oracle {
            // A raw half is below 2^301 < 2p; one conditional subtraction of
            // the long-standing helper canonicalizes it for the oracle.
            let canonical = conditional_subtract_modulus_const(limbs);
            let mut bytes = [0_u8; FIELD_BYTES];
            let mut index = 0;
            while index < FIELD_BYTES {
                bytes[index] = (canonical[index / 8] >> ((index % 8) * 8)) as u8;
                index += 1;
            }
            Oracle::from_canonical_bytes(&bytes).expect_copied("canonicalized halves are below p")
        }
        let low = [wide[0], wide[1], wide[2], wide[3], wide[4] & TOP_MASK];
        let high = [
            (wide[4] >> TOP_BITS) | (wide[5] << (64 - TOP_BITS)),
            (wide[5] >> TOP_BITS) | (wide[6] << (64 - TOP_BITS)),
            (wide[6] >> TOP_BITS) | (wide[7] << (64 - TOP_BITS)),
            (wide[7] >> TOP_BITS) | (wide[8] << (64 - TOP_BITS)),
            (wide[8] >> TOP_BITS) | (wide[9] << (64 - TOP_BITS)),
        ];
        // 2^301 mod p as a canonical oracle constant: 2^99 - 947.
        let mut shift_bytes = [0_u8; FIELD_BYTES];
        shift_bytes[0] = 0x4d;
        shift_bytes[1] = 0xfc;
        let mut index = 2;
        while index < 12 {
            shift_bytes[index] = 0xff;
            index += 1;
        }
        shift_bytes[12] = 0x07;
        let shift =
            Oracle::from_canonical_bytes(&shift_bytes).expect_copied("2^99 - 947 is canonical");
        let expected = oracle_from_limbs(low).add(oracle_from_limbs(high).mul(shift));
        expected.to_canonical_bytes()
    }

    #[test]
    fn wide_reduction_matches_the_montgomery_oracle_on_boundaries() {
        let top_limb_mask = (1_u64 << 26) - 1;
        let mut state = 0x4d41_4346_4f4c_4432_u64;
        let mut case_index = 0_usize;
        // 602 one-hot patterns, named boundaries, and randomized wide values,
        // all limited to the reachable product range below 2^602.
        while case_index < 50_000 {
            let mut wide = [0_u64; LIMBS * 2];
            if case_index < 602 {
                wide[case_index / 64] = 1_u64 << (case_index % 64);
            } else if case_index == 602 {
                // all reachable bits set
                let mut limb = 0;
                while limb < LIMBS * 2 {
                    wide[limb] = u64::MAX;
                    limb += 1;
                }
                wide[LIMBS * 2 - 1] = top_limb_mask;
            } else if case_index == 603 {
                wide[LIMBS * 2 - 1] = top_limb_mask;
            } else if case_index == 604 {
                // alternating bit pattern across the full reachable width
                let mut limb = 0;
                while limb < LIMBS * 2 {
                    wide[limb] = 0xaaaa_aaaa_aaaa_aaaa;
                    limb += 1;
                }
                wide[LIMBS * 2 - 1] &= top_limb_mask;
            } else if case_index == 605 {
                let mut limb = 0;
                while limb < LIMBS * 2 {
                    wide[limb] = 0x5555_5555_5555_5555;
                    limb += 1;
                }
                wide[LIMBS * 2 - 1] &= top_limb_mask;
            } else {
                let mut limb = 0;
                while limb < LIMBS * 2 {
                    wide[limb] = split_mix(&mut state);
                    limb += 1;
                }
                wide[LIMBS * 2 - 1] &= top_limb_mask;
            }
            let reduced = conditional_subtract_modulus_const(reduce_wide_unreduced(wide));
            let via_new = Fe301(reduced).to_canonical_bytes();
            assert_eq!(
                via_new,
                oracle_reduce_wide(wide),
                "wide reduction diverged from the Montgomery oracle"
            );
            case_index += 1;
        }
    }

    #[test]
    fn specialized_arithmetic_matches_the_montgomery_oracle() {
        let mut state = 0x4645_3330_312d_5231_u64;
        for _ in 0..10_000 {
            let left = generated(&mut state);
            let right = generated(&mut state);
            let left_oracle = oracle(left);
            let right_oracle = oracle(right);
            assert_eq!(
                left.add(right).to_canonical_bytes(),
                left_oracle.add(right_oracle).to_canonical_bytes()
            );
            assert_eq!(
                left.sub(right).to_canonical_bytes(),
                left_oracle.sub(right_oracle).to_canonical_bytes()
            );
            assert_eq!(
                left.mul(right).to_canonical_bytes(),
                left_oracle.mul(right_oracle).to_canonical_bytes()
            );
            assert_eq!(
                left.square().to_canonical_bytes(),
                left_oracle.square().to_canonical_bytes()
            );
            for multiplier in [0_u32, 1, 301, 2_086_388_329, u32::MAX] {
                assert_eq!(
                    left.mul_small(multiplier).to_canonical_bytes(),
                    left_oracle
                        .mul(Oracle::from_u64(multiplier as u64))
                        .to_canonical_bytes()
                );
            }
        }
    }

    #[test]
    fn specialized_inversion_and_square_root_retain_oracle_results() {
        let mut state = 0x4645_3330_312d_494e_u64;
        for _ in 0..128 {
            let value = generated(&mut state);
            let inverse = value.invert();
            assert_eq!(inverse.is_some().to_bool(), !value.is_zero().to_bool());
            if inverse.is_some().to_bool() {
                assert!(
                    value
                        .mul(inverse.to_inner_unchecked())
                        .ct_eq(&Fe301::ONE)
                        .to_bool()
                );
            }
            let square = value.square();
            let root = square.sqrt().expect_copied("a square has a root");
            assert!(root.square().ct_eq(&square).to_bool());

            let mut denominator = generated(&mut state);
            if denominator.is_zero().to_bool() {
                denominator = Fe301::ONE;
            }

            let ratio = Fe301::sqrt_ratio(value, denominator);
            let oracle_ratio = Oracle::sqrt_ratio(oracle(value), oracle(denominator));
            assert_eq!(
                ratio.is_some().to_bool(),
                oracle_ratio.is_some().to_bool(),
                "the optimized ratio decoder must retain oracle acceptance"
            );
            if ratio.is_some().to_bool() {
                assert_eq!(
                    ratio.to_inner_unchecked().to_canonical_bytes(),
                    oracle_ratio.to_inner_unchecked().to_canonical_bytes(),
                    "the optimized fixed exponent must retain the oracle root"
                );
            }

            let numerator = square.mul(denominator);
            let ratio_root = Fe301::sqrt_ratio(numerator, denominator)
                .expect_copied("a constructed square ratio has a root");
            assert!(
                ratio_root
                    .square()
                    .mul(denominator)
                    .ct_eq(&numerator)
                    .to_bool()
            );
        }

        assert!(
            Fe301::sqrt_ratio(Fe301::ONE, Fe301::ZERO)
                .is_none()
                .to_bool()
        );
        assert!(
            Fe301::sqrt_ratio(Fe301::ZERO, Fe301::ZERO)
                .is_none()
                .to_bool()
        );
    }
}
