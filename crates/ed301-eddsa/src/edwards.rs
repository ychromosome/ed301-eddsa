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
    field_5x64::Fe301 as FieldElement,
    parameters::{FIELD_BITS, FIELD_BYTES},
    scalar::Scalar,
    secret_taint::declassify,
};

const EDWARDS_A: u32 = 2_086_388_329;
const EDWARDS_D: u32 = 301;
const BASEPOINT_TABLE_ROWS: usize = FIELD_BYTES;
const BASEPOINT_TABLE_WIDTH: usize = 8;
const BASEPOINT_TABLE_SIZE: usize = BASEPOINT_TABLE_ROWS * BASEPOINT_TABLE_WIDTH;
const RADIX16_DIGITS: usize = FIELD_BYTES * 2;
const BASEPOINT_WNAF_WIDTH: u32 = 8;
const POINT_WNAF_WIDTH: u32 = 8;
const BASEPOINT_ODD_MULTIPLES: usize = 1 << (BASEPOINT_WNAF_WIDTH - 2);
const POINT_ODD_MULTIPLES: usize = 1 << (POINT_WNAF_WIDTH - 2);

pub(crate) type VartimePointTable = [AffineNielsPoint; POINT_ODD_MULTIPLES];

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

// Width-8 wNAF recoding of the fixed public prime order, from most to least
// significant position. Exactly 18 nonzero odd digits; the leading digit is
// `+1` at bit 299, so subgroup validation initializes its accumulator with
// the point itself and then performs exactly 299 doublings and 17 signed
// mixed additions from the shared odd-multiples table. The schedule is a
// public constant and never depends on point data.
const PRIME_ORDER_WNAF8_DESC: [(u16, i8); 18] = [
    (299, 1),
    (149, 1),
    (141, -73),
    (131, -103),
    (119, 17),
    (111, 37),
    (99, 19),
    (91, 9),
    (82, -1),
    (73, -91),
    (65, 25),
    (57, -109),
    (45, 23),
    (37, 29),
    (28, 29),
    (17, 95),
    (9, 75),
    (0, 3),
];

// Set bits of the fixed public prime order, from most to least significant.
// The top bit is consumed by initializing the accumulator with `P`; the
// remaining schedule therefore performs exactly 299 doublings and 63
// additions instead of the generic add-always ladder's 301 additions.
const PRIME_ORDER_SET_BITS_DESC: [u16; 64] = [
    299, 148, 146, 145, 143, 142, 140, 139, 138, 135, 134, 131, 123, 119, 116, 113, 111, 103, 100,
    99, 94, 90, 89, 88, 87, 86, 85, 84, 83, 81, 80, 78, 75, 73, 69, 68, 64, 61, 58, 57, 49, 47, 46,
    45, 41, 40, 39, 37, 32, 31, 30, 28, 23, 21, 20, 19, 18, 17, 15, 12, 10, 9, 1, 0,
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

/// Affine cached point for the mixed-addition formulas used by fixed-base and
/// public verification tables.  `xy = x + y` and `dt = d*x*y` remove one
/// field multiplication and the small-constant multiply from every table add.
#[derive(Clone, Copy)]
pub(crate) struct AffineNielsPoint {
    x: FieldElement,
    y: FieldElement,
    xy: FieldElement,
    dt: FieldElement,
}

impl AffineNielsPoint {
    const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        xy: FieldElement::ONE,
        dt: FieldElement::ZERO,
    };

    fn from_projective(point: EdwardsPoint, inverse_z: FieldElement) -> Self {
        let x = point.x.mul(inverse_z);
        let y = point.y.mul(inverse_z);
        Self {
            x,
            y,
            xy: x.add(y),
            dt: x.mul(y).mul_small(EDWARDS_D),
        }
    }

    const fn from_projective_const(point: EdwardsPoint, inverse_z: FieldElement) -> Self {
        let x = point.x.mul_const(inverse_z);
        let y = point.y.mul_const(inverse_z);
        Self {
            x,
            y,
            xy: x.add_const(y),
            dt: x.mul_const(y).mul_small_const(EDWARDS_D),
        }
    }

    fn negate(self) -> Self {
        let x = self.x.neg();
        Self {
            x,
            y: self.y,
            xy: x.add(self.y),
            dt: self.dt.neg(),
        }
    }

    fn conditional_select(when_false: Self, when_true: Self, choice: Choice) -> Self {
        Self {
            x: FieldElement::conditional_select(when_false.x, when_true.x, choice),
            y: FieldElement::conditional_select(when_false.y, when_true.y, choice),
            xy: FieldElement::conditional_select(when_false.xy, when_true.xy, choice),
            dt: FieldElement::conditional_select(when_false.dt, when_true.dt, choice),
        }
    }
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
        let dt = self.t.mul_small(EDWARDS_D).mul(rhs.t);
        let zz = self.z.mul(rhs.z);
        let cross = self.x.add(self.y).mul(rhs.x.add(rhs.y)).sub(xx).sub(yy);
        let difference = zz.sub(dt);
        let sum = zz.add(dt);
        let twisted = yy.sub(xx.mul_small(EDWARDS_A));

        Self {
            x: cross.mul(difference),
            y: sum.mul(twisted),
            z: difference.mul(sum),
            t: cross.mul(twisted),
        }
    }

    /// Add an affine precomputed point using the complete mixed formula.
    pub(crate) fn add_affine(self, rhs: AffineNielsPoint) -> Self {
        let xx = self.x.mul(rhs.x);
        let yy = self.y.mul(rhs.y);
        let dt = self.t.mul(rhs.dt);
        let cross = self.x.add(self.y).mul(rhs.xy).sub(xx).sub(yy);
        let difference = self.z.sub(dt);
        let sum = self.z.add(dt);
        let twisted = yy.sub(xx.mul_small(EDWARDS_A));

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
        let zz = self.z.square();
        let two_zz = zz.add(zz);
        let twisted_xx = xx.mul_small(EDWARDS_A);
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

    const fn add_const(self, rhs: Self) -> Self {
        let xx = self.x.mul_const(rhs.x);
        let yy = self.y.mul_const(rhs.y);
        let dt = self.t.mul_small_const(EDWARDS_D).mul_const(rhs.t);
        let zz = self.z.mul_const(rhs.z);
        let cross = self
            .x
            .add_const(self.y)
            .mul_const(rhs.x.add_const(rhs.y))
            .sub_const(xx)
            .sub_const(yy);
        let difference = zz.sub_const(dt);
        let sum = zz.add_const(dt);
        let twisted = yy.sub_const(xx.mul_small_const(EDWARDS_A));

        Self {
            x: cross.mul_const(difference),
            y: sum.mul_const(twisted),
            z: difference.mul_const(sum),
            t: cross.mul_const(twisted),
        }
    }

    const fn double_const(self) -> Self {
        let xx = self.x.square_const();
        let yy = self.y.square_const();
        let zz = self.z.square_const();
        let two_zz = zz.add_const(zz);
        let twisted_xx = xx.mul_small_const(EDWARDS_A);
        let cross = self
            .x
            .add_const(self.y)
            .square_const()
            .sub_const(xx)
            .sub_const(yy);
        let sum = twisted_xx.add_const(yy);
        let difference = sum.sub_const(two_zz);
        let twisted_difference = twisted_xx.sub_const(yy);

        Self {
            x: cross.mul_const(difference),
            y: sum.mul_const(twisted_difference),
            z: difference.mul_const(sum),
            t: cross.mul_const(twisted_difference),
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

    /// Multiply the fixed base point by a canonical secret scalar.
    ///
    /// This is the standard EdDSA signed-radix-16 shape: 38 rows contain
    /// `[1..8] * [256^i]B`; odd digits are accumulated, shifted by four
    /// doublings, and followed by the even digits.  Every secret digit scans
    /// all eight entries and uses conditional selection.
    pub(crate) fn scalar_mul_base(scalar: &Scalar) -> Self {
        let mut encoded = crate::secret::secret([0_u8; FIELD_BYTES]);
        scalar.write_canonical_bytes(&mut encoded);
        Self::scalar_mul_base_encoded(&encoded)
    }

    /// Multiply the fixed base point by the exact pruned secret encoding.
    pub(crate) fn scalar_mul_base_pruned(scalar: &[u8; FIELD_BYTES]) -> Self {
        Self::scalar_mul_base_encoded(scalar)
    }

    fn scalar_mul_base_encoded(scalar: &[u8; FIELD_BYTES]) -> Self {
        let digits = signed_radix16(scalar);
        let mut result = Self::IDENTITY;
        let mut digit_index = 1;

        while digit_index < RADIX16_DIGITS {
            result = result.add_affine(select_basepoint(digit_index >> 1, digits[digit_index]));
            digit_index += 2;
        }

        result = result.double().double().double().double();
        digit_index = 0;
        while digit_index < RADIX16_DIGITS {
            result = result.add_affine(select_basepoint(digit_index >> 1, digits[digit_index]));
            digit_index += 2;
        }
        result
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

    /// Return whether `[L]P` is the identity using the fixed public wNAF
    /// schedule and the caller-supplied odd-multiples table of this point.
    ///
    /// The digit positions, digit values, loop counts and table indices come
    /// only from [`PRIME_ORDER_WNAF8_DESC`], a public constant, so the
    /// control flow is input-independent even though the point additions use
    /// the variable-time mixed-addition path. Callers must pass the table
    /// built from this same point.
    pub(crate) fn is_prime_subgroup_with_table(&self, table: &VartimePointTable) -> Choice {
        let (leading_position, leading_digit) = PRIME_ORDER_WNAF8_DESC[0];
        debug_assert_eq!(leading_digit, 1);
        let mut accumulator = *self;
        let mut current_bit = leading_position as usize;
        let mut digit_index = 1;

        while digit_index < PRIME_ORDER_WNAF8_DESC.len() {
            let (position, digit) = PRIME_ORDER_WNAF8_DESC[digit_index];
            while current_bit > position as usize {
                accumulator = accumulator.double();
                current_bit -= 1;
            }
            accumulator = vartime_add_signed(accumulator, digit, table, false);
            digit_index += 1;
        }
        accumulator.is_identity()
    }

    /// Multiply by the fixed public prime order using its sparse bit pattern.
    ///
    /// The loop counts and additions depend only on
    /// [`PRIME_ORDER_SET_BITS_DESC`], never on point data. This is used for
    /// strict public-key subgroup validation and remains safe when the point
    /// was derived from a secret scalar because its control flow is entirely
    /// input-independent.
    fn scalar_mul_prime_order_sparse(self) -> Self {
        let mut accumulator = self;
        let mut current_bit = PRIME_ORDER_SET_BITS_DESC[0] as usize;
        let mut set_bit_index = 1;

        while set_bit_index < PRIME_ORDER_SET_BITS_DESC.len() {
            let set_bit = PRIME_ORDER_SET_BITS_DESC[set_bit_index] as usize;
            while current_bit > set_bit {
                accumulator = accumulator.double();
                current_bit -= 1;
            }
            accumulator = accumulator.add(self);
            set_bit_index += 1;
        }
        accumulator
    }

    /// Compute `[base_scalar]B - [point_scalar]point` for public verification.
    ///
    /// Both scalar recodings, branches and table indices are variable-time.
    /// Signature responses, challenges and verification keys are public, so
    /// this follows the same separation used by Ed25519/Ed448 implementations:
    /// secret signing stays on the constant-time fixed-base path while public
    /// verification uses a Straus/wNAF multiscalar multiplication.
    pub(crate) fn vartime_double_scalar_mul_basepoint(
        base_scalar: &Scalar,
        point_scalar: &Scalar,
        point_table: &VartimePointTable,
    ) -> Self {
        let base_digits = base_scalar.vartime_wnaf(BASEPOINT_WNAF_WIDTH);
        let point_digits = point_scalar.vartime_wnaf(POINT_WNAF_WIDTH);
        let mut top = FIELD_BITS;

        while top != 0 && base_digits[top] == 0 && point_digits[top] == 0 {
            top -= 1;
        }

        let mut result = Self::IDENTITY;
        loop {
            result = result.double();
            result = vartime_add_signed(result, base_digits[top], &BASEPOINT_ODD_TABLE, false);
            result = vartime_add_signed(result, point_digits[top], point_table, true);
            if top == 0 {
                break;
            }
            top -= 1;
        }
        result
    }

    /// Precompute public odd multiples for repeated verification.
    ///
    /// This table contains no secret material and its construction is
    /// deliberately variable-time.  A validated public key owns it so the
    /// per-signature path follows OpenSSL's prepared-key pattern.
    pub(crate) fn prepare_vartime_table(self) -> VartimePointTable {
        build_vartime_odd_point_table(self)
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

    /// Canonicalize a secret-derived public point without decoding its wire
    /// encoding again.
    ///
    /// Only affine coordinates that are uniquely determined by the completed
    /// public encoding cross the declassification boundary. The secret-tainted
    /// projective `Z` coordinate is deliberately discarded rather than being
    /// treated as public.
    pub(crate) fn canonical_public_artifact(
        self,
    ) -> Result<([u8; FIELD_BYTES], Self), EdwardsPointError> {
        let (mut encoded, affine_x, affine_y) = self.encode_components(true)?;
        let mut canonical_point = Self::from_affine(affine_x, affine_y);
        declassify(&mut encoded);
        declassify(&mut canonical_point);
        Ok((encoded, canonical_point))
    }

    #[inline(always)]
    fn encode_inner(
        self,
        declassify_fault_predicates: bool,
    ) -> Result<[u8; FIELD_BYTES], EdwardsPointError> {
        let (encoded, _, _) = self.encode_components(declassify_fault_predicates)?;
        Ok(encoded)
    }

    fn encode_components(
        self,
        declassify_fault_predicates: bool,
    ) -> Result<([u8; FIELD_BYTES], FieldElement, FieldElement), EdwardsPointError> {
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
        Ok((encoded, affine_x, affine_y))
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
        let numerator = FieldElement::ONE.sub(yy);
        let denominator = FieldElement::from_u64(EDWARDS_A as u64).sub(yy.mul_small(EDWARDS_D));
        let root = FieldElement::sqrt_ratio(numerator, denominator)
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
        self.scalar_mul_prime_order_sparse().is_identity()
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
        let left = xx.mul_small(EDWARDS_A).mul(zz).add(yy.mul(zz));
        let right = zz.square().add(xx.mul_small(EDWARDS_D).mul(yy));

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

const fn build_basepoint_table() -> [AffineNielsPoint; BASEPOINT_TABLE_SIZE] {
    let mut projective = [EdwardsPoint::IDENTITY; BASEPOINT_TABLE_SIZE];
    let mut row_base = EdwardsPoint::BASEPOINT;
    let mut row = 0;

    while row < BASEPOINT_TABLE_ROWS {
        projective[row * BASEPOINT_TABLE_WIDTH] = row_base;
        let mut entry = 1;
        while entry < BASEPOINT_TABLE_WIDTH {
            projective[row * BASEPOINT_TABLE_WIDTH + entry] =
                projective[row * BASEPOINT_TABLE_WIDTH + entry - 1].add_const(row_base);
            entry += 1;
        }
        let mut doubling = 0;
        while doubling < 8 {
            row_base = row_base.double_const();
            doubling += 1;
        }
        row += 1;
    }
    batch_normalize_const(projective)
}

static BASEPOINT_TABLE: [AffineNielsPoint; BASEPOINT_TABLE_SIZE] = build_basepoint_table();

const fn build_basepoint_odd_table() -> [AffineNielsPoint; BASEPOINT_ODD_MULTIPLES] {
    let mut projective = [EdwardsPoint::IDENTITY; BASEPOINT_ODD_MULTIPLES];
    let step = EdwardsPoint::BASEPOINT.double_const();
    projective[0] = EdwardsPoint::BASEPOINT;
    let mut index = 1;
    while index < BASEPOINT_ODD_MULTIPLES {
        projective[index] = projective[index - 1].add_const(step);
        index += 1;
    }
    batch_normalize_const(projective)
}

static BASEPOINT_ODD_TABLE: [AffineNielsPoint; BASEPOINT_ODD_MULTIPLES] =
    build_basepoint_odd_table();

fn build_vartime_odd_point_table(point: EdwardsPoint) -> VartimePointTable {
    let mut projective = [EdwardsPoint::IDENTITY; POINT_ODD_MULTIPLES];
    let step = point.double();
    projective[0] = point;
    let mut index = 1;
    while index < POINT_ODD_MULTIPLES {
        projective[index] = projective[index - 1].add(step);
        index += 1;
    }
    batch_normalize(projective)
}

const fn batch_normalize_const<const N: usize>(points: [EdwardsPoint; N]) -> [AffineNielsPoint; N] {
    let mut prefixes = [FieldElement::ONE; N];
    let mut product = FieldElement::ONE;
    let mut index = 0;
    while index < N {
        prefixes[index] = product;
        product = product.mul_const(points[index].z);
        index += 1;
    }
    let mut inverse = product.invert_const_nonzero();
    let mut output = [AffineNielsPoint::IDENTITY; N];
    index = N;
    while index != 0 {
        index -= 1;
        let inverse_z = inverse.mul_const(prefixes[index]);
        inverse = inverse.mul_const(points[index].z);
        output[index] = AffineNielsPoint::from_projective_const(points[index], inverse_z);
    }
    output
}

fn batch_normalize<const N: usize>(points: [EdwardsPoint; N]) -> [AffineNielsPoint; N] {
    let mut prefixes = [FieldElement::ONE; N];
    let mut product = FieldElement::ONE;
    let mut index = 0;
    while index < N {
        prefixes[index] = product;
        product = product.mul(points[index].z);
        index += 1;
    }
    let mut inverse = product.invert().to_inner_unchecked();
    let mut output = [AffineNielsPoint::IDENTITY; N];
    index = N;
    while index != 0 {
        index -= 1;
        let inverse_z = inverse.mul(prefixes[index]);
        inverse = inverse.mul(points[index].z);
        output[index] = AffineNielsPoint::from_projective(points[index], inverse_z);
    }
    output
}

fn vartime_add_signed<const N: usize>(
    accumulator: EdwardsPoint,
    digit: i8,
    table: &[AffineNielsPoint; N],
    negate_scalar: bool,
) -> EdwardsPoint {
    if digit == 0 {
        return accumulator;
    }
    let magnitude = digit.unsigned_abs() as usize;
    let mut addend = table[magnitude >> 1];
    if (digit < 0) ^ negate_scalar {
        addend = addend.negate();
    }
    accumulator.add_affine(addend)
}

fn signed_radix16(scalar: &[u8; FIELD_BYTES]) -> crate::secret::Secret<[i8; RADIX16_DIGITS]> {
    let mut digits = crate::secret::secret([0_i8; RADIX16_DIGITS]);
    let mut index = 0;
    while index < RADIX16_DIGITS {
        digits[index] = ((scalar[index >> 1] >> ((index & 1) << 2)) & 0x0f) as i8;
        index += 1;
    }

    index = 0;
    while index + 1 < RADIX16_DIGITS {
        let carry = digits[index].wrapping_add(8) >> 4;
        digits[index] = digits[index].wrapping_sub(carry.wrapping_shl(4));
        digits[index + 1] = digits[index + 1].wrapping_add(carry);
        index += 1;
    }
    digits
}

fn select_basepoint(row: usize, digit: i8) -> AffineNielsPoint {
    let signed = digit as i16;
    let sign_mask = signed >> 15;
    let magnitude = (signed ^ sign_mask).wrapping_sub(sign_mask) as u8;
    let negative = Choice::from_u8_lsb((digit as u8) >> 7);
    let mut selected = AffineNielsPoint::IDENTITY;
    let mut entry = 0;

    while entry < BASEPOINT_TABLE_WIDTH {
        selected = AffineNielsPoint::conditional_select(
            selected,
            BASEPOINT_TABLE[row * BASEPOINT_TABLE_WIDTH + entry],
            Choice::from_u8_eq(magnitude, (entry + 1) as u8),
        );
        entry += 1;
    }
    AffineNielsPoint::conditional_select(selected, selected.negate(), negative)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{decode_hex_array, splitmix64};

    const SCALAR_12345: [u8; FIELD_BYTES] = decode_hex_array(
        b"3930000000000000000000000000000000000000000000000000000000000000000000000000",
    );
    const MULTIPLE_12345_ENCODING: [u8; FIELD_BYTES] = decode_hex_array(
        b"9ffa3fbe41c0ee7def76269467f7702cbe30ed930021f90ee241b5b1bdc34a6af128f51db512",
    );
    const DRAFT00_PRUNED_SECRET: [u8; FIELD_BYTES] = decode_hex_array(
        b"686d13326b81a70d3bb299eb137d475b59ddee671f92cdd334883fe6d784fc03813c2542a119",
    );
    const DRAFT00_PUBLIC_ENCODING: [u8; FIELD_BYTES] = decode_hex_array(
        b"8cad07b4f9a308523a8df9bee22a721b8ff5e597c1ce47e39df67f97a475fd018013fc188890",
    );
    const DRAFT00_NONCE_SCALAR: [u8; FIELD_BYTES] = decode_hex_array(
        b"a3c7355a9c1ea903bc4fef22588ce6b75c292ccea514dbe689bacf7e3b3ca64449c9983cbd05",
    );
    const DRAFT00_COMMITMENT_ENCODING: [u8; FIELD_BYTES] = decode_hex_array(
        b"2964a4e22d5ed6e41ad5d5bbfdf4d518bb067b8982f3f8f5900d074a6bee97567b9581033694",
    );
    const FIELD_MODULUS_ENCODING: [u8; FIELD_BYTES] = decode_hex_array(
        b"b30300000000000000000000f8ffffffffffffffffffffffffffffffffffffffffffffffff1f",
    );
    const ORDER_TWO_ENCODING: [u8; FIELD_BYTES] = decode_hex_array(
        b"b20300000000000000000000f8ffffffffffffffffffffffffffffffffffffffffffffffff1f",
    );
    const ORDER_FOUR_ENCODING: [u8; FIELD_BYTES] = decode_hex_array(
        b"0000000000000000000000000000000000000000000000000000000000000000000000000080",
    );
    const MIXED_ORDER_TWO_ENCODING: [u8; FIELD_BYTES] = decode_hex_array(
        b"480cc08aa5f37f9ac317c0308a9008280cb84e6d6ddb5398aadd8cbe61930d375775fd2c7707",
    );
    const MIXED_ORDER_FOUR_ENCODING: [u8; FIELD_BYTES] = decode_hex_array(
        b"3373a6039b6583c450910497e99e855dd7e20e877bc221b580d663671adb3f49ffd30524ed96",
    );

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
    fn fixed_base_radix16_matches_the_generic_constant_time_ladder() {
        for scalar_bytes in [[0_u8; FIELD_BYTES], SCALAR_12345, DRAFT00_NONCE_SCALAR] {
            let scalar = scalar(&scalar_bytes);
            let expected = EdwardsPoint::BASEPOINT.scalar_mul(&scalar);
            let actual = EdwardsPoint::scalar_mul_base(&scalar);
            assert!(actual.ct_eq(&expected).to_bool());
        }

        let expected = EdwardsPoint::BASEPOINT.scalar_mul_pruned(&DRAFT00_PRUNED_SECRET);
        let actual = EdwardsPoint::scalar_mul_base_pruned(&DRAFT00_PRUNED_SECRET);
        assert!(actual.ct_eq(&expected).to_bool());
        assert_eq!(
            actual.encode(),
            Ok(DRAFT00_PUBLIC_ENCODING),
            "the fixed-base path must retain the draft-00 wire bytes"
        );
    }

    #[test]
    fn public_straus_and_affine_tables_match_complete_group_arithmetic() {
        let public = EdwardsPoint::decode_strict_subgroup(&DRAFT00_PUBLIC_ENCODING)
            .expect("the draft public key is a strict subgroup point");
        let table = public.prepare_vartime_table();
        let scalars = [
            Scalar::ZERO,
            Scalar::ONE,
            scalar(&SCALAR_12345),
            scalar(&DRAFT00_NONCE_SCALAR),
        ];

        for base_scalar in &scalars {
            for point_scalar in &scalars {
                let expected = EdwardsPoint::BASEPOINT
                    .scalar_mul(base_scalar)
                    .add(public.scalar_mul(point_scalar).negate());
                let actual = EdwardsPoint::vartime_double_scalar_mul_basepoint(
                    base_scalar,
                    point_scalar,
                    &table,
                );
                assert!(
                    actual.ct_eq(&expected).to_bool(),
                    "public wNAF/Straus arithmetic must retain the complete-formula result"
                );
            }
        }

        let mut odd_multiple = public;
        let step = public.double();
        for affine in table {
            let accumulator = EdwardsPoint::BASEPOINT.add(odd_multiple);
            assert!(
                EdwardsPoint::BASEPOINT
                    .add_affine(affine)
                    .ct_eq(&accumulator)
                    .to_bool(),
                "batch-normalized affine entries must retain their odd multiple"
            );
            odd_multiple = odd_multiple.add(step);
        }
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
    fn fixed_wnaf_subgroup_schedule_matches_the_sparse_reference() {
        // The hardcoded schedule must reconstruct the prime order exactly.
        let mut reconstructed = [0_i128; 5];
        for (position, digit) in PRIME_ORDER_WNAF8_DESC {
            let limb = position as usize / 64;
            let shift = position as usize % 64;
            reconstructed[limb] += (digit as i128) << shift;
        }
        let mut carried = [0_u64; 5];
        let mut carry = 0_i128;
        for (index, value) in reconstructed.into_iter().enumerate() {
            let total = value + carry;
            carried[index] = total as u64;
            carry = total >> 64;
        }
        assert_eq!(carry, 0);
        let mut expected = [0_u64; 5];
        for (index, byte) in PRIME_ORDER_BYTES.iter().enumerate() {
            expected[index / 8] |= (*byte as u64) << ((index % 8) * 8);
        }
        assert_eq!(carried, expected);

        // Torsion representatives with canonical encodings.
        let identity = {
            let mut encoding = [0_u8; FIELD_BYTES];
            encoding[0] = 1;
            EdwardsPoint::decode(&encoding).expect("identity decodes")
        };
        let order_two = EdwardsPoint::decode(&ORDER_TWO_ENCODING).expect("order-2 decodes");
        let order_four = EdwardsPoint::decode(&ORDER_FOUR_ENCODING).expect("order-4 decodes");
        let mixed_two =
            EdwardsPoint::decode(&MIXED_ORDER_TWO_ENCODING).expect("mixed order-2 decodes");
        let mixed_four =
            EdwardsPoint::decode(&MIXED_ORDER_FOUR_ENCODING).expect("mixed order-4 decodes");
        let torsion = [identity, order_two, order_four, order_four.negate()];

        let mut state: u64 = 0x574e_4146_3853_4348;
        let mut checked = 0_usize;
        let mut candidates = [EdwardsPoint::IDENTITY; 32];
        candidates[0] = identity;
        candidates[1] = order_two;
        candidates[2] = order_four;
        candidates[3] = order_four.negate();
        candidates[4] = mixed_two;
        candidates[5] = mixed_four;
        candidates[6] = EdwardsPoint::BASEPOINT;
        let mut index = 7;
        while index < candidates.len() {
            let mut scalar_bytes = [0_u8; FIELD_BYTES];
            for byte in scalar_bytes.iter_mut() {
                *byte = splitmix64(&mut state) as u8;
            }
            scalar_bytes[FIELD_BYTES - 1] &= 0x03;
            let multiple = EdwardsPoint::BASEPOINT.scalar_mul_encoded(&scalar_bytes);
            // Shift through the complete four-element torsion group.
            candidates[index] = multiple.add(torsion[index % torsion.len()]);
            index += 1;
        }

        for point in candidates {
            // Table construction must be total for every decodable point.
            let table = point.prepare_vartime_table();
            let fast = point.is_prime_subgroup_with_table(&table).to_bool();
            let reference = point.is_prime_subgroup().to_bool();
            assert_eq!(
                fast, reference,
                "fixed wNAF subgroup predicate diverged from the sparse reference"
            );
            checked += 1;
        }
        assert_eq!(checked, 32);
    }

    #[test]
    fn sparse_prime_order_schedule_matches_the_generic_ladder() {
        let mut reconstructed = [0_u8; FIELD_BYTES];
        for bit in PRIME_ORDER_SET_BITS_DESC {
            reconstructed[bit as usize >> 3] |= 1 << (bit as usize & 7);
        }
        assert_eq!(reconstructed, PRIME_ORDER_BYTES);

        let mut point = EdwardsPoint::IDENTITY;
        for _ in 0..2_048 {
            let sparse = point.scalar_mul_prime_order_sparse();
            let generic = point.scalar_mul_encoded(&PRIME_ORDER_BYTES);
            assert!(
                sparse.ct_eq(&generic).to_bool(),
                "the fixed sparse order schedule must match the generic ladder"
            );
            point = point.add(EdwardsPoint::BASEPOINT);
        }

        for encoded in [
            ORDER_TWO_ENCODING,
            ORDER_FOUR_ENCODING,
            MIXED_ORDER_TWO_ENCODING,
            MIXED_ORDER_FOUR_ENCODING,
        ] {
            let point = EdwardsPoint::decode(&encoded).expect("the torsion case must decode");
            assert!(
                point
                    .scalar_mul_prime_order_sparse()
                    .ct_eq(&point.scalar_mul_encoded(&PRIME_ORDER_BYTES))
                    .to_bool(),
                "the sparse schedule must retain torsion behavior"
            );
        }
    }

    #[test]
    fn canonical_public_artifact_matches_strict_decode() {
        let mut point = EdwardsPoint::BASEPOINT;
        for _ in 0..128 {
            let (encoded, canonical) = point
                .canonical_public_artifact()
                .expect("a valid point must canonicalize");
            let decoded = EdwardsPoint::decode(&encoded).expect("the artifact must decode");
            assert!(canonical.ct_eq(&decoded).to_bool());
            assert_eq!(canonical.encode(), Ok(encoded));
            point = point.add(EdwardsPoint::BASEPOINT);
        }
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
