//! Direct per-row point and scalar policy assertions (FBL-08).
//!
//! Every declared row of the frozen edge-case matrices is asserted directly
//! at the core's public parse API:
//! `validate_public_key` for the public-key policy of each point row,
//! `Signature::from_bytes` for the commitment policy of each point row and
//! the syntax policy of each scalar row.  The provider passes these byte
//! strings through unmodified (covered by the C acceptance harnesses), so
//! the core's parse behaviour is the provider's parse behaviour.
//!
//! Mutation control: with `ED301D00_POLICY_MUTATE=1` in the environment
//! every expected result is inverted and this test MUST fail; the matrix
//! runner asserts that failure.

use ed301_eddsa::{Signature, validate_public_key};

use crate::policy_vectors_data::{POINT_POLICY, SCALAR_POLICY, VALID_R, VALID_S};

fn mutate() -> bool {
    std::env::var("ED301D00_POLICY_MUTATE").is_ok_and(|value| value == "1")
}

#[test]
fn point_rows_match_declared_policies() {
    let invert = mutate();
    for (id, encoding, public_ok, commitment_ok) in POINT_POLICY {
        let expect_public = *public_ok ^ invert;
        let expect_commitment = *commitment_ok ^ invert;
        assert_eq!(
            validate_public_key(encoding),
            expect_public,
            "public-key policy for point row {id}"
        );
        let mut signature = encoding.to_vec();
        signature.extend_from_slice(VALID_S);
        assert_eq!(
            Signature::from_bytes(&signature).is_ok(),
            expect_commitment,
            "commitment policy for point row {id}"
        );
    }
}

#[test]
fn scalar_rows_match_declared_syntax() {
    let invert = mutate();
    for (id, encoding, syntax_ok) in SCALAR_POLICY {
        let expect = *syntax_ok ^ invert;
        let mut signature = VALID_R.to_vec();
        signature.extend_from_slice(encoding);
        assert_eq!(
            Signature::from_bytes(&signature).is_ok(),
            expect,
            "canonical-scalar syntax for scalar row {id}"
        );
    }
}
