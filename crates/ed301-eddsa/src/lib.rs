//! Rust implementation candidate for `Ed301-EdDSA-draft-00`.
//!
//! The crate implements only the context-free, one-shot byte contract bound
//! by the Round-4 source manifest. It is review software, not a production or
//! standards-conformance claim.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod edwards;
mod field;
pub mod parameters;
mod scalar;
mod secret;
mod secret_taint;
pub mod signature;
mod signature_hash;

pub use signature::{
    Signature, SignatureError, SigningKey, VerifyingKey, sign, validate_public_key, verify,
};

#[cfg(test)]
mod vector_tests;
