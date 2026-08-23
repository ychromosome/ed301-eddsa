//! Loadable OpenSSL provider for the experimental `Ed301-EdDSA-draft-00`
//! signature primitive.
//!
//! The provider is signature-only.  It exposes raw EVP key management and
//! deterministic one-shot 76-byte signatures for the manifest-bound Rust
//! input crate `ed301-eddsa` and, for an isolated proof only, an explicitly
//! ephemeral, host-audited, nonregistrable test identifier profile.
//! It makes no production, constant-time, standards or release claim, and it
//! deliberately does not reuse the historical `Ed301-Sig-v1` identity or
//! semantics.

#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(panic = "unwind"))]
compile_error!("the Ed301 OpenSSL provider requires panic=unwind at its FFI boundary");

use core::ffi::{c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

mod sig_ffi;

#[cfg(test)]
mod policy_tests;
#[cfg(test)]
#[path = "policy_vectors_data.rs"]
mod policy_vectors_data;

unsafe extern "C" {
    fn ed301_eddsa_draft00_shim_init(
        handle: *const c_void,
        input_dispatch: *const c_void,
        output_dispatch: *mut *const c_void,
        provider_context: *mut *mut c_void,
        signature_rust_api: *const c_void,
    ) -> c_int;
}

/// OpenSSL provider entry point.
///
/// # Safety
///
/// All pointers must follow the `OSSL_provider_init` contract from the
/// OpenSSL headers used to build this module.  The function prevents Rust
/// panics from unwinding across the C ABI boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OSSL_provider_init(
    handle: *const c_void,
    input_dispatch: *const c_void,
    output_dispatch: *mut *const c_void,
    provider_context: *mut *mut c_void,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null()
            || input_dispatch.is_null()
            || output_dispatch.is_null()
            || provider_context.is_null()
        {
            return 0;
        }

        // SAFETY: Null pointers were rejected above.  OpenSSL owns all pointed
        // objects and the C shim validates the same provider-init contract.
        unsafe {
            ed301_eddsa_draft00_shim_init(
                handle,
                input_dispatch,
                output_dispatch,
                provider_context,
                (&raw const sig_ffi::SIGNATURE_RUST_API).cast(),
            )
        }
    }))
    .unwrap_or(0)
}
