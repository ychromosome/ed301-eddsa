//! Test-only safe wrappers around Valgrind Memcheck client requests.
//!
//! This crate is intentionally outside the production workspace. Its tiny
//! unsafe FFI boundary changes only Valgrind's shadow metadata; it never
//! mutates the referenced Rust value.

#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::{ffi::c_void, mem::size_of_val};

unsafe extern "C" {
    fn ed301_vg_running_on_valgrind() -> u32;
    fn ed301_vg_make_mem_undefined(address: *mut c_void, length: usize);
    fn ed301_vg_make_mem_defined(address: *mut c_void, length: usize);
    fn ed301_vg_get_vbits(address: *const c_void, vbits: *mut u8, length: usize) -> u32;
    fn ed301_vg_count_errors() -> usize;
}

/// Return Valgrind's nesting depth, or zero outside Valgrind.
#[must_use]
pub fn running_on_valgrind() -> u32 {
    // SAFETY: The C wrapper performs a Valgrind client request without
    // dereferencing application memory.
    unsafe { ed301_vg_running_on_valgrind() }
}

/// Mark an initialized value secret in Memcheck's shadow state.
pub fn mark_undefined<T: ?Sized>(value: &mut T) {
    // SAFETY: `value` is live for `size_of_val(value)` bytes. The C wrapper
    // changes only Valgrind metadata and does not read or write the value.
    unsafe {
        ed301_vg_make_mem_undefined(
            core::ptr::from_mut(value).cast::<c_void>(),
            size_of_val(value),
        );
    }
}

/// Mark a reviewed public value or predicate defined in Memcheck's shadow state.
pub fn make_defined<T: ?Sized>(value: &mut T) {
    // SAFETY: `value` is live for `size_of_val(value)` bytes. The C wrapper
    // changes only Valgrind metadata and does not read or write the value.
    unsafe {
        ed301_vg_make_mem_defined(
            core::ptr::from_mut(value).cast::<c_void>(),
            size_of_val(value),
        );
    }
}

/// Copy one shadow-validity byte per application byte into `vbits`.
///
/// A zero bit is defined and a one bit is undefined. Returns Valgrind's
/// client-request status; one denotes success.
pub fn get_vbits(value: &[u8], vbits: &mut [u8]) -> u32 {
    if value.len() != vbits.len() {
        return 3;
    }
    // SAFETY: Both slices are live and have the same length. Memcheck writes
    // only the shadow-byte result to `vbits`.
    unsafe {
        ed301_vg_get_vbits(
            value.as_ptr().cast::<c_void>(),
            vbits.as_mut_ptr(),
            value.len(),
        )
    }
}

/// Return the number of Memcheck errors observed in the current process.
#[must_use]
pub fn error_count() -> usize {
    // SAFETY: The C wrapper performs a metadata-only client request.
    unsafe { ed301_vg_count_errors() }
}
