//! Rust-owned key and one-shot signature contexts for `Ed301-EdDSA-draft-00`.
//!
//! Adapted from the historical provider's `ed301_sig_ffi.rs` dispatch shape
//! (see the result provenance map).  Differences bound by this experiment:
//! the cryptographic core is the frozen `ed301-eddsa` crate in this
//! repository,
//! there is no context, digest, prehash, streaming or randomized-signing
//! surface at all, and the historical `Ed301-Sig-v1` semantics are not
//! reachable from this module.
//!
//! All object pointers in the callback table are opaque outside Rust.  Every
//! callback catches unwinding so a Rust panic can never cross the C ABI
//! boundary.

use core::ffi::{c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

use crypto_bigint::CtEq;
use ed301_eddsa::{
    SigningKey, VerifyingKey,
    parameters::{PUBLIC_KEY_BYTES, SEED_BYTES, SIGNATURE_BYTES},
    validate_public_key, verify,
};
use zeroize::Zeroize;

/// Function table consumed by the provider's C shim.
#[repr(C)]
pub(crate) struct SignatureRustApi {
    pub(crate) abi_version: u32,
    pub(crate) struct_size: usize,
    pub(crate) seed_bytes: usize,
    pub(crate) public_key_bytes: usize,
    pub(crate) signature_bytes: usize,
    pub(crate) key_new: extern "C" fn() -> *mut c_void,
    pub(crate) key_free: unsafe extern "C" fn(*mut c_void),
    pub(crate) key_import:
        unsafe extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize) -> c_int,
    pub(crate) key_set_encoded_public: unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int,
    pub(crate) key_from_seed: unsafe extern "C" fn(*const u8, usize) -> *mut c_void,
    pub(crate) key_duplicate: unsafe extern "C" fn(*const c_void, c_int, c_int) -> *mut c_void,
    pub(crate) key_has: unsafe extern "C" fn(*const c_void, c_int, c_int) -> c_int,
    pub(crate) key_validate: unsafe extern "C" fn(*const c_void, c_int, c_int) -> c_int,
    pub(crate) key_match: unsafe extern "C" fn(*const c_void, *const c_void, c_int, c_int) -> c_int,
    pub(crate) key_get_private: unsafe extern "C" fn(*const c_void, *mut u8, usize) -> c_int,
    pub(crate) key_get_public: unsafe extern "C" fn(*const c_void, *mut u8, usize) -> c_int,
    pub(crate) signature_new: extern "C" fn() -> *mut c_void,
    pub(crate) signature_free: unsafe extern "C" fn(*mut c_void),
    pub(crate) signature_duplicate: unsafe extern "C" fn(*const c_void) -> *mut c_void,
    pub(crate) signature_reset: unsafe extern "C" fn(*mut c_void),
    pub(crate) signature_sign_init: unsafe extern "C" fn(*mut c_void, *const c_void) -> c_int,
    pub(crate) signature_verify_init: unsafe extern "C" fn(*mut c_void, *const c_void) -> c_int,
    pub(crate) signature_sign:
        unsafe extern "C" fn(*const c_void, *const u8, usize, *mut u8, usize) -> c_int,
    pub(crate) signature_verify:
        unsafe extern "C" fn(*const c_void, *const u8, usize, *const u8, usize) -> c_int,
    pub(crate) cleanse: unsafe extern "C" fn(*mut u8, usize),
}

/// `Ed301-EdDSA-draft-00` callback table for the C provider shim.
pub(crate) static SIGNATURE_RUST_API: SignatureRustApi = SignatureRustApi {
    abi_version: 2,
    struct_size: core::mem::size_of::<SignatureRustApi>(),
    seed_bytes: SEED_BYTES,
    public_key_bytes: PUBLIC_KEY_BYTES,
    signature_bytes: SIGNATURE_BYTES,
    key_new,
    key_free,
    key_import,
    key_set_encoded_public,
    key_from_seed,
    key_duplicate,
    key_has,
    key_validate,
    key_match,
    key_get_private,
    key_get_public,
    signature_new,
    signature_free,
    signature_duplicate,
    signature_reset,
    signature_sign_init,
    signature_verify_init,
    signature_sign,
    signature_verify,
    cleanse,
};

#[derive(Clone)]
struct SecretSeed([u8; SEED_BYTES]);

impl Zeroize for SecretSeed {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretSeed {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Default)]
pub(crate) struct DraftKey {
    private: Option<SecretSeed>,
    public: Option<[u8; PUBLIC_KEY_BYTES]>,
}

#[derive(Clone, Default)]
enum SignatureOperation {
    #[default]
    Uninitialized,
    Sign(SecretSeed),
    Verify([u8; PUBLIC_KEY_BYTES]),
}

#[derive(Clone, Default)]
pub(crate) struct DraftSignatureContext {
    operation: SignatureOperation,
}

/// Test-only fail-closed diagnostic, compiled in ONLY under the
/// `test-failpoint` feature (separately named test artifact): while the
/// environment variable names a callback, every invocation of that callback
/// panics, so the acceptance matrix can demonstrate that a Rust panic never
/// unwinds across the C ABI boundary.  The ordinary module is built without
/// this feature and contains neither the hook nor the variable-name string.
#[cfg(feature = "test-failpoint")]
fn hit_panic_failpoint(name: &str) {
    if let Ok(value) = std::env::var("ED301_EDDSA_DRAFT00_PANIC_FAILPOINT")
        && value == name
    {
        panic!("injected test panic in {name}");
    }
}

#[cfg(not(feature = "test-failpoint"))]
#[inline(always)]
fn hit_panic_failpoint(_name: &str) {}

/// Test-only allocation-failure selector, compiled in ONLY under the
/// `test-failpoint` feature (same separately named test artifact as the
/// panic failpoint): while the environment variable names one of the five
/// allocating callbacks (`key_new`, `key_from_seed`, `key_duplicate`,
/// `signature_new`, `signature_duplicate`), that callback reports
/// allocation failure by returning null instead of panicking; clearing the
/// variable restores normal allocation.  The ordinary module is built
/// without this feature and contains neither the hook nor the
/// variable-name string.
#[cfg(feature = "test-failpoint")]
fn hit_alloc_failpoint(name: &str) -> bool {
    matches!(
        std::env::var("ED301_EDDSA_DRAFT00_ALLOC_FAILPOINT"),
        Ok(value) if value == name
    )
}

#[cfg(not(feature = "test-failpoint"))]
#[inline(always)]
fn hit_alloc_failpoint(_name: &str) -> bool {
    false
}

/// Fallibly move `value` onto the heap.
///
/// Returns `None` instead of aborting the process when the global allocator
/// cannot satisfy the request; the moved value is dropped in that case, so
/// secret material still runs its zeroizing destructor.  Zero-sized types
/// never allocate and use a dangling, aligned pointer exactly as `Box::new`
/// does, so the returned box drops normally.
fn try_box<T>(value: T) -> Option<Box<T>> {
    let layout = std::alloc::Layout::new::<T>();
    if layout.size() == 0 {
        let pointer = core::ptr::NonNull::<T>::dangling().as_ptr();
        // SAFETY: For a zero-sized type any aligned dangling pointer is a
        // valid place to write the value.
        unsafe { core::ptr::write(pointer, value) };
        // SAFETY: `Box::from_raw` accepts a dangling aligned pointer for a
        // zero-sized type and takes ownership of the written value.
        return Some(unsafe { Box::from_raw(pointer) });
    }
    // SAFETY: `layout` has non-zero size.
    let pointer = unsafe { std::alloc::alloc(layout) }.cast::<T>();
    if pointer.is_null() {
        drop(value);
        return None;
    }
    // SAFETY: `pointer` is non-null and was allocated with the layout of
    // `T`, so it is properly aligned, writable and uniquely owned here.
    unsafe { core::ptr::write(pointer, value) };
    // SAFETY: `pointer` now owns an initialized `T` obtained from the
    // global allocator, matching the `Box::from_raw` contract.
    Some(unsafe { Box::from_raw(pointer) })
}

/// Fallible heap allocation for one named externally reachable call site.
fn try_box_at<T>(site: &str, value: T) -> Option<Box<T>> {
    if hit_alloc_failpoint(site) {
        drop(value);
        return None;
    }
    try_box(value)
}

fn ffi_int(operation: impl FnOnce() -> c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(0)
}

fn ffi_pointer(operation: impl FnOnce() -> *mut c_void) -> *mut c_void {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(core::ptr::null_mut())
}

/// Allocate an empty key object.
pub(crate) extern "C" fn key_new() -> *mut c_void {
    ffi_pointer(|| {
        hit_panic_failpoint("key_new");
        match try_box_at("key_new", DraftKey::default()) {
            Some(key) => Box::into_raw(key).cast(),
            None => core::ptr::null_mut(),
        }
    })
}

/// Free a Rust-owned key object.
pub(crate) unsafe extern "C" fn key_free(key: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !key.is_null() {
            // SAFETY: The shim returns every Rust-owned key pointer at most once.
            drop(unsafe { Box::from_raw(key.cast::<DraftKey>()) });
        }
    }));
}

/// Atomically import an optional seed and/or public key.
pub(crate) unsafe extern "C" fn key_import(
    key: *mut c_void,
    private: *const u8,
    private_len: usize,
    public: *const u8,
    public_len: usize,
) -> c_int {
    ffi_int(|| {
        hit_panic_failpoint("key_import");
        // SAFETY: The shim passes a live Rust-owned key object.
        let Some(key) = (unsafe { key.cast::<DraftKey>().as_mut() }) else {
            return 0;
        };

        // SAFETY: Present parameter storage is readable for this call.
        let Some(raw_private) = (unsafe { read_optional_secret_seed(private, private_len) }) else {
            return 0;
        };
        // SAFETY: Present parameter storage is readable for this call.
        let Some(raw_public) =
            (unsafe { read_optional_exact::<PUBLIC_KEY_BYTES>(public, public_len) })
        else {
            return 0;
        };

        if raw_private.is_none() && raw_public.is_none() {
            return 0;
        }

        let derived_public = match raw_private.as_ref() {
            Some(seed) => match derive_public(&seed.0) {
                Some(derived) => Some(derived),
                None => return 0,
            },
            None => None,
        };

        if let Some(public) = raw_public.as_ref() {
            if !validate_public_key(public) {
                return 0;
            }
            if let Some(derived) = derived_public.as_ref()
                && !bytes_equal(derived, public)
            {
                return 0;
            }
        }

        let public = derived_public.or(raw_public);
        *key = DraftKey {
            private: raw_private,
            public,
        };
        1
    })
}

/// Set a strict public encoding without replacing an existing different key.
pub(crate) unsafe extern "C" fn key_set_encoded_public(
    key: *mut c_void,
    public: *const u8,
    public_len: usize,
) -> c_int {
    ffi_int(|| {
        // SAFETY: The shim passes a live Rust-owned key object.
        let Some(key) = (unsafe { key.cast::<DraftKey>().as_mut() }) else {
            return 0;
        };
        // SAFETY: Parameter storage is readable for this call.
        let Some(Some(public)) =
            (unsafe { read_optional_exact::<PUBLIC_KEY_BYTES>(public, public_len) })
        else {
            return 0;
        };
        if !validate_public_key(&public) {
            return 0;
        }
        if let Some(existing) = key.public.as_ref()
            && !bytes_equal(existing, &public)
        {
            return 0;
        }
        if let Some(private) = key.private.as_ref() {
            let Some(derived) = derive_public(&private.0) else {
                return 0;
            };
            if !bytes_equal(&derived, &public) {
                return 0;
            }
        }

        key.public = Some(public);
        1
    })
}

/// Import a seed generated by the OpenSSL private RAND path and derive its
/// public key.
pub(crate) unsafe extern "C" fn key_from_seed(seed: *const u8, seed_len: usize) -> *mut c_void {
    ffi_pointer(|| {
        hit_panic_failpoint("key_generate");
        // SAFETY: The shim supplies exactly seed_len readable bytes for this
        // call and cleanses its temporary immediately afterwards.
        let Some(Some(seed)) = (unsafe { read_optional_secret_seed(seed, seed_len) }) else {
            return core::ptr::null_mut();
        };
        let Some(public) = derive_public(&seed.0) else {
            return core::ptr::null_mut();
        };

        let key = DraftKey {
            private: Some(seed),
            public: Some(public),
        };
        match try_box_at("key_generate", key) {
            Some(key) => Box::into_raw(key).cast(),
            None => core::ptr::null_mut(),
        }
    })
}

/// Duplicate selected key components.
pub(crate) unsafe extern "C" fn key_duplicate(
    source: *const c_void,
    include_private: c_int,
    include_public: c_int,
) -> *mut c_void {
    ffi_pointer(|| {
        // SAFETY: The shim passes a live Rust-owned key object.
        let Some(source) = (unsafe { source.cast::<DraftKey>().as_ref() }) else {
            return core::ptr::null_mut();
        };

        let private = (include_private != 0)
            .then(|| source.private.clone())
            .flatten();
        let public = (include_public != 0).then_some(source.public).flatten();

        match try_box_at("key_duplicate", DraftKey { private, public }) {
            Some(key) => Box::into_raw(key).cast(),
            None => core::ptr::null_mut(),
        }
    })
}

/// Test whether a key contains the selected components.
pub(crate) unsafe extern "C" fn key_has(
    key: *const c_void,
    require_private: c_int,
    require_public: c_int,
) -> c_int {
    ffi_int(|| {
        // SAFETY: The shim passes a live Rust-owned key object.
        let Some(key) = (unsafe { key.cast::<DraftKey>().as_ref() }) else {
            return 0;
        };
        if require_private != 0 && key.private.is_none()
            || require_public != 0 && key.public.is_none()
        {
            0
        } else {
            1
        }
    })
}

/// Validate selected key components and their relation when both are selected.
pub(crate) unsafe extern "C" fn key_validate(
    key: *const c_void,
    validate_private: c_int,
    validate_public: c_int,
) -> c_int {
    ffi_int(|| {
        // SAFETY: The shim passes a live Rust-owned key object.
        let Some(key) = (unsafe { key.cast::<DraftKey>().as_ref() }) else {
            return 0;
        };

        let derived = if validate_private != 0 {
            let Some(private) = key.private.as_ref() else {
                return 0;
            };
            match derive_public(&private.0) {
                Some(public) => Some(public),
                None => return 0,
            }
        } else {
            None
        };

        if validate_public != 0 {
            let Some(public) = key.public.as_ref() else {
                return 0;
            };
            if !validate_public_key(public) {
                return 0;
            }
            if let Some(derived) = derived.as_ref()
                && !bytes_equal(derived, public)
            {
                return 0;
            }
        }

        1
    })
}

/// Compare selected key components in constant time.
pub(crate) unsafe extern "C" fn key_match(
    first: *const c_void,
    second: *const c_void,
    match_private: c_int,
    match_public: c_int,
) -> c_int {
    ffi_int(|| {
        // SAFETY: The shim passes two live Rust-owned key objects.
        let Some(first) = (unsafe { first.cast::<DraftKey>().as_ref() }) else {
            return 0;
        };
        // SAFETY: Same contract as for first.
        let Some(second) = (unsafe { second.cast::<DraftKey>().as_ref() }) else {
            return 0;
        };

        if match_public != 0 {
            let (Some(first), Some(second)) = (first.public.as_ref(), second.public.as_ref())
            else {
                return 0;
            };
            if !bytes_equal(first, second) {
                return 0;
            }
        }
        if match_private != 0 {
            let (Some(first), Some(second)) = (first.private.as_ref(), second.private.as_ref())
            else {
                return 0;
            };
            if !bytes_equal(&first.0, &second.0) {
                return 0;
            }
        }

        1
    })
}

/// Copy a private seed into a shim-owned output buffer.
pub(crate) unsafe extern "C" fn key_get_private(
    key: *const c_void,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    ffi_int(|| {
        // SAFETY: The shim passes a live Rust-owned key object.
        let Some(key) = (unsafe { key.cast::<DraftKey>().as_ref() }) else {
            return 0;
        };
        let Some(private) = key.private.as_ref() else {
            return 0;
        };
        // SAFETY: The shim supplies output_len writable bytes.
        if unsafe { write_exact(output, output_len, &private.0) } {
            1
        } else {
            0
        }
    })
}

/// Copy a public key into a shim-owned output buffer.
pub(crate) unsafe extern "C" fn key_get_public(
    key: *const c_void,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    ffi_int(|| {
        // SAFETY: The shim passes a live Rust-owned key object.
        let Some(key) = (unsafe { key.cast::<DraftKey>().as_ref() }) else {
            return 0;
        };
        let Some(public) = key.public.as_ref() else {
            return 0;
        };
        // SAFETY: The shim supplies output_len writable bytes.
        if unsafe { write_exact(output, output_len, public) } {
            1
        } else {
            0
        }
    })
}

/// Allocate an uninitialized one-shot signature context.
pub(crate) extern "C" fn signature_new() -> *mut c_void {
    ffi_pointer(|| {
        hit_panic_failpoint("signature_new");
        match try_box_at("signature_new", DraftSignatureContext::default()) {
            Some(context) => Box::into_raw(context).cast(),
            None => core::ptr::null_mut(),
        }
    })
}

/// Free a Rust-owned one-shot signature context.
pub(crate) unsafe extern "C" fn signature_free(context: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !context.is_null() {
            // SAFETY: The shim returns every Rust-owned context pointer at most once.
            drop(unsafe { Box::from_raw(context.cast::<DraftSignatureContext>()) });
        }
    }));
}

/// Invalidate a signature context and drop any initialized secret operation.
pub(crate) unsafe extern "C" fn signature_reset(context: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The shim passes a live Rust-owned signature context.
        let Some(context) = (unsafe { context.cast::<DraftSignatureContext>().as_mut() }) else {
            return;
        };
        context.operation = SignatureOperation::Uninitialized;
    }));
}

/// Duplicate a signature context, including its initialized key snapshot.
pub(crate) unsafe extern "C" fn signature_duplicate(source: *const c_void) -> *mut c_void {
    ffi_pointer(|| {
        // SAFETY: The shim passes a live Rust-owned signature context.
        let Some(source) = (unsafe { source.cast::<DraftSignatureContext>().as_ref() }) else {
            return core::ptr::null_mut();
        };
        match try_box_at("signature_duplicate", source.clone()) {
            Some(context) => Box::into_raw(context).cast(),
            None => core::ptr::null_mut(),
        }
    })
}

/// Initialize a context for signing.
pub(crate) unsafe extern "C" fn signature_sign_init(
    context: *mut c_void,
    key: *const c_void,
) -> c_int {
    ffi_int(|| {
        // SAFETY: The shim passes live Rust-owned objects.
        let Some(context) = (unsafe { context.cast::<DraftSignatureContext>().as_mut() }) else {
            return 0;
        };
        context.operation = SignatureOperation::Uninitialized;
        hit_panic_failpoint("signature_sign_init");
        // SAFETY: Same contract as for context.
        let Some(key) = (unsafe { key.cast::<DraftKey>().as_ref() }) else {
            return 0;
        };
        let Some(seed) = key.private.as_ref() else {
            return 0;
        };
        let Some(derived) = derive_public(&seed.0) else {
            return 0;
        };
        if let Some(public) = key.public.as_ref()
            && !bytes_equal(&derived, public)
        {
            return 0;
        }

        context.operation = SignatureOperation::Sign(seed.clone());
        1
    })
}

/// Initialize a context for verification.
pub(crate) unsafe extern "C" fn signature_verify_init(
    context: *mut c_void,
    key: *const c_void,
) -> c_int {
    ffi_int(|| {
        // SAFETY: The shim passes live Rust-owned objects.
        let Some(context) = (unsafe { context.cast::<DraftSignatureContext>().as_mut() }) else {
            return 0;
        };
        context.operation = SignatureOperation::Uninitialized;
        hit_panic_failpoint("signature_verify_init");
        // SAFETY: Same contract as for context.
        let Some(key) = (unsafe { key.cast::<DraftKey>().as_ref() }) else {
            return 0;
        };
        let Some(public) = key.public else {
            return 0;
        };
        if !validate_public_key(&public) {
            return 0;
        }

        context.operation = SignatureOperation::Verify(public);
        1
    })
}

/// Sign one complete opaque message into a 76-byte output buffer.
pub(crate) unsafe extern "C" fn signature_sign(
    context: *const c_void,
    message: *const u8,
    message_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    ffi_int(|| {
        hit_panic_failpoint("signature_sign");
        // SAFETY: The shim passes a live Rust-owned signature context.
        let Some(context) = (unsafe { context.cast::<DraftSignatureContext>().as_ref() }) else {
            return 0;
        };
        let SignatureOperation::Sign(seed) = &context.operation else {
            return 0;
        };
        if output.is_null() || output_len < SIGNATURE_BYTES {
            return 0;
        }
        // SAFETY: The shim keeps message_len bytes readable for this call.
        let Some(message) = (unsafe { read_bytes(message, message_len) }) else {
            return 0;
        };
        let Ok(signing_key) = SigningKey::from_seed(&seed.0) else {
            return 0;
        };
        let Ok(signature) = signing_key.sign(message) else {
            return 0;
        };
        // SAFETY: output_len was checked above and the shim owns the buffer.
        if unsafe { write_exact(output, output_len, &signature.to_bytes()) } {
            1
        } else {
            0
        }
    })
}

/// Verify one complete opaque message and 76-byte signature.
pub(crate) unsafe extern "C" fn signature_verify(
    context: *const c_void,
    message: *const u8,
    message_len: usize,
    signature_value: *const u8,
    signature_len: usize,
) -> c_int {
    ffi_int(|| {
        hit_panic_failpoint("signature_verify");
        // SAFETY: The shim passes a live Rust-owned signature context.
        let Some(context) = (unsafe { context.cast::<DraftSignatureContext>().as_ref() }) else {
            return 0;
        };
        let SignatureOperation::Verify(public) = &context.operation else {
            return 0;
        };
        // SAFETY: The shim keeps both input buffers readable for this call.
        let Some(message) = (unsafe { read_bytes(message, message_len) }) else {
            return 0;
        };
        // SAFETY: Same contract as for message.
        let Some(signature_value) = (unsafe { read_bytes(signature_value, signature_len) }) else {
            return 0;
        };

        if verify(public, message, signature_value) {
            1
        } else {
            0
        }
    })
}

/// Zero a shim-owned temporary buffer.
pub(crate) unsafe extern "C" fn cleanse(buffer: *mut u8, length: usize) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if length != 0 && length <= isize::MAX as usize && !buffer.is_null() {
            // SAFETY: The shim supplies length writable bytes.
            unsafe { core::slice::from_raw_parts_mut(buffer, length) }.zeroize();
        }
    }));
}

fn derive_public(seed: &[u8; SEED_BYTES]) -> Option<[u8; PUBLIC_KEY_BYTES]> {
    let signing_key = SigningKey::from_seed(seed).ok()?;
    let verifying_key: VerifyingKey = signing_key.verifying_key().ok()?;
    Some(verifying_key.to_bytes())
}

unsafe fn read_optional_exact<const N: usize>(
    input: *const u8,
    input_len: usize,
) -> Option<Option<[u8; N]>> {
    if input.is_null() && input_len == 0 {
        return Some(None);
    }
    if input.is_null() || input_len != N {
        return None;
    }

    let mut output = [0_u8; N];
    // SAFETY: The caller guarantees input_len readable bytes at input.
    unsafe { core::ptr::copy_nonoverlapping(input, output.as_mut_ptr(), N) };
    Some(Some(output))
}

/// Copy an optional private seed directly into its non-`Copy`, zeroizing
/// owner.  No plain `[u8; SEED_BYTES]` temporary exists between the FFI
/// input and the retained key object.
unsafe fn read_optional_secret_seed(
    input: *const u8,
    input_len: usize,
) -> Option<Option<SecretSeed>> {
    if input.is_null() && input_len == 0 {
        return Some(None);
    }
    if input.is_null() || input_len != SEED_BYTES {
        return None;
    }

    let mut output = SecretSeed([0_u8; SEED_BYTES]);
    // SAFETY: The caller guarantees exactly SEED_BYTES readable bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(input, output.0.as_mut_ptr(), SEED_BYTES);
    }
    Some(Some(output))
}

unsafe fn read_bytes<'a>(input: *const u8, input_len: usize) -> Option<&'a [u8]> {
    if input_len == 0 {
        return Some(&[]);
    }
    if input.is_null() || input_len > isize::MAX as usize {
        return None;
    }
    // SAFETY: The caller guarantees input_len readable bytes at input.
    Some(unsafe { core::slice::from_raw_parts(input, input_len) })
}

unsafe fn write_exact<const N: usize>(output: *mut u8, output_len: usize, value: &[u8; N]) -> bool {
    if output.is_null() || output_len < N {
        return false;
    }
    // SAFETY: The caller guarantees output_len writable bytes at output.
    unsafe { core::ptr::copy_nonoverlapping(value.as_ptr(), output, N) };
    true
}

fn bytes_equal(first: &[u8; PUBLIC_KEY_BYTES], second: &[u8; PUBLIC_KEY_BYTES]) -> bool {
    first.ct_eq(second).to_bool()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ZST_DROPS: AtomicUsize = AtomicUsize::new(0);

    struct ZeroSized;

    impl Drop for ZeroSized {
        fn drop(&mut self) {
            ZST_DROPS.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn try_box_zero_sized_allocates_and_drops_once() {
        let before = ZST_DROPS.load(Ordering::SeqCst);
        let boxed = try_box(ZeroSized).expect("zero-sized try_box cannot fail");
        assert_eq!(ZST_DROPS.load(Ordering::SeqCst), before);
        drop(boxed);
        assert_eq!(ZST_DROPS.load(Ordering::SeqCst), before + 1);
    }

    #[test]
    fn try_box_round_trips_a_sized_value() {
        let boxed = try_box([0xA5_u8; 16]).expect("small allocation should succeed");
        assert_eq!(*boxed, [0xA5_u8; 16]);
    }

    #[test]
    fn read_bytes_rejects_oversized_length_without_dereference() {
        let byte = 0_u8;
        // SAFETY: The oversized length is rejected before any slice is
        // formed, so the single readable byte is never exceeded.
        let oversized = unsafe { read_bytes(&byte, (isize::MAX as usize) + 1) };
        assert!(oversized.is_none());
        // SAFETY: Same rejection applies to the maximum representable
        // length.
        let maximal = unsafe { read_bytes(&byte, usize::MAX) };
        assert!(maximal.is_none());
    }

    #[test]
    fn cleanse_ignores_null_zero_and_oversized_buffers() {
        // SAFETY: A null buffer must be ignored regardless of length.
        unsafe { cleanse(core::ptr::null_mut(), 8) };
        let mut byte = 0x5A_u8;
        // SAFETY: A zero length must never dereference the buffer.
        unsafe { cleanse(&mut byte, 0) };
        assert_eq!(byte, 0x5A);
        // SAFETY: The oversized length is rejected before any slice is
        // formed, so the single writable byte is never exceeded.
        unsafe { cleanse(&mut byte, (isize::MAX as usize) + 1) };
        assert_eq!(byte, 0x5A);
        // SAFETY: Exactly one writable byte is supplied.
        unsafe { cleanse(&mut byte, 1) };
        assert_eq!(byte, 0);
    }

    #[test]
    fn key_duplicate_honors_component_selection_exactly() {
        let source = DraftKey {
            private: Some(SecretSeed([0x11; SEED_BYTES])),
            public: Some([0x22; PUBLIC_KEY_BYTES]),
        };

        for (include_private, include_public) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
            let duplicate = unsafe {
                key_duplicate(
                    (&source as *const DraftKey).cast(),
                    include_private,
                    include_public,
                )
            };
            assert!(!duplicate.is_null());
            // SAFETY: key_duplicate returned this live Rust-owned object once.
            let duplicate = unsafe { Box::from_raw(duplicate.cast::<DraftKey>()) };
            assert_eq!(duplicate.private.is_some(), include_private != 0);
            assert_eq!(duplicate.public.is_some(), include_public != 0);
        }
    }

    #[test]
    fn failed_reinitialization_invalidates_old_operation() {
        let mut context = Box::new(DraftSignatureContext {
            operation: SignatureOperation::Sign(SecretSeed([0xA5; SEED_BYTES])),
        });
        let context_pointer = (&mut *context as *mut DraftSignatureContext).cast();
        assert_eq!(
            unsafe { signature_sign_init(context_pointer, core::ptr::null()) },
            0
        );
        assert!(matches!(
            context.operation,
            SignatureOperation::Uninitialized
        ));

        context.operation = SignatureOperation::Verify([0x5A; PUBLIC_KEY_BYTES]);
        assert_eq!(
            unsafe { signature_verify_init(context_pointer, core::ptr::null()) },
            0
        );
        assert!(matches!(
            context.operation,
            SignatureOperation::Uninitialized
        ));
    }

    #[test]
    fn signature_reset_invalidates_initialized_secret() {
        let mut context = Box::new(DraftSignatureContext {
            operation: SignatureOperation::Sign(SecretSeed([0x3C; SEED_BYTES])),
        });
        let context_pointer = (&mut *context as *mut DraftSignatureContext).cast();
        unsafe { signature_reset(context_pointer) };
        assert!(matches!(
            context.operation,
            SignatureOperation::Uninitialized
        ));
    }
}
