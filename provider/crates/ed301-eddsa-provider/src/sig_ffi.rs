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

use core::{
    ffi::{c_int, c_void},
    marker::PhantomData,
    ops::Deref,
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering, fence},
};
use std::panic::{AssertUnwindSafe, catch_unwind};

use crypto_bigint::CtEq;
use ed301_eddsa::{
    ExpandedSigningKey, SigningKey, VerifyingKey,
    parameters::{PUBLIC_KEY_BYTES, SEED_BYTES, SIGNATURE_BYTES},
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

struct PrivateKeyMaterial {
    seed: SecretSeed,
    expanded: Shared<ExpandedSigningKey>,
}

impl Clone for PrivateKeyMaterial {
    fn clone(&self) -> Self {
        Self {
            seed: SecretSeed(self.seed.0),
            expanded: self.expanded.clone(),
        }
    }
}

struct SharedInner<T> {
    references: AtomicUsize,
    value: T,
}

/// Fallibly allocated, immutable provider state shared by keys and signature
/// contexts. This is deliberately narrower than `Arc`: it supports only
/// construction, immutable dereference and cloning, so key replacement keeps
/// snapshot semantics without copying the roughly 10-KiB verification table.
struct Shared<T> {
    inner: NonNull<SharedInner<T>>,
    marker: PhantomData<SharedInner<T>>,
}

impl<T> Shared<T> {
    fn try_new_at(site: &str, value: T) -> Option<Self> {
        let inner = try_box_at(
            site,
            SharedInner {
                references: AtomicUsize::new(1),
                value,
            },
        )?;
        let inner = NonNull::from(Box::leak(inner));
        Some(Self {
            inner,
            marker: PhantomData,
        })
    }

    #[cfg(test)]
    fn reference_count(&self) -> usize {
        // SAFETY: Every live Shared owns one reference to the allocation.
        unsafe { self.inner.as_ref() }
            .references
            .load(Ordering::Relaxed)
    }
}

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        // SAFETY: `self` holds a live reference, so the allocation and counter
        // remain valid throughout this increment.
        let inner = unsafe { self.inner.as_ref() };
        let previous = inner.references.fetch_add(1, Ordering::Relaxed);
        if previous > isize::MAX as usize {
            std::process::abort();
        }
        Self {
            inner: self.inner,
            marker: PhantomData,
        }
    }
}

impl<T> Deref for Shared<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: A live Shared reference keeps the immutable value allocated.
        &unsafe { self.inner.as_ref() }.value
    }
}

impl<T> Drop for Shared<T> {
    fn drop(&mut self) {
        // SAFETY: `self` owns exactly one live reference to this allocation.
        let inner = unsafe { self.inner.as_ref() };
        if inner.references.fetch_sub(1, Ordering::Release) != 1 {
            return;
        }
        fence(Ordering::Acquire);
        // SAFETY: The final reference uniquely reclaims the original Box.
        drop(unsafe { Box::from_raw(self.inner.as_ptr()) });
    }
}

// SAFETY: Shared exposes immutable access only. Sending or sharing it is sound
// exactly when the stored value is both Send and Sync.
unsafe impl<T: Send + Sync> Send for Shared<T> {}
// SAFETY: Same invariant as the Send implementation above.
unsafe impl<T: Send + Sync> Sync for Shared<T> {}

#[derive(Clone, Default)]
pub(crate) struct DraftKey {
    private: Option<PrivateKeyMaterial>,
    public: Option<Shared<VerifyingKey>>,
}

#[derive(Clone, Default)]
enum SignatureOperation {
    #[default]
    Uninitialized,
    Sign(Shared<ExpandedSigningKey>),
    Verify(Shared<VerifyingKey>),
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
    match std::env::var("ED301_EDDSA_DRAFT00_PANIC_FAILPOINT") {
        Ok(value) if value == name => panic!("injected test panic in {name}"),
        _ => {}
    }
}

#[cfg(not(feature = "test-failpoint"))]
#[inline(always)]
fn hit_panic_failpoint(_name: &str) {}

/// Test-only allocation-failure selector, compiled in ONLY under the
/// `test-failpoint` feature (same separately named test artifact as the
/// panic failpoint): while the environment variable names an allocating
/// callback (`key_new`, `key_generate`, `key_duplicate`, `signature_new` or
/// `signature_duplicate`), that callback reports
/// allocation failure by returning null or zero instead of panicking;
/// `key_import` and `key_set_encoded_public` cover the newly shared immutable
/// key-state allocations as well. Clearing the variable restores normal
/// allocation. The ordinary module is built
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

/// Catch a verification panic without collapsing an internal failure into a
/// cryptographic non-match.  OpenSSL's provider contract reserves zero for a
/// validly executed verification whose equation does not match, while a
/// negative return reports an operational error.
fn ffi_verify_int(operation: impl FnOnce() -> c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(-1)
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

        let private = match raw_private {
            Some(seed) => match prepare_private(seed, "key_import") {
                Some(private) => Some(private),
                None => return 0,
            },
            None => None,
        };

        let supplied_public = match raw_public {
            Some(public) => match VerifyingKey::from_bytes(&public) {
                Ok(public) => Some(public),
                Err(_) => return 0,
            },
            None => None,
        };
        if let Some(public) = supplied_public.as_ref()
            && private.as_ref().is_some_and(|private| {
                !bytes_equal(private.expanded.verifying_key_bytes(), public.as_bytes())
            })
        {
            return 0;
        }

        let public = match (private.as_ref(), supplied_public) {
            (Some(_), Some(public)) | (None, Some(public)) => {
                match Shared::try_new_at("key_import", public) {
                    Some(public) => Some(public),
                    None => return 0,
                }
            }
            (Some(private), None) => {
                match Shared::try_new_at("key_import", private.expanded.verifying_key()) {
                    Some(public) => Some(public),
                    None => return 0,
                }
            }
            (None, None) => None,
        };
        *key = DraftKey { private, public };
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
        let Some(Some(encoded)) =
            (unsafe { read_optional_exact::<PUBLIC_KEY_BYTES>(public, public_len) })
        else {
            return 0;
        };
        let Ok(public) = VerifyingKey::from_bytes(&encoded) else {
            return 0;
        };
        if key
            .public
            .as_ref()
            .is_some_and(|existing| !bytes_equal(existing.as_bytes(), public.as_bytes()))
        {
            return 0;
        }
        if let Some(private) = key.private.as_ref()
            && !bytes_equal(private.expanded.verifying_key_bytes(), public.as_bytes())
        {
            return 0;
        }

        let Some(public) = Shared::try_new_at("key_set_encoded_public", public) else {
            return 0;
        };
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
        let Some(private) = prepare_private(seed, "key_generate") else {
            return core::ptr::null_mut();
        };
        let Some(public) = Shared::try_new_at("key_generate", private.expanded.verifying_key())
        else {
            return core::ptr::null_mut();
        };

        let key = DraftKey {
            private: Some(private),
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
        let public = (include_public != 0)
            .then(|| source.public.clone())
            .flatten();

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
            match SigningKey::from_seed(&private.seed.0).and_then(|signing| signing.expand()) {
                Ok(expanded) => {
                    if !bytes_equal(
                        expanded.verifying_key_bytes(),
                        private.expanded.verifying_key_bytes(),
                    ) {
                        return 0;
                    }
                    Some(*expanded.verifying_key_bytes())
                }
                Err(_) => return 0,
            }
        } else {
            None
        };

        if validate_public != 0 {
            let Some(public) = key.public.as_ref() else {
                return 0;
            };
            if derived
                .as_ref()
                .is_some_and(|derived| !bytes_equal(derived, public.as_bytes()))
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
            if !bytes_equal(first.as_bytes(), second.as_bytes()) {
                return 0;
            }
        }
        if match_private != 0 {
            let (Some(first), Some(second)) = (first.private.as_ref(), second.private.as_ref())
            else {
                return 0;
            };
            if !bytes_equal(&first.seed.0, &second.seed.0) {
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
        if unsafe { write_exact(output, output_len, &private.seed.0) } {
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
        if unsafe { write_exact(output, output_len, public.as_bytes()) } {
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
        /*
         * EVP_DigestSignInit_ex() reuses the previously bound key when its
         * pkey argument is NULL.  The one-shot Ed301 context has no buffered
         * message state, so retaining the matching immutable operation is the
         * complete reinitialization.  A NULL key in any other state remains a
         * fail-closed error.
         */
        if key.is_null() {
            hit_panic_failpoint("signature_sign_init");
            if matches!(context.operation, SignatureOperation::Sign(_)) {
                return 1;
            }
            context.operation = SignatureOperation::Uninitialized;
            return 0;
        }

        context.operation = SignatureOperation::Uninitialized;
        hit_panic_failpoint("signature_sign_init");
        // SAFETY: Same contract as for context.
        let Some(key) = (unsafe { key.cast::<DraftKey>().as_ref() }) else {
            return 0;
        };
        let Some(private) = key.private.as_ref() else {
            return 0;
        };
        if key.public.as_ref().is_some_and(|public| {
            !bytes_equal(private.expanded.verifying_key_bytes(), public.as_bytes())
        }) {
            return 0;
        }

        context.operation = SignatureOperation::Sign(private.expanded.clone());
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
        /* See signature_sign_init(): NULL retains only a matching operation. */
        if key.is_null() {
            hit_panic_failpoint("signature_verify_init");
            if matches!(context.operation, SignatureOperation::Verify(_)) {
                return 1;
            }
            context.operation = SignatureOperation::Uninitialized;
            return 0;
        }

        context.operation = SignatureOperation::Uninitialized;
        hit_panic_failpoint("signature_verify_init");
        // SAFETY: Same contract as for context.
        let Some(key) = (unsafe { key.cast::<DraftKey>().as_ref() }) else {
            return 0;
        };
        let Some(public) = key.public.as_ref() else {
            return 0;
        };

        context.operation = SignatureOperation::Verify(public.clone());
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
        let SignatureOperation::Sign(signing_key) = &context.operation else {
            return 0;
        };
        if output.is_null() || output_len < SIGNATURE_BYTES {
            return 0;
        }
        // SAFETY: The shim keeps message_len bytes readable for this call.
        let Some(message) = (unsafe { read_bytes(message, message_len) }) else {
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
    ffi_verify_int(|| {
        hit_panic_failpoint("signature_verify");
        // SAFETY: The shim passes a live Rust-owned signature context.
        let Some(context) = (unsafe { context.cast::<DraftSignatureContext>().as_ref() }) else {
            return -1;
        };
        let SignatureOperation::Verify(public) = &context.operation else {
            return -1;
        };

        // SAFETY: The shim keeps the message buffer readable for this call.
        let Some(message) = (unsafe { read_bytes(message, message_len) }) else {
            return -1;
        };

        /* A malformed signature is a normal verification non-match. */
        if signature_len != SIGNATURE_BYTES {
            return 0;
        }

        // SAFETY: Same contract as for message.
        let Some(signature_value) = (unsafe { read_bytes(signature_value, signature_len) }) else {
            return -1;
        };

        i32::from(public.verify_bytes(message, signature_value))
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

fn prepare_private(seed: SecretSeed, allocation_site: &str) -> Option<PrivateKeyMaterial> {
    let signing_key = SigningKey::from_seed(&seed.0).ok()?;
    let expanded = signing_key.expand().ok()?;
    let expanded = Shared::try_new_at(allocation_site, expanded)?;
    Some(PrivateKeyMaterial { seed, expanded })
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
    static SHARED_DROPS: AtomicUsize = AtomicUsize::new(0);

    struct ZeroSized;

    struct SharedDrop;

    impl Drop for ZeroSized {
        fn drop(&mut self) {
            ZST_DROPS.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Drop for SharedDrop {
        fn drop(&mut self) {
            SHARED_DROPS.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn expanded_key(fill: u8) -> ExpandedSigningKey {
        SigningKey::from_seed(&[fill; SEED_BYTES])
            .expect("fixed-size test seed")
            .expand()
            .expect("test seed expansion")
    }

    fn shared<T>(value: T) -> Shared<T> {
        Shared::try_new_at("unit_test", value).expect("small test allocation")
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
    fn shared_state_is_immutable_and_drops_after_the_last_reference() {
        let before = SHARED_DROPS.load(Ordering::SeqCst);
        let first = shared(SharedDrop);
        assert_eq!(first.reference_count(), 1);
        let second = first.clone();
        assert_eq!(first.reference_count(), 2);
        drop(first);
        assert_eq!(second.reference_count(), 1);
        assert_eq!(SHARED_DROPS.load(Ordering::SeqCst), before);
        drop(second);
        assert_eq!(SHARED_DROPS.load(Ordering::SeqCst), before + 1);
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
        let expanded = shared(expanded_key(0x11));
        let source = DraftKey {
            public: Some(shared(expanded.verifying_key())),
            private: Some(PrivateKeyMaterial {
                seed: SecretSeed([0x11; SEED_BYTES]),
                expanded: expanded.clone(),
            }),
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
    fn null_key_reinitialization_preserves_only_the_matching_operation() {
        let expanded = shared(expanded_key(0xA5));
        let mut context = Box::new(DraftSignatureContext {
            operation: SignatureOperation::Sign(expanded.clone()),
        });
        let context_pointer = (&mut *context as *mut DraftSignatureContext).cast();
        assert_eq!(expanded.reference_count(), 2);
        assert_eq!(
            unsafe { signature_sign_init(context_pointer, core::ptr::null()) },
            1
        );
        assert!(matches!(context.operation, SignatureOperation::Sign(_)));
        assert_eq!(expanded.reference_count(), 2);

        /* A NULL key never changes an existing operation into another kind. */
        assert_eq!(
            unsafe { signature_verify_init(context_pointer, core::ptr::null()) },
            0
        );
        assert!(matches!(
            context.operation,
            SignatureOperation::Uninitialized
        ));
        assert_eq!(expanded.reference_count(), 1);

        let public = shared(expanded_key(0x5A).verifying_key());
        context.operation = SignatureOperation::Verify(public.clone());
        assert_eq!(public.reference_count(), 2);
        assert_eq!(
            unsafe { signature_verify_init(context_pointer, core::ptr::null()) },
            1
        );
        assert!(matches!(context.operation, SignatureOperation::Verify(_)));
        assert_eq!(public.reference_count(), 2);

        assert_eq!(
            unsafe { signature_sign_init(context_pointer, core::ptr::null()) },
            0
        );
        assert!(matches!(
            context.operation,
            SignatureOperation::Uninitialized
        ));
        assert_eq!(public.reference_count(), 1);
    }

    #[test]
    fn signature_verify_preserves_the_provider_tristate() {
        let expanded = expanded_key(0x42);
        let message = b"provider verify tri-state";
        let signature = expanded
            .sign(message)
            .expect("fixed test signing operation")
            .to_bytes();
        let mut context = DraftSignatureContext {
            operation: SignatureOperation::Verify(shared(expanded.verifying_key())),
        };
        let context_pointer = (&mut context as *mut DraftSignatureContext).cast();

        assert_eq!(
            unsafe {
                signature_verify(
                    context_pointer,
                    message.as_ptr(),
                    message.len(),
                    signature.as_ptr(),
                    signature.len(),
                )
            },
            1
        );

        let changed_message = b"provider verify tri-statf";
        assert_eq!(
            unsafe {
                signature_verify(
                    context_pointer,
                    changed_message.as_ptr(),
                    changed_message.len(),
                    signature.as_ptr(),
                    signature.len(),
                )
            },
            0
        );

        let malformed = [0xff_u8; SIGNATURE_BYTES];
        assert_eq!(
            unsafe {
                signature_verify(
                    context_pointer,
                    message.as_ptr(),
                    message.len(),
                    malformed.as_ptr(),
                    malformed.len(),
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                signature_verify(
                    context_pointer,
                    message.as_ptr(),
                    message.len(),
                    signature.as_ptr(),
                    SIGNATURE_BYTES - 1,
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                signature_verify(
                    context_pointer,
                    message.as_ptr(),
                    message.len(),
                    core::ptr::null(),
                    SIGNATURE_BYTES,
                )
            },
            -1
        );
        assert_eq!(
            unsafe {
                signature_verify(
                    context_pointer,
                    core::ptr::null(),
                    1,
                    signature.as_ptr(),
                    SIGNATURE_BYTES - 1,
                )
            },
            -1
        );
        assert_eq!(
            unsafe {
                signature_verify(
                    context_pointer,
                    core::ptr::null(),
                    1,
                    signature.as_ptr(),
                    signature.len(),
                )
            },
            -1
        );
        assert_eq!(
            unsafe {
                signature_verify(
                    context_pointer,
                    message.as_ptr(),
                    (isize::MAX as usize) + 1,
                    signature.as_ptr(),
                    signature.len(),
                )
            },
            -1
        );

        let uninitialized = DraftSignatureContext::default();
        assert_eq!(
            unsafe {
                signature_verify(
                    (&uninitialized as *const DraftSignatureContext).cast(),
                    message.as_ptr(),
                    message.len(),
                    signature.as_ptr(),
                    signature.len(),
                )
            },
            -1
        );
        assert_eq!(
            unsafe {
                signature_verify(
                    core::ptr::null(),
                    message.as_ptr(),
                    message.len(),
                    signature.as_ptr(),
                    signature.len(),
                )
            },
            -1
        );
    }

    #[test]
    fn signature_reset_invalidates_initialized_secret() {
        let mut context = Box::new(DraftSignatureContext {
            operation: SignatureOperation::Sign(shared(expanded_key(0x3C))),
        });
        let context_pointer = (&mut *context as *mut DraftSignatureContext).cast();
        unsafe { signature_reset(context_pointer) };
        assert!(matches!(
            context.operation,
            SignatureOperation::Uninitialized
        ));
    }

    #[test]
    fn signature_contexts_share_prepared_key_state() {
        let expanded = shared(expanded_key(0x27));
        let public = shared(expanded.verifying_key());
        let key = DraftKey {
            private: Some(PrivateKeyMaterial {
                seed: SecretSeed([0x27; SEED_BYTES]),
                expanded: expanded.clone(),
            }),
            public: Some(public.clone()),
        };
        assert_eq!(expanded.reference_count(), 2);
        assert_eq!(public.reference_count(), 2);

        let mut sign_context = DraftSignatureContext::default();
        assert_eq!(
            unsafe {
                signature_sign_init(
                    (&mut sign_context as *mut DraftSignatureContext).cast(),
                    (&key as *const DraftKey).cast(),
                )
            },
            1
        );
        assert_eq!(expanded.reference_count(), 3);

        let duplicate =
            unsafe { signature_duplicate((&sign_context as *const DraftSignatureContext).cast()) };
        assert!(!duplicate.is_null());
        assert_eq!(expanded.reference_count(), 4);
        unsafe { signature_free(duplicate) };
        assert_eq!(expanded.reference_count(), 3);
        unsafe { signature_reset((&mut sign_context as *mut DraftSignatureContext).cast()) };
        assert_eq!(expanded.reference_count(), 2);

        let mut verify_context = DraftSignatureContext::default();
        assert_eq!(
            unsafe {
                signature_verify_init(
                    (&mut verify_context as *mut DraftSignatureContext).cast(),
                    (&key as *const DraftKey).cast(),
                )
            },
            1
        );
        assert_eq!(public.reference_count(), 3);
        unsafe { signature_reset((&mut verify_context as *mut DraftSignatureContext).cast()) };
        assert_eq!(public.reference_count(), 2);
    }
}
