//! Explicit public-output boundary used by the core.

#[cfg(feature = "secret-taint-instrumentation")]
#[inline(never)]
pub(crate) fn declassify<T: ?Sized>(value: &mut T) {
    ed301_valgrind_client::make_defined(value);
}

#[cfg(not(feature = "secret-taint-instrumentation"))]
#[inline(always)]
pub(crate) fn declassify<T: ?Sized>(_value: &mut T) {}
