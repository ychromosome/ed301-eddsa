//! RAII ownership for named secret intermediates.

use zeroize::{Zeroize, Zeroizing};

/// A named logical secret owner which zeroizes its value on every drop path,
/// including panic unwinding.
pub(crate) type Secret<T> = Zeroizing<T>;

/// Move a secret value into its unwind-safe owner immediately after creation.
#[inline(always)]
pub(crate) fn secret<T: Zeroize>(value: T) -> Secret<T> {
    Zeroizing::new(value)
}

#[cfg(all(test, panic = "unwind"))]
mod tests {
    extern crate std;

    use super::*;
    use crate::scalar::Scalar;
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    struct UnwindProbe {
        bytes: [u8; 76],
        observed_zeroized: Arc<AtomicBool>,
    }

    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    impl Zeroize for UnwindProbe {
        fn zeroize(&mut self) {
            self.bytes.zeroize();
            self.observed_zeroized
                .store(self.bytes == [0_u8; 76], Ordering::SeqCst);
        }
    }

    #[test]
    fn named_secret_owner_zeroizes_during_unwind() {
        assert_zeroize_on_drop::<Secret<[u8; 76]>>();
        assert_zeroize_on_drop::<Secret<[u8; 38]>>();
        assert_zeroize_on_drop::<Secret<Scalar>>();
        assert!(core::mem::needs_drop::<Secret<[u8; 76]>>());
        assert!(core::mem::needs_drop::<Secret<[u8; 38]>>());
        assert!(core::mem::needs_drop::<Secret<Scalar>>());

        let observed_zeroized = Arc::new(AtomicBool::new(false));
        let observer = Arc::clone(&observed_zeroized);

        let outcome = catch_unwind(AssertUnwindSafe(move || {
            let _owner = secret(UnwindProbe {
                bytes: [0xa5_u8; 76],
                observed_zeroized: observer,
            });
            panic!("controlled unwind after secret creation");
        }));

        assert!(outcome.is_err());
        assert!(observed_zeroized.load(Ordering::SeqCst));
    }
}
