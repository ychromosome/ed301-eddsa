//! ARM64 tests

#![cfg(target_arch = "aarch64")]

cpufeatures::new!(armcaps, "aes", "sha2", "sha3", "sm4");

#[test]
fn init() {
    let token: armcaps::InitToken = armcaps::init();
    assert_eq!(token.get(), armcaps::get());
}

#[test]
fn init_get() {
    let (token, val) = armcaps::init_get();
    assert_eq!(val, token.get());
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn composite_hwcaps_require_every_bit() {
    use cpufeatures::aarch64::hwcaps;

    assert!(!cpufeatures::check!(libc::HWCAP_AES, "aes"));
    assert!(!cpufeatures::check!(libc::HWCAP_PMULL, "aes"));
    assert!(!cpufeatures::check!(
        hwcaps::AES & !libc::HWCAP_ASIMD,
        "aes"
    ));
    assert!(cpufeatures::check!(hwcaps::AES, "aes"));

    assert!(!cpufeatures::check!(libc::HWCAP_SHA1, "sha2"));
    assert!(!cpufeatures::check!(libc::HWCAP_SHA2, "sha2"));
    assert!(!cpufeatures::check!(
        hwcaps::SHA2 & !libc::HWCAP_ASIMD,
        "sha2"
    ));
    assert!(cpufeatures::check!(hwcaps::SHA2, "sha2"));

    assert!(!cpufeatures::check!(
        hwcaps::SHA2 | libc::HWCAP_SHA3,
        "sha3"
    ));
    assert!(!cpufeatures::check!(
        hwcaps::SHA2 | libc::HWCAP_SHA512,
        "sha3"
    ));
    assert!(cpufeatures::check!(hwcaps::SHA3, "sha3"));

    assert!(!cpufeatures::check!(libc::HWCAP_SM3, "sm4"));
    assert!(!cpufeatures::check!(libc::HWCAP_SM4, "sm4"));
    assert!(!cpufeatures::check!(
        hwcaps::SM4 & !libc::HWCAP_ASIMD,
        "sm4"
    ));
    assert!(cpufeatures::check!(hwcaps::SM4, "sm4"));
}
