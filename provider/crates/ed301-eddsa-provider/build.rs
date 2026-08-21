fn main() {
    println!("cargo:rerun-if-changed=c/provider_shim.c");
    println!("cargo:rerun-if-changed=c/param_helpers.h");
    println!("cargo:rerun-if-changed=c/provider_internal.h");
    println!("cargo:rerun-if-env-changed=OPENSSL_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_LIB_DIR");

    let mut build = cc::Build::new();
    // The test-only failpoint artifact renames the module and its
    // "provider=" property inside the C shim (FBL-02).
    if std::env::var_os("CARGO_FEATURE_TEST_FAILPOINT").is_some() {
        build.define("ED301D00_TEST_FAILPOINT_ARTIFACT", "1");
    }
    build
        .file("c/provider_shim.c")
        .std("c11")
        .flag_if_supported("-fvisibility=hidden")
        .flag_if_supported("-fstack-protector-strong")
        .warnings(true)
        .warnings_into_errors(true);

    if let Some(include_dir) = std::env::var_os("OPENSSL_INCLUDE_DIR") {
        build.include(include_dir);
    }
    build.compile("ed301_eddsa_draft00_shim");

    if let Some(lib_dir) = std::env::var_os("OPENSSL_LIB_DIR") {
        println!(
            "cargo:rustc-link-search=native={}",
            lib_dir.to_string_lossy()
        );
    }
    println!("cargo:rustc-link-lib=crypto");

    // The dynamic export surface is restricted to the single required
    // provider entry point by rustc's own cdylib symbol handling (verified
    // by the module-exports gate); current rustc emits its own anonymous
    // version script for cdylibs, so a second linker version script must
    // not be combined with it.
}
