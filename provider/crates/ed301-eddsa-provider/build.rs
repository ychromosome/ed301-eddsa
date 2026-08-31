use std::env;
use std::fs;
use std::path::PathBuf;

fn required_exact_environment(name: &str, expected: &str) {
    let actual = env::var(name).unwrap_or_else(|_| panic!("{name} is required"));
    assert_eq!(actual, expected, "unsafe {name} selection");
}

fn canonical_directory(name: &str) -> PathBuf {
    let raw = env::var(name).unwrap_or_else(|_| panic!("{name} is required"));
    assert!(
        !raw.chars().any(char::is_control),
        "{name} contains a control character"
    );
    let path = fs::canonicalize(&raw)
        .unwrap_or_else(|error| panic!("cannot canonicalize {name}: {error}"));
    assert!(path.is_dir(), "{name} is not a directory");
    let printable = path
        .to_str()
        .unwrap_or_else(|| panic!("{name} is not valid UTF-8"));
    assert!(
        !printable.chars().any(char::is_control),
        "canonical {name} contains a control character"
    );
    path
}

fn reject_native_injection_environment() {
    const EXACT: &[&str] = &[
        "ARFLAGS",
        "CFLAGS",
        "CCC_OVERRIDE_OPTIONS",
        "CCC_PRINT_BINDINGS",
        "CCC_PRINT_OPTIONS",
        "COMPILER_PATH",
        "CPPFLAGS",
        "CXXFLAGS",
        "LDFLAGS",
        "LIBRARY_PATH",
        "CPATH",
        "C_INCLUDE_PATH",
        "CPLUS_INCLUDE_PATH",
        "OBJC_INCLUDE_PATH",
        "CRATE_CC_NO_DEFAULTS",
        "CC_ENABLE_DEBUG_OUTPUT",
        "GCC_EXEC_PREFIX",
        "HOST_ARFLAGS",
        "HOST_CFLAGS",
        "TARGET_ARFLAGS",
        "TARGET_CFLAGS",
    ];
    for (name, _) in env::vars_os() {
        let Some(name) = name.to_str() else {
            panic!("non-UTF-8 environment variable name");
        };
        let prefixed = [
            "CC_",
            "CXX_",
            "AR_",
            "RANLIB_",
            "CFLAGS_",
            "CPPFLAGS_",
            "CXXFLAGS_",
            "LDFLAGS_",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix));
        assert!(
            !prefixed && !EXACT.contains(&name),
            "native build override is forbidden: {name}"
        );
    }
}

fn main() {
    println!("cargo:rerun-if-changed=c/provider_shim.c");
    println!("cargo:rerun-if-changed=c/param_helpers.h");
    println!("cargo:rerun-if-changed=c/provider_internal.h");
    for name in [
        "ED301_HERMETIC_PROVIDER_BUILD",
        "OPENSSL_INCLUDE_DIR",
        "OPENSSL_LIB_DIR",
        "CC",
        "AR",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }

    required_exact_environment("ED301_HERMETIC_PROVIDER_BUILD", "1");
    required_exact_environment("CC", "/usr/bin/gcc");
    required_exact_environment("AR", "/usr/bin/ar");
    reject_native_injection_environment();
    let include_dir = canonical_directory("OPENSSL_INCLUDE_DIR");
    let lib_dir = canonical_directory("OPENSSL_LIB_DIR");

    let mut build = cc::Build::new();
    let failpoint = env::var_os("CARGO_FEATURE_TEST_FAILPOINT").is_some();
    let pki_experiment = env::var_os("CARGO_FEATURE_PKI_EXPERIMENT").is_some();
    let tls_experiment = env::var_os("CARGO_FEATURE_TLS_EXPERIMENT").is_some();
    let tls_collider = env::var_os("CARGO_FEATURE_TLS_COLLIDER").is_some();
    let pki_only = pki_experiment && !tls_experiment && !tls_collider;
    assert!(
        usize::from(failpoint)
            + usize::from(pki_only)
            + usize::from(tls_experiment)
            + usize::from(tls_collider)
            <= 1,
        "provider artifact features are mutually exclusive"
    );
    if failpoint {
        build.define("ED301V1_TEST_FAILPOINT_ARTIFACT", "1");
    }
    if pki_experiment {
        build.define("ED301V1_PKI_EXPERIMENT_ARTIFACT", "1");
    }
    if tls_experiment {
        build.define("ED301V1_TLS_EXPERIMENT_ARTIFACT", "1");
    }
    if tls_collider {
        build.define("ED301V1_TLS_COLLIDER_ARTIFACT", "1");
    }
    build
        .compiler("/usr/bin/gcc")
        .archiver("/usr/bin/ar")
        .include(&include_dir)
        .file("c/provider_shim.c")
        .std("c11")
        .flag_if_supported("-fvisibility=hidden")
        .flag_if_supported("-fstack-protector-strong")
        .warnings(true)
        .warnings_into_errors(true)
        .compile("ed301_eddsa_v1_shim");

    println!(
        "cargo:rustc-link-search=native={}",
        lib_dir
            .to_str()
            .expect("canonical OPENSSL_LIB_DIR must remain UTF-8")
    );
    println!("cargo:rustc-link-lib=crypto");

    // The dynamic export surface is restricted to the single required
    // provider entry point by rustc's cdylib symbol handling and is verified
    // independently by the module-export gate.
}
