use std::env;

fn main() {
    println!("cargo:rerun-if-changed=c/valgrind_client.c");
    for name in ["ED301_HERMETIC_NATIVE_BUILD", "CC", "AR"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    assert_eq!(
        env::var("ED301_HERMETIC_NATIVE_BUILD").as_deref(),
        Ok("1"),
        "secret-taint native build requires the hermetic gate"
    );
    assert_eq!(env::var("CC").as_deref(), Ok("/usr/bin/gcc"));
    assert_eq!(env::var("AR").as_deref(), Ok("/usr/bin/ar"));

    cc::Build::new()
        .compiler("/usr/bin/gcc")
        .archiver("/usr/bin/ar")
        .file("c/valgrind_client.c")
        .std("c11")
        .warnings(true)
        .warnings_into_errors(true)
        .compile("ed301_valgrind_client");
}
