fn main() {
    println!("cargo:rerun-if-changed=c/valgrind_client.c");

    cc::Build::new()
        .file("c/valgrind_client.c")
        .std("c11")
        .warnings(true)
        .warnings_into_errors(true)
        .compile("ed301_valgrind_client");
}
