use std::{hint::black_box, process::ExitCode};

use ed301_eddsa::SigningKey;
use ed301_valgrind_client::{make_defined, mark_undefined, running_on_valgrind};

fn main() -> ExitCode {
    if running_on_valgrind() == 0 {
        eprintln!("external_profile_taint_error=gate must run under Valgrind");
        return ExitCode::FAILURE;
    }

    let mut seed = [0x42_u8; 38];
    mark_undefined(&mut seed);
    let result = SigningKey::from_seed(&seed)
        .and_then(|key| key.sign(b"ordinary-external-consumer"))
        .map(|signature| signature.to_bytes());
    make_defined(&mut seed);

    match result {
        Ok(signature) => {
            black_box(signature);
            println!("external_profile_taint=PASS");
            ExitCode::SUCCESS
        }
        Err(_) => {
            eprintln!("external_profile_taint_error=signing failed");
            ExitCode::FAILURE
        }
    }
}
