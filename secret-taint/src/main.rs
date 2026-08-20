use std::{env, process::ExitCode};

use ed301_eddsa::{
    SigningKey,
    parameters::{PUBLIC_KEY_BYTES, SEED_BYTES, SIGNATURE_BYTES},
};
use ed301_valgrind_client::{get_vbits, make_defined, mark_undefined, running_on_valgrind};

const SECRET_ENV: &str = "ED301_CT_SECRET_HEX";
const EXPECTED_PUBLIC_ENV: &str = "ED301_CT_EXPECTED_PUBLIC_HEX";
const EXPECTED_SIGNATURE_ENV: &str = "ED301_CT_EXPECTED_SIGNATURE_HEX";

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Defined,
    Tainted,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("secret_taint_error={message}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    if running_on_valgrind() == 0 {
        return Err("harness must run under Valgrind".into());
    }
    let mut case = None;
    let mut mode = None;
    for argument in env::args().skip(1) {
        if let Some(value) = argument.strip_prefix("--case=") {
            case = Some(value.to_owned());
        } else if let Some(value) = argument.strip_prefix("--mode=") {
            mode = Some(match value {
                "defined" => Mode::Defined,
                "tainted" => Mode::Tainted,
                _ => return Err(format!("unsupported mode: {value}")),
            });
        } else {
            return Err(format!("unsupported argument: {argument}"));
        }
    }
    let case = case.ok_or_else(|| "missing --case".to_owned())?;
    let mode = mode.ok_or_else(|| "missing --mode".to_owned())?;
    match case.as_str() {
        "public" => run_public(mode)?,
        "sign" => run_sign(mode)?,
        _ => return Err(format!("unsupported case: {case}")),
    }
    println!(
        "secret_taint_case={case} mode={} instrumentation={} pass=1",
        if mode == Mode::Defined {
            "defined"
        } else {
            "tainted"
        },
        u8::from(cfg!(feature = "instrumented")),
    );
    Ok(())
}

fn run_public(mode: Mode) -> Result<(), String> {
    let mut seed = required_array::<SEED_BYTES>(SECRET_ENV)?;
    let expected = required_array::<PUBLIC_KEY_BYTES>(EXPECTED_PUBLIC_ENV)?;
    apply_mode(mode, &mut seed);
    let key = SigningKey::from_seed(&seed).map_err(|_| "key import failed")?;
    let public = key
        .verifying_key()
        .map_err(|_| "public derivation failed")?
        .to_bytes();
    require_public_vbits(mode, &public)?;
    make_defined(&mut seed);
    if public != expected {
        return Err("public KAT mismatch".into());
    }
    Ok(())
}

fn run_sign(mode: Mode) -> Result<(), String> {
    let mut seed = required_array::<SEED_BYTES>(SECRET_ENV)?;
    let expected = required_array::<SIGNATURE_BYTES>(EXPECTED_SIGNATURE_ENV)?;
    apply_mode(mode, &mut seed);
    let key = SigningKey::from_seed(&seed).map_err(|_| "key import failed")?;
    let signature = key.sign(b"").map_err(|_| "signing failed")?.to_bytes();
    require_public_vbits(mode, &signature)?;
    make_defined(&mut seed);
    if signature != expected {
        return Err("signature KAT mismatch".into());
    }
    Ok(())
}

fn apply_mode<const N: usize>(mode: Mode, secret: &mut [u8; N]) {
    if mode == Mode::Tainted {
        mark_undefined(secret);
    }
}

fn require_public_vbits(mode: Mode, value: &[u8]) -> Result<(), String> {
    let vbits = validity_bits(value)?;
    if (mode == Mode::Defined || cfg!(feature = "instrumented"))
        && vbits.iter().any(|byte| *byte != 0)
    {
        return Err("public output was not declassified".into());
    }
    Ok(())
}

fn validity_bits(value: &[u8]) -> Result<Vec<u8>, String> {
    let mut vbits = vec![0_u8; value.len()];
    let status = get_vbits(value, &mut vbits);
    make_defined(&mut vbits);
    if status != 1 {
        return Err(format!("VALGRIND_GET_VBITS failed with status {status}"));
    }
    Ok(vbits)
}

fn required_array<const N: usize>(name: &str) -> Result<[u8; N], String> {
    let value = env::var(name).map_err(|_| format!("missing {name}"))?;
    if value.len() != N * 2 {
        return Err(format!("{name} has the wrong hexadecimal length"));
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = (hex_nibble(value.as_bytes()[offset])? << 4)
            | hex_nibble(value.as_bytes()[offset + 1])?;
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("invalid hexadecimal input".into()),
    }
}
