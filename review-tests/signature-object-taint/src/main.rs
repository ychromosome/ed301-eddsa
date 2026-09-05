use core::mem::size_of;
use std::process::ExitCode;

use ed301_eddsa::{Signature, SigningKey, parameters::SIGNATURE_BYTES};
use ed301_valgrind_client::{get_vbits, make_defined, mark_undefined, running_on_valgrind};

#[derive(Debug)]
struct ShadowState {
    size: usize,
    undefined_offsets: Vec<usize>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("signature_object_taint_error={message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    if running_on_valgrind() == 0 {
        return Err("gate must run under Valgrind".into());
    }

    let mut seed = [0x42_u8; 38];
    mark_undefined(&mut seed);
    let key = SigningKey::from_seed(&seed).map_err(|_| "seed import failed")?;
    let mut signature = key
        .sign(b"whole-public-object")
        .map_err(|_| "signing failed")?;
    let signed_state = inspect(&signature)?;

    /*
     * Restore shadow state before moving/dropping the diagnostic object. The
     * values are public only after this gate has recorded whether the library
     * performed the required declassification itself.
     */
    make_defined(&mut signature);
    let wire = signature.to_bytes();
    let mut parsed = Signature::from_bytes(&wire).map_err(|_| "parse failed")?;
    let parsed_state = inspect(&parsed)?;
    make_defined(&mut parsed);
    make_defined(&mut seed);

    print_state("signed", &signed_state);
    print_state("parsed", &parsed_state);

    for (label, state) in [("signed", signed_state), ("parsed", parsed_state)] {
        if state.size != SIGNATURE_BYTES {
            return Err(format!(
                "{label} Signature has {} bytes; public wire artifact has {SIGNATURE_BYTES}",
                state.size
            ));
        }
        if !state.undefined_offsets.is_empty() {
            return Err(format!(
                "{label} Signature retains {} secret-labelled or padding bytes",
                state.undefined_offsets.len()
            ));
        }
    }
    Ok(())
}

fn inspect(signature: &Signature) -> Result<ShadowState, String> {
    let raw = unsafe {
        /*
         * Test-only object-representation inspection. `signature` is live for
         * exactly `size_of::<Signature>()` bytes and the slice is read-only.
         */
        core::slice::from_raw_parts(
            core::ptr::from_ref(signature).cast::<u8>(),
            size_of::<Signature>(),
        )
    };
    let mut vbits = vec![0_u8; raw.len()];
    let status = get_vbits(raw, &mut vbits);
    make_defined(&mut vbits);
    if status != 1 {
        return Err(format!("VALGRIND_GET_VBITS failed with status {status}"));
    }
    let undefined_offsets = vbits
        .iter()
        .enumerate()
        .filter_map(|(offset, byte)| (*byte != 0).then_some(offset))
        .collect();
    Ok(ShadowState {
        size: raw.len(),
        undefined_offsets,
    })
}

fn print_state(label: &str, state: &ShadowState) {
    println!(
        "signature_object_state label={label} size={} undefined_bytes={} ranges={:?}",
        state.size,
        state.undefined_offsets.len(),
        ranges(&state.undefined_offsets)
    );
}

fn ranges(offsets: &[usize]) -> Vec<(usize, usize)> {
    let Some((&first, rest)) = offsets.split_first() else {
        return Vec::new();
    };
    let mut output = Vec::new();
    let mut start = first;
    let mut previous = first;
    for &offset in rest {
        if offset != previous + 1 {
            output.push((start, previous));
            start = offset;
        }
        previous = offset;
    }
    output.push((start, previous));
    output
}
