use ed301_eddsa::{SigningKey, VerifyingKey};
use std::hint::black_box;
use std::time::Instant;

fn parse_count(value: Option<String>) -> Result<u64, &'static str> {
    let count = value
        .ok_or("missing count")?
        .parse::<u64>()
        .map_err(|_| "invalid count")?;
    if count == 0 || count > 100_000_000 {
        return Err("count outside 1..=100000000");
    }
    Ok(count)
}

fn measure(mut operation: impl FnMut(), count: u64) -> f64 {
    let started = Instant::now();
    for _ in 0..count {
        operation();
    }
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / count as f64
}

fn main() -> Result<(), &'static str> {
    let mut arguments = std::env::args().skip(1);
    let operation = arguments.next().ok_or("missing operation")?;
    let count = parse_count(arguments.next())?;
    if arguments.next().is_some() {
        return Err("too many arguments");
    }

    let mut seed = [0_u8; 38];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let message = black_box([0x5a_u8; 64]);
    let signing = SigningKey::from_seed(&seed).map_err(|_| "signing key")?;
    let expanded = signing.expand().map_err(|_| "expanded key")?;
    let public = expanded.verifying_key_bytes().to_owned();
    let verifying = VerifyingKey::from_bytes(&public).map_err(|_| "verifying key")?;
    let signature = expanded.sign(&message).map_err(|_| "signature")?;
    if !verifying.verify_bytes(&message, signature.as_bytes()) {
        return Err("self-test");
    }

    let mean_ns = match operation.as_str() {
        "expand" => measure(
            || {
                let key = SigningKey::from_seed(black_box(&seed)).unwrap();
                black_box(key.expand().unwrap());
            },
            count,
        ),
        "sign" => measure(
            || {
                black_box(expanded.sign(black_box(&message)).unwrap());
            },
            count,
        ),
        "verify" => measure(
            || {
                black_box(
                    verifying.verify_bytes(black_box(&message), black_box(signature.as_bytes())),
                );
            },
            count,
        ),
        "import" => measure(
            || {
                black_box(VerifyingKey::from_bytes(black_box(&public)).unwrap());
            },
            count,
        ),
        _ => return Err("operation must be expand, sign, verify or import"),
    };
    println!("RESULT operation={operation} count={count} mean_ns={mean_ns:.3}");
    Ok(())
}
