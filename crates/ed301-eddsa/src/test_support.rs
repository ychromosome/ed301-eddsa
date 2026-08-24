//! Shared deterministic helpers for the crate's test modules.

/// Decode a lower-case hexadecimal test literal into a fixed-size byte array.
pub(crate) const fn decode_hex_array<const OUTPUT: usize>(hex: &[u8]) -> [u8; OUTPUT] {
    if hex.len() != OUTPUT * 2 {
        panic!("invalid test hex length");
    }

    let mut output = [0_u8; OUTPUT];
    let mut index = 0;
    while index < OUTPUT {
        output[index] = (hex_nibble(hex[index * 2]) << 4) | hex_nibble(hex[index * 2 + 1]);
        index += 1;
    }
    output
}

const fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid test hex"),
    }
}

/// Advance the deterministic SplitMix64 stream used by randomized tests.
pub(crate) fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}
