// Import hacspec and all needed definitions.
use hacspec::*;
hacspec_imports!();

// Type definitions for use in chacha.

// These are type aliases for convenience

// These are actual types; fixed-length arrays.
array!(State, 16, U32, u32);
bytes!(StateBytes, 64);
bytes!(IV, 12);
bytes!(Key, 32);

pub fn state_to_bytes(x: State) -> StateBytes {
    let mut r = StateBytes::new();
    for i in 0..x.len() {
        let bytes = u32_to_le_bytes(x[i]);
        r[i * 4] = bytes[3];
        r[i * 4 + 1] = bytes[2];
        r[i * 4 + 2] = bytes[1];
        r[i * 4 + 3] = bytes[0];
    }
    r
}

fn line(a: usize, b: usize, d: usize, s: usize, m: State) -> State {
    let mut state = m;
    let sb = state[b];
    state[a] += sb;
    let sa = state[a];
    state[d] ^= sa;
    // TODO: The 32 here is interpreted as i32 on Linux (not on Windows),
    //       where .wrapping_sub is not defined.
    state[d] = state[d] << s as u32 | state[d] >> (32usize - s) as u32;
    state
}

pub fn quarter_round(a: usize, b: usize, c: usize, d: usize, state: State) -> State {
    let state = line(a, b, d, 16, state);
    let state = line(c, d, b, 12, state);
    let state = line(a, b, d, 8, state);
    line(c, d, b, 7, state)
}

fn double_round( state: State) -> State {
    let state = quarter_round(0, 4, 8, 12, state);
    let state = quarter_round(1, 5, 9, 13, state);
    let state = quarter_round(2, 6, 10, 14, state);
    let state = quarter_round(3, 7, 11, 15, state);

    let state = quarter_round(0, 5, 10, 15, state);
    let state = quarter_round(1, 6, 11, 12, state);
    let state = quarter_round(2, 7, 8, 13, state);
    quarter_round(3, 4, 9, 14, state)
}

pub fn block_init(key: Key, ctr: U32, iv: IV) -> State {
    State([
        U32(0x6170_7865),
        U32(0x3320_646e),
        U32(0x7962_2d32),
        U32(0x6b20_6574),
        u32_from_le_bytes(U32Word::from_sub(key, 0..4)),
        u32_from_le_bytes(U32Word::from_sub(key, 4..8)),
        u32_from_le_bytes(U32Word::from_sub(key, 8..12)),
        u32_from_le_bytes(U32Word::from_sub(key, 12..16)),
        u32_from_le_bytes(U32Word::from_sub(key, 16..20)),
        u32_from_le_bytes(U32Word::from_sub(key, 20..24)),
        u32_from_le_bytes(U32Word::from_sub(key, 24..28)),
        u32_from_le_bytes(U32Word::from_sub(key, 28..32)),
        ctr,
        u32_from_le_bytes(U32Word::from_sub(iv, 0..4)),
        u32_from_le_bytes(U32Word::from_sub(iv, 4..8)),
        u32_from_le_bytes(U32Word::from_sub(iv, 8..12)),
    ])
}

pub fn block_inner(key: Key, ctr: U32, iv: IV) -> State {
    let st = block_init(key, ctr, iv);
    let mut state = st;
    for _ in 0..10 {
        state = double_round(state);
    }
    for i in 0..16 {
        state[i] = state[i] + st[i];
    }
    state
}

pub fn block(key: Key, ctr: U32, iv: IV) -> StateBytes {
    let state = block_inner(key, ctr, iv);
    state_to_bytes(state)
}

pub fn chacha(key: Key, iv: IV, m: Bytes) -> Result<Bytes, String> {
    let l = m.len();
    let n_blocks: usize = l / 64;
    let rem = l % 64;
    let mut ctr = U32(1);
    let mut blocks_out = Bytes::new_len(l);
    for i in 0..n_blocks {
        let key_block = block(key, ctr, iv);
        for j in 0..64 {
            let k = (i * 64) + j;
            blocks_out[k] = m[k] ^ key_block[j];
        }
        ctr += U32(1);
    }
    // Last block might not be full
    if rem != 0 {
        let key_block = block(key, ctr, iv);
        for i in 0..rem {
            let k = (n_blocks * 64) + i;
            blocks_out[k] = m[k] ^ key_block[i];
        }
    }
    Ok(blocks_out)
}
