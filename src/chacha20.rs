// Import hacspec and all needed definitions.
use hacspec::prelude::*;

// Type definitions for use in chacha.

// These are type aliases for convenience
type State = [u32; 16];

// These are actual types; fixed-length arrays.
bytes!(StateBytes, 64);
bytes!(IV, 12);
bytes!(Key, 32);

pub fn state_to_bytes(x: State) -> StateBytes {
    let mut r = StateBytes::new();
    for i in 0..x.len() {
        let bytes = Bytes::from_u32l(x[i]);
        r[i * 4] = bytes[3];
        r[i * 4 + 1] = bytes[2];
        r[i * 4 + 2] = bytes[1];
        r[i * 4 + 3] = bytes[0];
    }
    r
}

#[wrappit]
fn line(a: usize, b: usize, d: usize, s: usize, m: State) -> State {
    let mut state = m;
    state[a] += state[b];
    state[d] ^= state[a];
    // TODO: The 32 here is interpreted as i32 on Linux (not on Windows),
    //       where .wrapping_sub is not defined.
    state[d] = state[d] << s | state[d] >> (32usize - s);
    state
}

pub fn quarter_round(a: usize, b: usize, c: usize, d: usize, m: State) -> State {
    let state = line(a, b, d, 16, m);
    let state = line(c, d, b, 12, state);
    let state = line(a, b, d, 8, state);
    line(c, d, b, 7, state)
}

fn double_round(m: State) -> State {
    let state = quarter_round(0, 4, 8, 12, m);
    let state = quarter_round(1, 5, 9, 13, state);
    let state = quarter_round(2, 6, 10, 14, state);
    let state = quarter_round(3, 7, 11, 15, state);

    let state = quarter_round(0, 5, 10, 15, state);
    let state = quarter_round(1, 6, 11, 12, state);
    let state = quarter_round(2, 7, 8, 13, state);
    quarter_round(3, 4, 9, 14, state)
}

pub fn block_init(key: Key, ctr: u32, iv: IV) -> State {
    [
        0x6170_7865,
        0x3320_646e,
        0x7962_2d32,
        0x6b20_6574,
        u32::from_le_bytes(key.get(0..4)),
        u32::from_le_bytes(key.get(4..8)),
        u32::from_le_bytes(key.get(8..12)),
        u32::from_le_bytes(key.get(12..16)),
        u32::from_le_bytes(key.get(16..20)),
        u32::from_le_bytes(key.get(20..24)),
        u32::from_le_bytes(key.get(24..28)),
        u32::from_le_bytes(key.get(28..32)),
        ctr,
        u32::from_le_bytes(iv.get(0..4)),
        u32::from_le_bytes(iv.get(4..8)),
        u32::from_le_bytes(iv.get(8..12)),
    ]
}

#[wrappit]
pub fn block_inner(key: Key, ctr: u32, iv: IV) -> State {
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

pub fn block(key: Key, ctr: u32, iv: IV) -> StateBytes {
    let state = block_inner(key, ctr, iv);
    state_to_bytes(state)
}

pub fn chacha(key: Key, iv: IV, m: Bytes) -> Result<Bytes, String> {
    let l = m.len();
    let n_blocks: usize = l / 64;
    let rem = l % 64;
    let mut ctr = 1;
    let mut blocks_out = Bytes::new_len(l);
    for i in 0..n_blocks {
        let key_block = block(key, ctr, iv);
        for j in 0..64 {
            let k = (i * 64) + j;
            blocks_out[k] = m[k] ^ key_block[j];
        }
        ctr += 1;
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
