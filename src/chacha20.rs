use hacspec::*;

type State = [u32; 16];
type Key = [u8; 32];
type IV = [u8; 12];

pub fn state_to_bytes(x: State) -> [u8; 64] {
    let mut r: [u8; 64] = [0; 64];
    for i in 0..x.len() {
        let bytes = from_u32l(x[i]);
        r[i * 4] = bytes.3;
        r[i * 4 + 1] = bytes.2;
        r[i * 4 + 2] = bytes.1;
        r[i * 4 + 3] = bytes.0;
    }
    r
}

fn line(a: usize, b: usize, d: usize, s: usize, m: State) -> State {
    let mut state = m;
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = state[d] ^ state[a];
    state[d] = state[d] << s | state[d] >> (32 - s);
    state
}

pub fn quarter_round(a: usize, b: usize, c: usize, d: usize, m: State) -> State {
    let mut state = m;
    state = line(a, b, d, 16, state);
    state = line(c, d, b, 12, state);
    state = line(a, b, d, 8, state);
    state = line(c, d, b, 7, state);
    state
}

fn double_round(m: State) -> State {
    let mut state = m;
    state = quarter_round(0, 4, 8, 12, state);
    state = quarter_round(1, 5, 9, 13, state);
    state = quarter_round(2, 6, 10, 14, state);
    state = quarter_round(3, 7, 11, 15, state);

    state = quarter_round(0, 5, 10, 15, state);
    state = quarter_round(1, 6, 11, 12, state);
    state = quarter_round(2, 7, 8, 13, state);
    state = quarter_round(3, 4, 9, 14, state);
    state
}

pub fn block_init(key: Key, ctr: u32, iv: IV) -> State {
    let state = [
        0x61707865,
        0x3320646e,
        0x79622d32,
        0x6b206574,
        to_u32l(&key[0..4]),
        to_u32l(&key[4..8]),
        to_u32l(&key[8..12]),
        to_u32l(&key[12..16]),
        to_u32l(&key[16..20]),
        to_u32l(&key[20..24]),
        to_u32l(&key[24..28]),
        to_u32l(&key[28..32]),
        ctr,
        to_u32l(&iv[0..4]),
        to_u32l(&iv[4..8]),
        to_u32l(&iv[8..12]),
    ];
    state
}

pub fn block_inner(key: Key, ctr: u32, iv: IV) -> State {
    let st = block_init(key, ctr, iv);
    let mut state = st;
    for _ in 0..10 {
        state = double_round(state);
    }
    for i in 0..16 {
        state[i] = state[i].wrapping_add(st[i]);
    }
    state
}

fn block(key: Key, ctr: u32, iv: IV) -> [u8; 64] {
    let state = block_inner(key, ctr, iv);
    state_to_bytes(state)
}

pub fn chacha(key: Key, iv: IV, m: &[u8]) -> Result<Vec<u8>, String> {
    let l = m.len();
    let n_blocks: usize = l / 64; // TODO: floor
    let rem = l % 64;
    let mut ctr = 1;
    let mut blocks_out = Vec::new();
    blocks_out.extend_from_slice(m);
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
