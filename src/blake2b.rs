// Import hacspec and all needed definitions.
use hacspec::*;
hacspec_imports!();

array!(State, 8, u64);
array!(DoubleState, 16, u64);
array!(Counter, 2, u64);
bytes!(Buffer, 128);
bytes!(Digest, 64);
array!(SigmaLine, 16 ,usize);
array!(Sigma, 12, SigmaLine);

static SIGMA: Sigma = Sigma([
    SigmaLine([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
    SigmaLine([14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]),
    SigmaLine([11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4]),
    SigmaLine([7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8]),
    SigmaLine([9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13]),
    SigmaLine([2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9]),
    SigmaLine([12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11]),
    SigmaLine([13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10]),
    SigmaLine([6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5]),
    SigmaLine([10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]),
    SigmaLine([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
    SigmaLine([14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]),
]);

static IV: State = State([
    0x6a09_e667_f3bc_c908u64,
    0xbb67_ae85_84ca_a73bu64,
    0x3c6e_f372_fe94_f82bu64,
    0xa54f_f53a_5f1d_36f1u64,
    0x510e_527f_ade6_82d1u64,
    0x9b05_688c_2b3e_6c1fu64,
    0x1f83_d9ab_fb41_bd6bu64,
    0x5be0_cd19_137e_2179u64,
]);

#[wrappit]
fn mix(v: DoubleState, a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) -> DoubleState {
    let mut result = v;
    result[a] = result[a] + result[b] + x;
    result[d] = (result[d] ^ result[a]).rotate_right(32);

    result[c] = result[c] + result[d];
    result[b] = (result[b] ^ result[c]).rotate_right(24);

    result[a] = result[a] + result[b] + y;
    result[d] = (result[d] ^ result[a]).rotate_right(16);

    result[c] = result[c] + result[d];
    result[b] = (result[b] ^ result[c]).rotate_right(63);

    result
}

// TODO: add test case where counter wraps
#[wrappit]
fn inc_counter(t: Counter, x: u64) -> Counter {
    let mut result: Counter = Counter::from_array([0u64; 2]);
    result[0] = t[0] + x;
    if result[0] < x {
        result[1] = t[1] + 1;
    }
    result
}

fn make_u64array(h: Buffer) -> DoubleState {
    let mut result = DoubleState::new();
    for i in 0..16 {
        result[i] = u64::from(h[8 * i])
            | u64::from(h[1 + 8 * i]) << 8
            | u64::from(h[2 + 8 * i]) << 16
            | u64::from(h[3 + 8 * i]) << 24
            | u64::from(h[4 + 8 * i]) << 32
            | u64::from(h[5 + 8 * i]) << 40
            | u64::from(h[6 + 8 * i]) << 48
            | u64::from(h[7 + 8 * i]) << 56;
    }
    result
}

fn compress(h: State, m: Buffer, t: Counter, last_block: bool) -> State {
    let mut v = DoubleState::new();

    // Read u8 data to u64.
    let m = make_u64array(m);

    // Prepare.
    v[0..8].clone_from_slice(&h[..]);
    v[8..16].clone_from_slice(&IV[..]);
    // TODO: This is equivalent to the following but the idiomatic way of doing it.
    //       Do we want to allow both?
    // for i in 0..8 {
    //     v[i] = h[i];
    //     v[i + 8] = IV[i];
    // }
    let foo0: u64 = t[0];
    let foo1: u64 = t[1];
    v[12] ^= foo0;
    v[13] ^= foo1;
    if last_block {
        v[14] = !v[14];
    }

    // Mixing.
    for i in 0..12 {
        v = mix(v, 0, 4, 8, 12, m[SIGMA[i][0]], m[SIGMA[i][1]]);
        v = mix(v, 1, 5, 9, 13, m[SIGMA[i][2]], m[SIGMA[i][3]]);
        v = mix(v, 2, 6, 10, 14, m[SIGMA[i][4]], m[SIGMA[i][5]]);
        v = mix(v, 3, 7, 11, 15, m[SIGMA[i][6]], m[SIGMA[i][7]]);
        v = mix(v, 0, 5, 10, 15, m[SIGMA[i][8]], m[SIGMA[i][9]]);
        v = mix(v, 1, 6, 11, 12, m[SIGMA[i][10]], m[SIGMA[i][11]]);
        v = mix(v, 2, 7, 8, 13, m[SIGMA[i][12]], m[SIGMA[i][13]]);
        v = mix(v, 3, 4, 9, 14, m[SIGMA[i][14]], m[SIGMA[i][15]]);
    }

    let mut compressed = State::new();
    for i in 0..8 {
        compressed[i] = h[i] ^ v[i] ^ v[i + 8];
    }
    compressed
}

fn get_byte(x:u64, i:usize) -> u8 {
    match i {
        0 => (x & 0xFFu64) as u8,
        1 => ((x & 0xFF00u64) >> 8) as u8,
        2 => ((x & 0xFF0000u64) >> 16) as u8,
        3 => ((x & 0xFF000000u64) >> 24) as u8,
        4 => ((x & 0xFF00000000u64) >> 32) as u8,
        5 => ((x & 0xFF0000000000u64) >> 40) as u8,
        6 => ((x & 0xFF000000000000u64) >> 48) as u8,
        7 => ((x & 0xFF00000000000000u64) >> 56) as u8,
        _ => 0 as u8
    }

}

pub fn blake2b(data: Bytes) -> Digest {
    let mut h = IV;
    // This only supports the 512 version without key.
    h[0] = h[0] ^ 0x0101_0000 ^ 64;

    let mut t = Counter::from_array([0; 2]);
    let blocks = data.len() / 128;
    for i in 0..blocks {
        let m = Buffer::from(&data[i * 128..i * 128 + 128]);
        t = inc_counter(t, 128);
        h = compress(h, m, t, false);
    }

    // Pad last bits of data to a full block.
    let mut m = Buffer::new();
    let remaining_bytes = data.len() - 128 * blocks;
    let remaining_start = data.len() - remaining_bytes;
    t = inc_counter(t, remaining_bytes as u64);
    for (j, i) in (remaining_start..(remaining_start + remaining_bytes)).enumerate() {
        m[j] = data[i];
    }
    h = compress(h, m, t, true);

    // We transform 8*u64 into 64*u8
    let mut d = Digest::new();
    for i in 0..8 {
        for j in 0..8 {
            d[i*8 + j] = get_byte(h[i], j);
        }
    }
    d
}
