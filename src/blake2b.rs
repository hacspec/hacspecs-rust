// Import hacspec and all needed definitions.
use hacspec::*;
hacspec_imports!();

type IV = [u64; 8];
type Counter = [u64; 2];
bytes!(Buffer, 128);
bytes!(Digest, 64);

static SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

static IV: IV = [
    0x6a09e667f3bcc908u64,
    0xbb67ae8584caa73bu64,
    0x3c6ef372fe94f82bu64,
    0xa54ff53a5f1d36f1u64,
    0x510e527fade682d1u64,
    0x9b05688c2b3e6c1fu64,
    0x1f83d9abfb41bd6bu64,
    0x5be0cd19137e2179u64,
];

#[wrappit]
fn mix(v: [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) -> [u64; 16] {
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
    let mut result: Counter = [0u64; 2];
    result[0] = t[0] + x;
    if result[0] < x {
        result[1] = t[1] + 1;
    }
    result
}

fn make_u64array(h: Buffer) -> [u64; 16] {
    let mut result: [u64; 16] = [0; 16];
    for i in 0..16 {
        result[i] = h[0 + 8 * i] as u64
            | (h[1 + 8 * i] as u64) << 8
            | (h[2 + 8 * i] as u64) << 16
            | (h[3 + 8 * i] as u64) << 24
            | (h[4 + 8 * i] as u64) << 32
            | (h[5 + 8 * i] as u64) << 40
            | (h[6 + 8 * i] as u64) << 48
            | (h[7 + 8 * i] as u64) << 56;
    }
    result
}

fn compress(h: [u64; 8], m: Buffer, t: Counter, last_block: bool) -> [u64; 8] {
    let mut v: [u64; 16] = [0; 16];

    // Read u8 data to u64.
    let m = make_u64array(m);

    // Prepare.
    for i in 0..8 {
        v[i] = h[i];
        v[i + 8] = IV[i];
    }
    let foo0: u64 = t[0].into();
    let foo1: u64 = t[1].into();
    v[12] = v[12] ^ foo0;
    v[13] = v[13] ^ foo1;
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

    let mut compressed = [0u64; 8];
    for i in 0..8 {
        compressed[i] = h[i] ^ v[i] ^ v[i + 8];
    }
    compressed
}

pub fn blake2b(data: Bytes) -> Digest {
    let mut h = IV;
    // This only supports the 512 version without key.
    h[0] = h[0] ^ 0x01010000 ^ 64;

    let mut t: Counter = [0; 2];
    let blocks = data.len() / 128;
    for i in 0..blocks {
        let m = Buffer::from(&data[0 + i * 128..0 + i * 128 + 128]);
        t = inc_counter(t, 128);
        h = compress(h, m, t, false);
    }

    // Pad last bits of data to a full block.
    let mut m = Buffer::new();
    let remaining_bytes = data.len() - 128 * blocks;
    let remaining_start = data.len() - remaining_bytes;
    t = inc_counter(t, remaining_bytes as u64);
    let mut j = 0;
    for i in remaining_start..(remaining_start + remaining_bytes) {
        m[j] = data[i];
        j += 1;
    }
    h = compress(h, m, t, true);
    h.into()
}
