use hacspec::*;

type State = [u32; 16];
type Key = [u8; 32];
type IV = [u8; 12];

fn state_to_bytes(x: &State) -> [u8; 64] {
    let mut r: [u8; 64] = [0; 64];
    for i in 0..x.len() {
        let bytes = from_u32l(&x[i]);
        r[i * 4] = bytes.3;
        r[i * 4 + 1] = bytes.2;
        r[i * 4 + 2] = bytes.1;
        r[i * 4 + 3] = bytes.0;
    }
    r
}

fn line(a: usize, b: usize, d: usize, s: usize, m: &mut State) {
    m[a] = m[a].wrapping_add(m[b]);
    m[d] = m[d] ^ m[a];
    m[d] = m[d] << s | m[d] >> (32 - s);
}

fn quarter_round(a: usize, b: usize, c: usize, d: usize, m: &mut State) {
    line(a, b, d, 16, m);
    line(c, d, b, 12, m);
    line(a, b, d, 8, m);
    line(c, d, b, 7, m);
}

fn double_round(m: &mut State) {
    quarter_round(0, 4, 8, 12, m);
    quarter_round(1, 5, 9, 13, m);
    quarter_round(2, 6, 10, 14, m);
    quarter_round(3, 7, 11, 15, m);

    quarter_round(0, 5, 10, 15, m);
    quarter_round(1, 6, 11, 12, m);
    quarter_round(2, 7, 8, 13, m);
    quarter_round(3, 4, 9, 14, m);
}

fn block_init(key: &Key, ctr: u32, iv: &IV) -> State {
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

fn block_inner(key: &Key, ctr: u32, iv: &IV) -> State {
    let st = block_init(key, ctr, iv);
    let mut state = st;
    for _ in 0..10 {
        double_round(&mut state);
    }
    for i in 0..16 {
        state[i] = state[i].wrapping_add(st[i]);
    }
    state
}

fn block(key: &Key, ctr: u32, iv: &IV) -> [u8; 64] {
    let state = block_inner(key, ctr, iv);
    state_to_bytes(&state)
}

pub fn chacha(key: &Key, iv: &IV, m: &[u8]) -> Result<Vec<u8>, String> {
    let l = m.len();
    let nblocks: usize = l / 64; // TODO: floor
    let rem = l % 64;
    let mut ctr = 1;
    let mut blocks_out = Vec::new();
    blocks_out.extend_from_slice(m);
    for i in 0..nblocks {
        let keyblock = block(key, ctr, iv);
        for j in 0..64 {
            let k = (i * 64) + j;
            blocks_out[k] = m[k] ^ keyblock[j];
        }
        ctr += 1;
    }
    // Last block might not be full
    if rem != 0 {
        let keyblock = block(key, ctr, iv);
        for i in 0..rem {
            let k = (nblocks * 64) + i;
            blocks_out[k] = m[k] ^ keyblock[i];
        }
    }
    Ok(blocks_out)
}

#[test]
fn test_quarter_round() {
    let mut state = [
        0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
        0x2a5f714c, 0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0x3d631689,
        0x2098d9d6, 0x91dbd320,
    ];
    let expected_state = [
        0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
        0xcfacafd2, 0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0xccc07c79,
        0x2098d9d6, 0x91dbd320,
    ];
    quarter_round(2, 7, 8, 13, &mut state);
    assert_eq!(state[..], expected_state[..]);
}

#[test]
fn test_block() {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let iv = [
        00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];
    let ctr: u32 = 1;
    let state = block_init(&key, ctr, &iv);
    let expected_state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
        0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
        0x4a000000, 0x00000000,
    ];
    assert_eq!(state[..], expected_state[..]);

    let state = block_inner(&key, ctr, &iv);
    let expected_state = [
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3, 0xc7f4d1c7, 0x0368c033, 0x9aaa2204,
        0x4e6cd4c3, 0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9, 0xd19c12b5, 0xb94e16de,
        0xe883d0cb, 0x4e3c50a2,
    ];
    assert_eq!(state[..], expected_state[..]);

    let expected_serialised = [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71,
        0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4,
        0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9,
        0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8,
        0xa2, 0x50, 0x3c, 0x4e,
    ];
    let serialised = state_to_bytes(&state);
    println!("{:?}", serialised.len());
    assert_eq!(serialised[..], expected_serialised[..]);
}
