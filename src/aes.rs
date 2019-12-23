// Import hacspec and all needed definitions.
use hacspec::*;
hacspec_imports!();
// TODO: move to hacspec_imports if we want to use it!
use contracts::*;

const BLOCKSIZE: usize = 16;
const IVSIZE: usize = 12;

bytes!(Block, BLOCKSIZE);
bytes!(Word, 4);
bytes!(Key, BLOCKSIZE);
bytes!(Nonce, IVSIZE);
bytes!(SBox, 256);
bytes!(RCon, 11);

bytes!(Bytes144, 144);
bytes!(Bytes176, 176);

#[rustfmt::skip]
const SBOX: SBox = SBox([
    U8(0x63), U8(0x7C), U8(0x77), U8(0x7B), U8(0xF2), U8(0x6B), U8(0x6F), U8(0xC5),
    U8(0x30), U8(0x01), U8(0x67), U8(0x2B), U8(0xFE), U8(0xD7), U8(0xAB), U8(0x76),
    U8(0xCA), U8(0x82), U8(0xC9), U8(0x7D), U8(0xFA), U8(0x59), U8(0x47), U8(0xF0),
    U8(0xAD), U8(0xD4), U8(0xA2), U8(0xAF), U8(0x9C), U8(0xA4), U8(0x72), U8(0xC0),
    U8(0xB7), U8(0xFD), U8(0x93), U8(0x26), U8(0x36), U8(0x3F), U8(0xF7), U8(0xCC),
    U8(0x34), U8(0xA5), U8(0xE5), U8(0xF1), U8(0x71), U8(0xD8), U8(0x31), U8(0x15),
    U8(0x04), U8(0xC7), U8(0x23), U8(0xC3), U8(0x18), U8(0x96), U8(0x05), U8(0x9A),
    U8(0x07), U8(0x12), U8(0x80), U8(0xE2), U8(0xEB), U8(0x27), U8(0xB2), U8(0x75),
    U8(0x09), U8(0x83), U8(0x2C), U8(0x1A), U8(0x1B), U8(0x6E), U8(0x5A), U8(0xA0),
    U8(0x52), U8(0x3B), U8(0xD6), U8(0xB3), U8(0x29), U8(0xE3), U8(0x2F), U8(0x84),
    U8(0x53), U8(0xD1), U8(0x00), U8(0xED), U8(0x20), U8(0xFC), U8(0xB1), U8(0x5B),
    U8(0x6A), U8(0xCB), U8(0xBE), U8(0x39), U8(0x4A), U8(0x4C), U8(0x58), U8(0xCF),
    U8(0xD0), U8(0xEF), U8(0xAA), U8(0xFB), U8(0x43), U8(0x4D), U8(0x33), U8(0x85),
    U8(0x45), U8(0xF9), U8(0x02), U8(0x7F), U8(0x50), U8(0x3C), U8(0x9F), U8(0xA8),
    U8(0x51), U8(0xA3), U8(0x40), U8(0x8F), U8(0x92), U8(0x9D), U8(0x38), U8(0xF5),
    U8(0xBC), U8(0xB6), U8(0xDA), U8(0x21), U8(0x10), U8(0xFF), U8(0xF3), U8(0xD2),
    U8(0xCD), U8(0x0C), U8(0x13), U8(0xEC), U8(0x5F), U8(0x97), U8(0x44), U8(0x17),
    U8(0xC4), U8(0xA7), U8(0x7E), U8(0x3D), U8(0x64), U8(0x5D), U8(0x19), U8(0x73),
    U8(0x60), U8(0x81), U8(0x4F), U8(0xDC), U8(0x22), U8(0x2A), U8(0x90), U8(0x88),
    U8(0x46), U8(0xEE), U8(0xB8), U8(0x14), U8(0xDE), U8(0x5E), U8(0x0B), U8(0xDB),
    U8(0xE0), U8(0x32), U8(0x3A), U8(0x0A), U8(0x49), U8(0x06), U8(0x24), U8(0x5C),
    U8(0xC2), U8(0xD3), U8(0xAC), U8(0x62), U8(0x91), U8(0x95), U8(0xE4), U8(0x79),
    U8(0xE7), U8(0xC8), U8(0x37), U8(0x6D), U8(0x8D), U8(0xD5), U8(0x4E), U8(0xA9),
    U8(0x6C), U8(0x56), U8(0xF4), U8(0xEA), U8(0x65), U8(0x7A), U8(0xAE), U8(0x08),
    U8(0xBA), U8(0x78), U8(0x25), U8(0x2E), U8(0x1C), U8(0xA6), U8(0xB4), U8(0xC6),
    U8(0xE8), U8(0xDD), U8(0x74), U8(0x1F), U8(0x4B), U8(0xBD), U8(0x8B), U8(0x8A),
    U8(0x70), U8(0x3E), U8(0xB5), U8(0x66), U8(0x48), U8(0x03), U8(0xF6), U8(0x0E),
    U8(0x61), U8(0x35), U8(0x57), U8(0xB9), U8(0x86), U8(0xC1), U8(0x1D), U8(0x9E),
    U8(0xE1), U8(0xF8), U8(0x98), U8(0x11), U8(0x69), U8(0xD9), U8(0x8E), U8(0x94),
    U8(0x9B), U8(0x1E), U8(0x87), U8(0xE9), U8(0xCE), U8(0x55), U8(0x28), U8(0xDF),
    U8(0x8C), U8(0xA1), U8(0x89), U8(0x0D), U8(0xBF), U8(0xE6), U8(0x42), U8(0x68),
    U8(0x41), U8(0x99), U8(0x2D), U8(0x0F), U8(0xB0), U8(0x54), U8(0xBB), U8(0x16),
]);

#[rustfmt::skip]
const RCON: RCon = RCon([
    U8(0x8d), U8(0x01), U8(0x02), U8(0x04), U8(0x08), U8(0x10), U8(0x20), U8(0x40),
    U8(0x80), U8(0x1b), U8(0x36),
]);

fn sub_bytes(state: Block) -> Block {
    let mut st = state;
    for i in 0..16 {
        st[i] = SBOX[U8::declassify(state[i]) as usize];
    }
    st
}

#[pre(i < 4)]
#[pre(shift < 4)]
fn shift_row(i: usize, shift: usize, state: Block) -> Block {
    let mut out = state;
    out[i] = state[i + (4 * (shift % 4))];
    out[i + 4] = state[i + (4 * ((shift + 1) % 4))];
    out[i + 8] = state[i + (4 * ((shift + 2) % 4))];
    out[i + 12] = state[i + (4 * ((shift + 3) % 4))];
    out
}

fn shift_rows(state: Block) -> Block {
    let state = shift_row(1, 1, state);
    let state = shift_row(2, 2, state);
    shift_row(3, 3, state)
}

fn xtime(x: U8) -> U8 {
    let x1 = x << 1;
    let x7 = x >> 7;
    let x71 = x7 & U8(1);
    let x711b = x71 * U8(0x1b);
    x1 ^ x711b
}

#[pre(c < 4)]
fn mix_column(c: usize, state: Block) -> Block {
    let i0 = 4 * c;
    let s0 = state[i0];
    let s1 = state[i0 + 1];
    let s2 = state[i0 + 2];
    let s3 = state[i0 + 3];
    let mut st = state;
    let tmp = s0 ^ s1 ^ s2 ^ s3;
    st[i0] = s0 ^ tmp ^ (xtime(s0 ^ s1));
    st[i0 + 1] = s1 ^ tmp ^ (xtime(s1 ^ s2));
    st[i0 + 2] = s2 ^ tmp ^ (xtime(s2 ^ s3));
    st[i0 + 3] = s3 ^ tmp ^ (xtime(s3 ^ s0));
    st
}

fn mix_columns(state: Block) -> Block {
    let state = mix_column(0, state);
    let state = mix_column(1, state);
    let state = mix_column(2, state);
    mix_column(3, state)
}

fn add_round_key(state: Block, key: Key) -> Block {
    let mut out = state;
    for i in 0..16 {
        out[i] ^= key[i];
    }
    out
}

fn aes_enc(state: Block, round_key: Key) -> Block {
    let state = sub_bytes(state);
    let state = shift_rows(state);
    let state = mix_columns(state);
    add_round_key(state, round_key)
}

fn aes_enc_last(state: Block, round_key: Key) -> Block {
    let state = sub_bytes(state);
    let state = shift_rows(state);
    add_round_key(state, round_key)
}

fn rounds(state: Block, key: Bytes144) -> Block {
    let mut out = state;
    for i in 0..9 {
        out = aes_enc(out, key.get(16 * i..16 * i + 16));
    }
    out
}

fn block_cipher(input: Block, key: Bytes176) -> Block {
    let k0: Key = key.get(0..16);
    let k: Bytes144 = key.get(16..10 * 16);
    let kn: Key = key.get(10 * 16..11 * 16);
    let state = add_round_key(input, k0);
    let state = rounds(state, k);
    aes_enc_last(state, kn)
}

fn rotate_word(w: Word) -> Word {
    Word([w[1usize], w[2usize], w[3usize], w[0usize]])
}

fn sub_word(w: Word) -> Word {
    Word([
        SBOX[U8::declassify(w[0usize]) as usize],
        SBOX[U8::declassify(w[1usize]) as usize],
        SBOX[U8::declassify(w[2usize]) as usize],
        SBOX[U8::declassify(w[3usize]) as usize],
    ])
}

fn aes_keygen_assist(w: Word, rcon: U8) -> Word {
    let k = rotate_word(w);
    let mut k = sub_word(k);
    k[0] ^= rcon;
    k
}

fn key_expansion_word(w0: Word, w1: Word, i: usize) -> Word {
    assert!(i < 44);
    let mut k = w1;
    if i % 4 == 0 {
        k = aes_keygen_assist(k, RCON[i / 4]);
    }
    for i in 0..4 {
        k[i] ^= w0[i];
    }
    k
}

fn key_expansion(key: Key) -> Bytes176 {
    let mut key_ex = Bytes176::new();
    // TODO: get rid of all `into`
    key_ex.update(0, &key);
    let mut i: usize;
    for j in 0..40 {
        i = j + 4;
        let word = key_expansion_word(
            key_ex.get(4 * i - 16..4 * i - 12),
            key_ex.get(4 * i - 4..4 * i),
            i,
        );
        key_ex.update(4 * i, &word);
    }
    key_ex
}

fn aes128_encrypt_block(k: Key, input: Block) -> Block {
    let key_ex = key_expansion(k);
    block_cipher(input, key_ex)
}

pub(crate) fn aes128_ctr_keyblock(k: Key, n: Nonce, c: U32) -> Block {
    let mut input = Block::new();
    input.update(0, &n);
    input.update(12, &u32_to_be_bytes(c));
    aes128_encrypt_block(k, input)
}

pub(crate) fn xor_block(block: Block, keyblock: Block) -> Block {
    let mut out = block;
    for i in 0..BLOCKSIZE {
        out[i] ^= keyblock[i];
    }
    out
}

fn aes128_counter_mode(key: Key, nonce: Nonce, counter: U32, msg: Bytes) -> Bytes {
    let l = msg.len();
    let n_blocks: usize = l / BLOCKSIZE;
    let rem = l % BLOCKSIZE;
    let mut ctr = counter;
    let mut blocks_out = Bytes::new_len(l);
    for i in 0..n_blocks {
        let keyblock = aes128_ctr_keyblock(key, nonce, ctr);
        let k = i * BLOCKSIZE;
        blocks_out.update(k, &xor_block(msg.get(k..k + BLOCKSIZE), keyblock));
        ctr += U32(1);
    }
    let keyblock = aes128_ctr_keyblock(key, nonce, ctr);
    let k = n_blocks * BLOCKSIZE;
    let mut last_block = Block::new();
    last_block.update_sub(0, &msg, k, rem);
    blocks_out.update_sub(k, &xor_block(last_block, keyblock), 0, rem);
    blocks_out
}

pub fn aes128_encrypt(key: Key, nonce: Nonce, counter: U32, msg: Bytes) -> Bytes {
    aes128_counter_mode(key, nonce, counter, msg)
}

pub fn aes128_decrypt(key: Key, nonce: Nonce, counter: U32, ctxt: Bytes) -> Bytes {
    aes128_counter_mode(key, nonce, counter, ctxt)
}

// Testing some internal functions.

#[test]
#[should_panic]
fn test_contract1() {
    shift_row(4, 3, Block::new());
}

#[test]
#[should_panic]
fn test_contract2() {
    shift_row(2, 4, Block::new());
}

#[test]
fn test_kat_block1() {
    #[rustfmt::skip]
    let msg = Block([
        U8(0x6b), U8(0xc1), U8(0xbe), U8(0xe2), U8(0x2e), U8(0x40), U8(0x9f), U8(0x96),
        U8(0xe9), U8(0x3d), U8(0x7e), U8(0x11), U8(0x73), U8(0x93), U8(0x17), U8(0x2a),
    ]);
    #[rustfmt::skip]
    let key = Key([
        U8(0x2b), U8(0x7e), U8(0x15), U8(0x16), U8(0x28), U8(0xae), U8(0xd2), U8(0xa6),
        U8(0xab), U8(0xf7), U8(0x15), U8(0x88), U8(0x09), U8(0xcf), U8(0x4f), U8(0x3c),
    ]);
    #[rustfmt::skip]
    let ctxt = [
        U8(0x3a), U8(0xd7), U8(0x7b), U8(0xb4), U8(0x0d), U8(0x7a), U8(0x36), U8(0x60),
        U8(0xa8), U8(0x9e), U8(0xca), U8(0xf3), U8(0x24), U8(0x66), U8(0xef), U8(0x97),
    ];

    let c = aes128_encrypt_block(key, msg);
    assert_eq!(
        (&ctxt[..]).iter().map(|x| U8::declassify(*x)).collect::<Vec<_>>(),
        (&c[..]).iter().map(|x| U8::declassify(*x)).collect::<Vec<_>>()
    );
}

#[test]
fn test_kat_block2() {
    #[rustfmt::skip]
    let msg = Block([
        U8(0x53), U8(0x69), U8(0x6e), U8(0x67), U8(0x6c), U8(0x65), U8(0x20), U8(0x62),
        U8(0x6c), U8(0x6f), U8(0x63), U8(0x6b), U8(0x20), U8(0x6d), U8(0x73), U8(0x67),
    ]);
    #[rustfmt::skip]
    let key = Key([
        U8(0xae), U8(0x68), U8(0x52), U8(0xf8), U8(0x12), U8(0x10), U8(0x67), U8(0xcc),
        U8(0x4b), U8(0xf7), U8(0xa5), U8(0x76), U8(0x55), U8(0x77), U8(0xf3), U8(0x9e),
    ]);
    #[rustfmt::skip]
    let ctxt = Bytes::from_array(&[
        U8(0x61), U8(0x5f), U8(0x09), U8(0xfb), U8(0x35), U8(0x3f), U8(0x61), U8(0x3b),
        U8(0xa2), U8(0x8f), U8(0xf3), U8(0xa3), U8(0x0c), U8(0x64), U8(0x75), U8(0x2d),
    ]);
    let c = aes128_encrypt_block(key, msg);
    assert_eq!(
        (&ctxt[..]).iter().map(|x| U8::declassify(*x)).collect::<Vec<_>>(),
        (&c[..]).iter().map(|x| U8::declassify(*x)).collect::<Vec<_>>()
    );
}
