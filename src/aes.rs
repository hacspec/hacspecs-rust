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

secret_constant_array!(
    SBOX,
    SBox,
    U8,
    [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB,
        0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4,
        0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71,
        0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
        0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6,
        0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB,
        0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45,
        0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44,
        0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
        0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49,
        0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
        0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25,
        0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E,
        0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1,
        0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB,
        0x16
    ]
);

secret_constant_array!(
    RCON,
    RCon,
    U8,
    [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
);

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
        out = aes_enc(out, Key::from_sub(key, 16 * i..16 * i + 16));
    }
    out
}

fn block_cipher(input: Block, key: Bytes176) -> Block {
    let k0 = Key::from_sub(key, 0..16);
    let k = Bytes144::from_sub(key, 16..10 * 16);
    let kn = Key::from_sub(key, 10 * 16..11 * 16);
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
    key_ex = key_ex.update(0, key);
    let mut i: usize;
    for j in 0..40 {
        i = j + 4;
        let word = key_expansion_word(
            Word::from_sub(key_ex, 4 * i - 16..4 * i - 12),
            Word::from_sub(key_ex, 4 * i - 4..4 * i),
            i,
        );
        key_ex = key_ex.update(4 * i, word);
    }
    key_ex
}

fn aes128_encrypt_block(k: Key, input: Block) -> Block {
    let key_ex = key_expansion(k);
    block_cipher(input, key_ex)
}

pub(crate) fn aes128_ctr_keyblock(k: Key, n: Nonce, c: U32) -> Block {
    let mut input = Block::new();
    input = input.update(0, n);
    input = input.update(12, u32_to_be_bytes(c));
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
        blocks_out = blocks_out.update(
            k,
            xor_block(Block::from_sub_pad(msg.clone(), k..k + BLOCKSIZE), keyblock),
        );
        ctr += U32(1);
    }
    let keyblock = aes128_ctr_keyblock(key, nonce, ctr);
    let k = n_blocks * BLOCKSIZE;
    let mut last_block = Block::new();
    last_block = last_block.update_sub(0, msg, k, rem);
    blocks_out = blocks_out.update_sub(k, xor_block(last_block, keyblock), 0, rem);
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
        (&ctxt[..])
            .iter()
            .map(|x| U8::declassify(*x))
            .collect::<Vec<_>>(),
        (&c[..])
            .iter()
            .map(|x| U8::declassify(*x))
            .collect::<Vec<_>>()
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
        ctxt.iter().map(|x| U8::declassify(*x)).collect::<Vec<_>>(),
        c.iter().map(|x| U8::declassify(*x)).collect::<Vec<_>>()
    );
}
