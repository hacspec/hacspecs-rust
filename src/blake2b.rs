// Import hacspec and all needed definitions.
use hacspec::prelude::*;

enum BlakeAlg {
    Blake2b,
    Blake2s,
}

use std::ops::{Add, BitXor, Div, Mul, Sub};

pub trait MachineInteger:
    BitXor<Self, Output = Self>
    + BitOr<Self, Output = Self>
    + Add<Self, Output = Self>
    + Shl<u32, Output = Self>
    + Shr<u32, Output = Self>
    + Sized
    + Default
    + From<u8>
    + Not<Output = Self>
{
    const ZERO: Self;
    const NUM_BITS: u32;
    fn rotate_right(self, r: u32) -> Self;
    fn to_U8(self) -> U8;
    fn to_U32(self) -> U32;
    fn to_U64(self) -> U64;
    fn from_U8(v: U8) -> Self;
    fn from_U32(v: U32) -> Self;
    fn from_U64(v: U64) -> Self;
    fn cast<T: MachineInteger>(self) -> T;
}

impl MachineInteger for U32 {
    const ZERO: Self = Self(0);
    const NUM_BITS: u32 = 32;
    fn rotate_right(self, r: u32) -> Self {
        Self::rotate_right(self, r)
    }
    fn to_U8(self) -> U8 {
        self.into()
    }
    fn to_U32(self) -> U32 {
        self
    }
    fn to_U64(self) -> U64 {
        self.into()
    }
    fn from_U8(v: U8) -> Self {
        Self(v.declassify() as u32)
    }
    fn from_U32(v: U32) -> Self {
        v
    }
    fn from_U64(v: U64) -> Self {
        Self(v.declassify() as u32)
    }
    fn cast<T: MachineInteger>(self) -> T {
        match T::NUM_BITS {
            32 => T::from_U32(self),
            64 => T::from_U64(self.into()),
            _ => panic!("Unknown cast"),
        }
    }
}

impl MachineInteger for U64 {
    const ZERO: Self = Self(0);
    const NUM_BITS: u32 = 64;
    fn rotate_right(self, r: u32) -> Self {
        Self::rotate_right(self, r)
    }
    fn to_U8(self) -> U8 {
        self.into()
    }
    fn to_U32(self) -> U32 {
        self.into()
    }
    fn to_U64(self) -> U64 {
        self.into()
    }
    fn from_U8(v: U8) -> Self {
        Self(v.declassify() as u64)
    }
    fn from_U32(v: U32) -> Self {
        Self(v.declassify() as u64)
    }
    fn from_U64(v: U64) -> Self {
        v
    }
    fn cast<T: MachineInteger>(self) -> T {
        match T::NUM_BITS {
            32 => T::from_U32(self.into()),
            64 => T::from_U64(self.into()),
            _ => panic!("Unknown cast"),
        }
    }
}

impl MachineInteger for U128 {
    const ZERO: Self = Self(0);
    const NUM_BITS: u32 = 128;
    fn rotate_right(self, r: u32) -> Self {
        Self::rotate_right(self, r)
    }
    fn to_U8(self) -> U8 {
        self.into()
    }
    fn to_U32(self) -> U32 {
        self.into()
    }
    fn to_U64(self) -> U64 {
        self.into()
    }
    fn from_U8(v: U8) -> Self {
        Self(v.declassify() as u128)
    }
    fn from_U32(v: U32) -> Self {
        Self(v.declassify() as u128)
    }
    fn from_U64(v: U64) -> Self {
        Self(v.declassify() as u128)
    }
    fn cast<T: MachineInteger>(self) -> T {
        match T::NUM_BITS {
            32 => T::from_U32(self.into()),
            64 => T::from_U64(self.into()),
            _ => panic!("Unknown cast"),
        }
    }
}

type State<T: MachineInteger> = [T; 8];
type DoubleState<T: MachineInteger> = [T; 16];
// array!(State<T: MachineInteger>, 8, T);
// array!(DoubleState, 16, MachineInteger);
// array!(Counter, 2, u64);

type X = Seq<u8>;
array!(Key, 8, X);

bytes!(Buffer, 128);
bytes!(Digest, 64);
array!(Sigma, 16 * 12, usize);

const SIGMA: Sigma = Sigma([
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2,
    11, 7, 5, 3, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4, 7, 9, 3, 1, 13, 12, 11, 14,
    2, 6, 5, 10, 4, 0, 15, 8, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13, 2, 12, 6, 10,
    0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7,
    1, 4, 10, 5, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8,
    9, 10, 11, 12, 13, 14, 15, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
]);

const IV_Blake2b: State<U64> = secret_array!(
    U64,
    [
        0x6a09_e667_f3bc_c908u64,
        0xbb67_ae85_84ca_a73bu64,
        0x3c6e_f372_fe94_f82bu64,
        0xa54f_f53a_5f1d_36f1u64,
        0x510e_527f_ade6_82d1u64,
        0x9b05_688c_2b3e_6c1fu64,
        0x1f83_d9ab_fb41_bd6bu64,
        0x5be0_cd19_137e_2179u64
    ]
);

const IV_Blake2s: State<U32> = secret_array!(
    U32,
    [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19
    ]
);

fn mix<T: MachineInteger>(
    v: DoubleState<T>,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: T,
    y: T,
) -> DoubleState<T> {
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

// TODO: move to library
fn make_Tarray<T: MachineInteger>(h: Buffer) -> DoubleState<T> {
    let mut result = DoubleState::default();
    match T::NUM_BITS {
        32 => {
            for i in 0..8 {
                result[i] = T::from_U8(h[8 * i])
                    | T::from_U8(h[1 + 8 * i]) << 8
                    | T::from_U8(h[2 + 8 * i]) << 16
                    | T::from_U8(h[3 + 8 * i]) << 24;
            }
        }
        64 => {
            for i in 0..16 {
                result[i] = T::from_U8(h[8 * i])
                    | T::from_U8(h[1 + 8 * i]) << 8
                    | T::from_U8(h[2 + 8 * i]) << 16
                    | T::from_U8(h[3 + 8 * i]) << 24
                    | T::from_U8(h[4 + 8 * i]) << 32
                    | T::from_U8(h[5 + 8 * i]) << 40
                    | T::from_U8(h[6 + 8 * i]) << 48
                    | T::from_U8(h[7 + 8 * i]) << 56;
            }
        }
        _ => panic!("Ughhh"),
    }
    result
}

fn get_num_loops(alg: BlakeAlg) -> usize {
    match alg {
        BlakeAlg::Blake2b => 12,
        BlakeAlg::Blake2s => 10,
    }
}

// fstar: ...
// cryptol: ...
fn compress<T: MachineInteger, U: MachineInteger>(
    alg: BlakeAlg,
    h: State<T>,
    m: Buffer,
    t: U,
    last_block: bool,
) -> State<T> {
    let mut v = DoubleState::default();

    // Read u8 data to u64.
    let m = make_Tarray(m);

    // Prepare.
    v = v.update_sub(0, h, 0, 8);
    v = v.update_sub(8, IV, 0, 8);
    v[12] = v[12] ^ t.cast();
    v[13] = v[13] ^ (t >> U::NUM_BITS).cast();
    if last_block {
        v[14] = !v[14];
    }

    let l = get_num_loops(alg);

    // Mixing.
    for i in 0..l {
        v = mix(v, 0, 4, 8, 12, m[SIGMA[i * 16 + 0]], m[SIGMA[i * 16 + 1]]);
        v = mix(v, 1, 5, 9, 13, m[SIGMA[i * 16 + 2]], m[SIGMA[i * 16 + 3]]);
        v = mix(v, 2, 6, 10, 14, m[SIGMA[i * 16 + 4]], m[SIGMA[i * 16 + 5]]);
        v = mix(v, 3, 7, 11, 15, m[SIGMA[i * 16 + 6]], m[SIGMA[i * 16 + 7]]);
        v = mix(v, 0, 5, 10, 15, m[SIGMA[i * 16 + 8]], m[SIGMA[i * 16 + 9]]);
        v = mix(
            v,
            1,
            6,
            11,
            12,
            m[SIGMA[i * 16 + 10]],
            m[SIGMA[i * 16 + 11]],
        );
        v = mix(v, 2, 7, 8, 13, m[SIGMA[i * 16 + 12]], m[SIGMA[i * 16 + 13]]);
        v = mix(v, 3, 4, 9, 14, m[SIGMA[i * 16 + 14]], m[SIGMA[i * 16 + 15]]);
    }

    let mut compressed = State::default();
    for i in 0..8 {
        compressed[i] = h[i] ^ v[i] ^ v[i + 8];
    }
    compressed
}

// TODO: move to library
fn get_byte<T: MachineInteger>(x: T, i: usize) -> U8 {
    match i {
        0 => U8::from(x & T(0xFF)),
        1 => U8::from((x & T(0xFF00)) >> 8),
        2 => U8::from((x & T(0xFF0000)) >> 16),
        3 => U8::from((x & T(0xFF000000)) >> 24),
        4 => U8::from((x & T(0xFF00000000)) >> 32),
        5 => U8::from((x & T(0xFF0000000000)) >> 40),
        6 => U8::from((x & T(0xFF000000000000)) >> 48),
        7 => U8::from((x & T(0xFF00000000000000)) >> 56),
        _ => U8(0),
    }
}

fn get_chunks(l: usize, block_size: usize) -> usize {
    div_ceil(l, block_size) as usize
}

fn get_chunk(data: ByteSeq, i: usize, block_size: usize) -> Buffer {
    Buffer::from(&data[i*block_size..i*block_size+block_size])
}

fn get_last_chunk(data: ByteSeq, i: usize, block_size: usize) -> Buffer {
    Buffer::from(&data[i*block_size..data.len()])
}

fn get_last_chunk_len(data: ByteSeq, i: usize, block_size: usize) -> u8 {
    (data.len() - (i * block_size)) as u8
}

fn blake2_update<T: MachineInteger, U: MachineInteger>(alg: BlakeAlg, data: ByteSeq, state: State<T>) {
    let mut t = U::default();
    let c = get_chunks(data.len(), 128);
    for i in 0..c-1 {
        t = t + U::from(128);
        state = compress(alg, state, get_chunk(data, i, 128), t, false);
    }
    t = t + U::from(get_last_chunk_len(data, c-1, 128));
    state = compress(alg, state, get_last_chunk(data, c-1, 128), t, true);
}

pub fn blake2b(data: ByteSeq, _k: ByteSeq) -> Digest64 {
    let mut h = IV;
    // This only supports the 512 version without key.
    h[0] = h[0] ^ U64(0x0101_0000) ^ U64(64);

    blake2_update(BlakeAlg::Blake2b, data, 64);

    // We transform 8*u64 into 64*u8
    let mut d = Digest::new();
    for i in 0..8 {
        for j in 0..8 {
            d[i * 8 + j] = get_byte(h[i], j);
        }
    }
    d
}

pub fn blake2s(data: ByteSeq, _k: ByteSeq) -> Digest32 {
    blake2(BlakeAlg::Blake2s, data, 32)
}
