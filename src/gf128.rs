// Import hacspec and all needed definitions.
use hacspec::*;
hacspec_imports!();

// Get Key, Block, and BLOCKSIZE types
// use crate::aes::{Key, Block};

const BLOCKSIZE: usize = 16;
// TODO: these should all cast to each other without into
bytes!(Block, BLOCKSIZE);
bytes!(Key, BLOCKSIZE);
bytes!(Tag, BLOCKSIZE);

// TODO: Use a 128-bit uint_n instead?
type Element = u128;
const IRRED: Element = 0xE1000000000000000000000000000000;

fn fadd(x: Element, y: Element) -> Element {
    x ^ y
}

fn fmul(x: Element, y: Element) -> Element {
    let mut res: Element = 0;
    let mut sh = x;
    for i in 0..128 {
        if y & (1 << (127 - i)) != 0 {
            res ^= sh;
        }
        if sh & 1 != 0 {
            sh = (sh >> 1) ^ IRRED;
        } else {
            sh = sh >> 1;
        }
    }
    res
}

// GMAC

// TODO: block is actually subblock
fn encode(block: Block) -> Element {
    let mut i : [u8; 16] = [0; 16];
    i.copy_from_slice(&block.iter().map(|x| U8::declassify(*x)).collect::<Vec<_>>());
    Element::from_be_bytes(i)
}

fn decode(e: Element) -> Block {
    Block::from(U128::to_bytes_be(&[U128(e)]))
}

// TODO: block is actually subblock
fn update(r: Element, block: Block, acc: Element) -> Element {
    fmul(fadd(encode(block), acc), r)
}

fn poly(msg: Bytes, r: Element) -> Element {
    let l = msg.len();
    let n_blocks: usize = l / BLOCKSIZE;
    let rem = l % BLOCKSIZE;
    let mut acc = 0;
    for i in 0..n_blocks {
        let k = i * BLOCKSIZE;
        acc = update(r, Block::from_sub_pad(msg.clone(), k..k + BLOCKSIZE), acc);
    }
    if rem != 0 {
        let k = n_blocks * BLOCKSIZE;
        let mut last_block = Block::new();
        last_block = last_block.update_sub(0, msg.clone(), k, rem);
        acc = update(r, last_block, acc);
    }
    acc
}

pub fn gmac(text: Bytes, k: Key) -> Tag {
    let s = Block::new();
    let r = encode(Block::copy(k));
    let a = poly(text, r);
    Tag::copy(decode(fadd(a, encode(s))))
}
