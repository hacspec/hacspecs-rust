// Import all hacspec definitions.
use hacspec::*;
// hacspec_imports!();
// TODO: simplify
extern crate uint;
use self::uint::*;
use std::{fmt, cmp::PartialEq};

// Import chacha20
use crate::chacha20;
use crate::chacha20::*;

// Type definitions for use in poly1305.

// These are type aliases for convenience
type Block = [u8; 16];

// These are actual types; fixed-length arrays.
bytes!(Tag, 16);

const BLOCKSIZE: usize = 16;

// Define the field mod 2^130-5
// define_abstract_integer_checked!(OneThreeOne, 260);
// define_refined_modular_integer!(
//     FieldElement,
//     OneThreeOne,
//     OneThreeOne::pow2(130) - OneThreeOne::from_literal(5)
// );
#[field(3fffffffffffffffffffffffffffffffb)]
struct FieldElement;


fn key_gen(key: Key, iv: IV) -> Key {
    let block = chacha20::block(key, 0, iv);
    Key::from_slice(&block[0..32])
}

fn encode_r(r: Block) -> FieldElement {
    let r_uint = u128::from_le_bytes(r);
    let r_uint = r_uint & 0x0ffffffc0ffffffc0ffffffc0fffffffu128;
    FieldElement::from_literal(r_uint)
}

// TODO: to_u128l isn't cool
fn encode(block: Bytes) -> FieldElement {
    let w_elem = FieldElement::from_literal(block.to_u128l());
    let l_elem = FieldElement::pow2(8 * block.len());
    w_elem + l_elem
}

fn poly_inner(m: Bytes, r: FieldElement) -> FieldElement {
    let blocks = m.split(BLOCKSIZE);
    let mut acc = FieldElement::from_literal(0);
    for b in blocks {
        acc = (acc + encode(b)) * r;
    }
    acc
}

fn poly(m: Bytes, key: Key) -> Tag {
    let r = to_array(&key[0..BLOCKSIZE]);
    let s = to_array(&key[BLOCKSIZE..2 * BLOCKSIZE]);
    let s_elem = FieldElement::from_literal(u128::from_le_bytes(s));
    let r_elem = encode_r(r);
    let a = poly_inner(m, r_elem);
    let n = a + s_elem;
    Tag::from_slice(&n.to_bytes_le()[0..16])
}

fn poly_mac(m: Bytes, key: Key, iv: IV) -> Tag {
    let mac_key = key_gen(key, iv);
    poly(m, mac_key)
}

#[test]
fn foo_test() {
    let key = Key::random();
    let iv = IV::random();
    let m = Bytes::random(40);
    poly_mac(m, key, iv);

    // RFC 7539 Test Vectors
    let msg = Bytes::from_array(&[
        0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x46,
        0x6f, 0x72, 0x75, 0x6d, 0x20, 0x52, 0x65, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x20, 0x47,
        0x72, 0x6f, 0x75, 0x70,
    ]);
    let k = Key::from_array([
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
        0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
        0xf5, 0x1b,
    ]);
    let expected = Tag::from_array([
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27,
        0xa9,
    ]);
    let computed = poly(msg, k);
    assert_eq!(expected, computed);
}
