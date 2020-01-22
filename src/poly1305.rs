// Import hacspec and all needed definitions.
use hacspec::prelude::*;

// Import chacha20
use crate::chacha20;
use crate::chacha20::*;

const BLOCKSIZE: usize = 16;
// Type definitions for use in poly1305.

// These are type aliases for convenience
type Block = [u8; BLOCKSIZE];

// These are actual types; fixed-length arrays.
bytes!(Tag, BLOCKSIZE);

// Define the Poly1305 field and field elements.
#[field(3fffffffffffffffffffffffffffffffb)]
struct FieldElement;

fn key_gen(key: Key, iv: IV) -> Key {
    let block = chacha20::block(key, 0, iv);
    Key::from_array(block.get(0..32))
}

fn encode_r(r: Block) -> FieldElement {
    let r_uint = u128::from_le_bytes(r);
    let r_uint = r_uint & 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff;
    FieldElement::from(r_uint)
}

fn encode(block: Bytes) -> FieldElement {
    let w_elem = FieldElement::from(block.to_le_uint());
    let l_elem = FieldElement::pow2(8 * block.len());
    w_elem + l_elem
}

fn poly_inner(m: Bytes, r: FieldElement) -> FieldElement {
    let blocks = m.split(BLOCKSIZE);
    let mut acc = FieldElement::from(0);
    for b in blocks {
        acc = (acc + encode(b)) * r;
    }
    acc
}

pub fn poly(m: Bytes, key: Key) -> Tag {
    let s_elem = FieldElement::from(u128::from_le_bytes(key.get(BLOCKSIZE..2 * BLOCKSIZE)));
    let r_elem = encode_r(key.get(0..BLOCKSIZE));
    let a = poly_inner(m, r_elem);
    let n = a + s_elem;
    // Note that n might be less than 16 byte -> zero-pad; but might also be
    // larger than Tag::capacity().
    Tag::from_vec_lazy(n.to_bytes_le())
}

pub fn poly_mac(m: Bytes, key: Key, iv: IV) -> Tag {
    let mac_key = key_gen(key, iv);
    poly(m, mac_key)
}
