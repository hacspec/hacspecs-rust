// Import hacspec and all needed definitions.
use hacspec::*;
hacspec_imports!();

// Import chacha20
use crate::chacha20;
use crate::chacha20::*;

const BLOCKSIZE: usize = 16;
// Type definitions for use in poly1305.

// These are type aliases for convenience
bytes!(Block, BLOCKSIZE);

// These are actual types; fixed-length arrays.
array!(Tag, BLOCKSIZE, u8);

// Define the Poly1305 field and field elements.
#[field(3fffffffffffffffffffffffffffffffb)]
struct FieldElement;

fn key_gen(key: Key, iv: IV) -> Key {
    let block = chacha20::block(key, 0, iv);
    block.get(0..32)
}

fn encode_r(r: Block) -> FieldElement {
    let r_uint = r.to_u128_le();
    let r_uint = r_uint & 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff;
    FieldElement::from(r_uint)
}

fn encode(block: Bytes) -> FieldElement {
    let mut block_as_u128 = U128Word::new();
    block_as_u128.update_sub(0, &block, 0, min(16, block.len()));
    let w_elem = FieldElement::from(u128_from_le_bytes(block_as_u128));
    let l_elem = FieldElement::pow2(8 * block.len());
    w_elem + l_elem
}

fn poly_inner(m: Bytes, r: FieldElement) -> FieldElement {
    let mut acc = FieldElement::from(0);
    for i in (0..m.len()).step_by(BLOCKSIZE) {
        let block_len = min(BLOCKSIZE, m.len() - i);
        let mut b = Seq::new_len(block_len);
        b.update_sub(0, &m, i, block_len);
        acc = (acc + encode(b)) * r;
    }
    acc
}

pub fn poly(m: Bytes, key: Key) -> Tag {
    let s_elem = FieldElement::from(u128_from_le_bytes(key.get(BLOCKSIZE..2 * BLOCKSIZE)));
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
