// Import hacspec and all needed definitions.
use hacspec::*;
hacspec_imports!();

// Import aes and gcm
use crate::aes;
use crate::aes::{aes128_ctr_keyblock, aes128_encrypt, aes128_decrypt, Block};
use crate::gf128::{gmac, Tag, Key};

fn pad_aad_msg(aad: Bytes, msg: Bytes) -> Bytes {
    let laad = aad.len();
    let lmsg = msg.len();
    let pad_aad = if laad % 16 == 0 {
        laad
    } else {
        laad + (16 - (laad % 16))
    };
    let pad_msg = if lmsg % 16 == 0 {
        lmsg
    } else {
        lmsg + (16 - (lmsg % 16))
    };
    let mut padded_msg = Bytes::new_len(pad_aad + pad_msg + 16);
    padded_msg.update(0, &aad);
    padded_msg.update(pad_aad, &msg);
    padded_msg.update(pad_aad + pad_msg, &u64_to_be_bytes(laad as u64 * 8));
    padded_msg.update(pad_aad + pad_msg + 8, &u64_to_be_bytes(lmsg as u64 * 8));
    padded_msg
}

// FIXME: fix type conversions :(
pub fn encrypt(key: aes::Key, iv: aes::Nonce, aad: Bytes, msg: Bytes) -> (Bytes, Tag) {
    let iv0 = aes::Nonce::new();

    let mac_key = aes128_ctr_keyblock(key, iv0, 0);
    let tag_mix = aes128_ctr_keyblock(key, iv, 1);

    let cipher_text = aes128_encrypt(key, iv, 2, msg);
    let padded_msg = pad_aad_msg(aad, cipher_text.clone());
    let tag = gmac(padded_msg, Key::from_exact_seq(&mac_key));
    let tag = aes::xor_block(Block::from_exact_seq(&tag), tag_mix);

    (cipher_text, Tag::from_exact_seq(&tag))
}

pub fn decrypt(
    key: aes::Key,
    iv: aes::Nonce,
    aad: Bytes,
    cipher_text: Bytes,
    tag: Tag,
) -> Result<Bytes, String> {
    let iv0 = aes::Nonce::new();

    let mac_key = aes128_ctr_keyblock(key, iv0, 0);
    let tag_mix = aes128_ctr_keyblock(key, iv, 1);

    let padded_msg = pad_aad_msg(aad, cipher_text.clone());
    let my_tag = gmac(padded_msg, Key::from_exact_seq(&mac_key));
    let my_tag = aes::xor_block(Block::from_exact_seq(&my_tag), tag_mix);

    if my_tag == Block::from_exact_seq(&tag) {
        Ok(aes128_decrypt(key, iv, 2, cipher_text))
    } else {
        Err("Mac verification failed".to_string())
    }
}
