// Import hacspec and all needed definitions.
use hacspec::*;
hacspec_imports!();

// Import aes and gcm
use crate::aes;
use crate::aes::{aes128_ctr_keyblock, aes128_decrypt, aes128_encrypt};
use crate::gf128;
use crate::gf128::{gmac, Tag};

fn pad_aad_msg(aad: ByteSlice, msg: ByteSlice) -> Bytes {
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
    padded_msg.update_slice(0, aad);
    padded_msg.update_slice(pad_aad, msg);
    padded_msg.update_raw(pad_aad + pad_msg, &(laad as u64 * 8).to_be_bytes());
    padded_msg.update_raw(pad_aad + pad_msg + 8, &(lmsg as u64 * 8).to_be_bytes());
    padded_msg
}

// FIXME: fix type conversions :(
pub fn encrypt(key: aes::Key, iv: aes::Nonce, aad: ByteSlice, msg: ByteSlice) -> (Bytes, Tag) {
    let iv0 = aes::Nonce::new();

    let mac_key = aes128_ctr_keyblock(key, iv0, 0);
    let tag_mix = aes128_ctr_keyblock(key, iv, 1);

    let cipher_text = aes128_encrypt(key, iv, 2, msg);
    let padded_msg = pad_aad_msg(aad, cipher_text.get_slice());
    let tag = gmac(padded_msg, mac_key.raw().into());
    let tag = aes::xor_block(tag.raw().into(), tag_mix);

    (cipher_text, tag.raw().into())
}

pub fn decrypt(
    key: aes::Key,
    iv: aes::Nonce,
    aad: ByteSlice,
    cipher_text: ByteSlice,
    tag: Tag,
) -> Result<Bytes, String> {
    let iv0 = aes::Nonce::new();

    let mac_key = aes128_ctr_keyblock(key, iv0, 0);
    let tag_mix = aes128_ctr_keyblock(key, iv, 1);

    let padded_msg = pad_aad_msg(aad, cipher_text);
    let my_tag = gmac(padded_msg, mac_key.raw().into());
    let my_tag = aes::xor_block(my_tag.raw().into(), tag_mix);
    let my_tag: Tag = my_tag.raw().into();

    if my_tag == tag {
        Ok(aes128_decrypt(key, iv, 2, cipher_text))
    } else {
        Err("Mac verification failed".to_string())
    }
}
