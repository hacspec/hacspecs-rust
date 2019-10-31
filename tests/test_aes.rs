extern crate hacspec;
use hacspec::*;

extern crate hacspecs;
use hacspecs::aes::*;

fn enc_dec_test(m: Bytes, key: Key, iv: Nonce) {
    let c = aes128_encrypt(key, iv, 0, m.clone());
    let m_dec = aes128_decrypt(key, iv, 0, c);
    assert_eq!(m, m_dec);
}

#[test]
fn test_enc_dec() {
    let key = Key::random();
    let iv = Nonce::random();
    let m = Bytes::random(40);
    enc_dec_test(m, key, iv);
}
