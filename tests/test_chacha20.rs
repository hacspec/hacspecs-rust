use hacspec::prelude::*;

extern crate hacspecs;
use hacspecs::chacha20::*;

#[test]
fn test_quarter_round() {
    let mut state = [
        0x8795_31e0, 0xc5ec_f37d, 0x5164_61b1, 0xc9a6_2f8a, 0x44c2_0ef3, 0x3390_af7f, 0xd9fc_690b,
        0x2a5f_714c, 0x5337_2767, 0xb00a_5631, 0x974c_541a, 0x359e_9963, 0x5c97_1061, 0x3d63_1689,
        0x2098_d9d6, 0x91db_d320,
    ];
    let expected_state = [
        0x8795_31e0, 0xc5ec_f37d, 0xbdb8_86dc, 0xc9a6_2f8a, 0x44c2_0ef3, 0x3390_af7f, 0xd9fc_690b,
        0xcfac_afd2, 0xe46b_ea80, 0xb00a_5631, 0x974c_541a, 0x359e_9963, 0x5c97_1061, 0xccc0_7c79,
        0x2098_d9d6, 0x91db_d320,
    ];
    state = quarter_round(2, 7, 8, 13, state);
    assert_eq!(state[..], expected_state[..]);
}

#[test]
fn test_block() {
    let key = Key::from([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ]);
    let iv = IV::from([
        00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ]);
    let ctr: u32 = 1;
    let state = block_init(key, ctr, iv);
    let expected_state = [
        0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574, 0x0302_0100, 0x0706_0504, 0x0b0a_0908,
        0x0f0e_0d0c, 0x1312_1110, 0x1716_1514, 0x1b1a_1918, 0x1f1e_1d1c, 0x0000_0001, 0x0900_0000,
        0x4a00_0000, 0x0000_0000,
    ];
    assert_eq!(state[..], expected_state[..]);

    let state = block_inner(key, ctr, iv);
    let expected_state = [
        0xe4e7_f110, 0x1559_3bd1, 0x1fdd_0f50, 0xc471_20a3, 0xc7f4_d1c7, 0x0368_c033, 0x9aaa_2204,
        0x4e6c_d4c3, 0x4664_82d2, 0x09aa_9f07, 0x05d7_c214, 0xa202_8bd9, 0xd19c_12b5, 0xb94e_16de,
        0xe883_d0cb, 0x4e3c_50a2,
    ];
    assert_eq!(state[..], expected_state[..]);

    let expected_serialised = [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71,
        0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4,
        0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9,
        0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8,
        0xa2, 0x50, 0x3c, 0x4e,
    ];
    let serialised = state_to_bytes(state);
    println!("{:?}", serialised.len());
    assert_eq!(serialised[..], expected_serialised[..]);
}

fn enc_dec_test(m: Bytes, key: Key, iv: IV) {
    let c = chacha(key, iv, m.clone()).unwrap();
    let m_dec = chacha(key, iv, c).unwrap();
    assert_eq!(m, m_dec);
}

fn kat_test(m: Bytes, key: Key, iv: IV, exp_cipher: Bytes, valid: bool) {
    let enc = chacha(key, iv, m.clone());
    assert!(enc.is_ok() == valid);
    if !valid {
        return;
    }
    let c = enc.unwrap();
    assert_eq!(exp_cipher, c);
    let m_dec = chacha(key, iv, c).unwrap();
    assert_eq!(m, m_dec);
}

#[test]
fn test_enc_dec() {
    let key = Key::random();
    let iv = IV::random();
    let m = Bytes::random(40);
    enc_dec_test(m, key, iv);
}

#[test]
fn test_kat() {
    let key = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    let iv = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];
    let m = [
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74,
        0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c,
        0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20,
        0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79,
        0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70,
        0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65,
        0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75,
        0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69, 0x74, 0x2e,
    ];
    let exp_cipher = vec![
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e,
        0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee,
        0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda,
        0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
        0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae,
        0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85,
        0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5,
        0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
    ];
    kat_test(m[..].into(), key.into(), iv.into(), exp_cipher.into(), true);
}
