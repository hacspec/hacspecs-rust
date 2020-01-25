#![allow(dead_code)]

// Import hacspec and all needed definitions.
use hacspec::*;
hacspec_imports!();

// Import primitives
use crate::curve25519;
use crate::sha2;
use crate::hkdf;

bytes!(PK, 32);
bytes!(SK, 32);
bytes!(MD, 32);
bytes!(Key, 32);
type MarshalledPk = [u8; 32];
type Ciphersuite = [u8; 6];

// TODO: ugh, we shouldn't allow derives, but we need it -> add library function for something like this.
#[derive(PartialEq, Copy, Clone)]
enum Mode {
    ModeBase = 0x00,
    ModePsk = 0x01,
    ModeAuth = 0x02,
    ModePskAuth = 0x03,
}

#[derive(PartialEq, Copy, Clone)]
enum Kem {
    DHKEM_P256 = 0x0010,
    DHKEM_P384 = 0x0011,
    DHKEM_P521 = 0x0012,
    DHKEM_25519 = 0x0020,
    DHKEM_448 = 0x0021,
}

#[derive(PartialEq, Copy, Clone)]
enum Kdf {
    HKDF_SHA256 = 0x0001,
    HKDF_SHA384 = 0x0002,
    HKDF_SHA512 = 0x0003,
}

#[derive(PartialEq, Copy, Clone)]
enum Aead {
    AES_GCM_128 = 0x0001,
    AES_GCM_256 = 0x0002,
    CHACHA20_POLY1305 = 0x0003,
}

// TODO ...
bytes!(AAD, 42);
bytes!(PSK, 42);

struct HpkeContext {
    // Mode and algorithms
    mode: Mode,
    kem_id: Kem,
    kdf_id: Kdf,
    aead_id: Aead,

    // Public inputs to this key exchange
    enc: MarshalledPk,
    pk_r: PK,
    pk_i: MarshalledPk,

    // Cryptographic hash of application-supplied pskID
    psk_id_hash: MD,

    // Cryptographic hash of application-supplied info
    info_hash: MD,
}

// Generate random x25519 key `(PK, SK)`.
fn generate_key_pair() -> (PK, SK) {
    let sk = SK::random();
    let pk = curve25519::secret_to_public(curve25519::SerializedScalar::from(sk.raw()));
    (PK::from(pk.raw()), SK::from(sk.raw()))
}

fn dh(sk: SK, pk: PK) -> PK {
    PK::from(
        curve25519::scalarmult(
            curve25519::SerializedScalar::from(sk.raw()),
            curve25519::SerializedPoint::from(pk.raw()),
        )
        .raw(),
    )
}

fn marshal(pk: PK) -> MarshalledPk {
    pk.into()
}

fn unmarshal(enc: MarshalledPk) -> PK {
    enc.into()
}

fn encap(pk_r: PK) -> (PK, MarshalledPk) {
    let (pk_e, sk_e) = generate_key_pair();
    let zz = dh(sk_e, pk_r);
    let enc = marshal(pk_e);
    (zz, enc)
}

// TODO: we need something like this in hacspec.rs
fn concat_pk(a: PK, b: PK) -> [u8; 64] {
    let mut out = [0u8; 64];
    for i in 0..a.len() {
        out[i] = a[i];
        out[i + a.len()] = b[i];
    }
    out
}

fn auth_encap(pk_r: PK, sk_i: SK) -> ([u8; 64], MarshalledPk) {
    let (pk_e, sk_e) = generate_key_pair();
    let zz = concat_pk(dh(sk_e, pk_r), dh(sk_i, pk_r));
    let enc = marshal(pk_e);
    (zz, enc)
}

fn auth_decap(enc: MarshalledPk, sk_r: SK, pk_i: PK) -> [u8; 64] {
    let pk_e = unmarshal(enc);
    concat_pk(dh(sk_r, pk_e), dh(sk_r, pk_i))
}

// TODO: this is only x25519 right now. Also re-computes pk.
fn pk(sk: SK) -> PK {
    PK::from(curve25519::secret_to_public(curve25519::SerializedScalar::from(sk.raw())).raw())
}

fn zero(len: usize) -> Bytes {
    Bytes::new_len(len)
}

// TODO: actually fail or something
fn verify_mode(mode: Mode, psk: PSK, psk_id: Bytes, pk_im: MarshalledPk) {
    let default_pk_im = zero(pk_im.len());
    let default_psk = zero(PSK::capacity());
    let default_psk_id = Bytes::new();

    let got_psk = psk[..] != default_psk[..] && psk_id != default_psk_id;
    let no_psk = psk[..] == default_psk[..] && psk_id == default_psk_id;
    let got_pk_im = pk_im[..] != default_pk_im[..];
    let no_pk_im = pk_im[..] == default_pk_im[..];

    if mode == Mode::ModeBase && (got_psk || got_pk_im) {
        println!("Invalid configuration for ModeBase")
    }
    if mode == Mode::ModePsk && (no_psk || got_pk_im) {
        println!("Invalid configuration for ModePsk")
    }
    if mode == Mode::ModeAuth && (got_psk || no_pk_im) {
        println!("Invalid configuration for ModeAuth")
    }
    if mode == Mode::ModePskAuth && (no_psk || no_pk_im) {
        println!("Invalid configuration for ModePskAuth")
    }
}

fn concat_u16(a: Kem, b: Kdf, c: Aead) -> Ciphersuite {
    let a = a as u16;
    let b = b as u16;
    let c = c as u16;
    [
        (a >> 8) as u8,
        (a & 0xFF) as u8,
        (b >> 8) as u8,
        (b & 0xFF) as u8,
        (c >> 8) as u8,
        (c & 0xFF) as u8,
    ]
}

fn hash(s: Bytes) -> MD {
    sha2::hash(s.get_slice()).raw().into()
}

fn concat_ctx(
    mode: Mode,
    ciphersuite: Ciphersuite,
    enc: MarshalledPk,
    pk_rm: MarshalledPk,
    pk_im: MarshalledPk,
    psk_id_hash: MD,
    info_hash: MD,
) -> Bytes {
    let mut out = Bytes::new_len(0);
    out.push(mode as u8);
    out.extend_from_slice(&ciphersuite);
    out.extend_from_slice(&enc);
    out.extend_from_slice(&pk_rm);
    out.extend_from_slice(&pk_im);
    out.extend_from_slice(psk_id_hash.raw());
    out.extend_from_slice(info_hash.raw());
    out
}

fn extract(psk: PSK, zz: [u8; 64]) -> MD {
    hkdf::extract(Bytes::from(psk.raw()), Bytes::from(&zz[..])).raw().into()
}

fn expand(secret: MD, label: Bytes, nk: usize) -> Key {
    hkdf::expand(Bytes::from(secret.raw()), label, nk).raw().into()
}

fn concat_label(label: String, context: Bytes) -> Bytes {
    let mut out = Bytes::new_len(0);
    // TODO: this is UTF-8 string to bytes conversion.
    out.extend_from_slice(label.as_bytes());
    out.extend(context);
    out
}

fn key_schedule(
    mode: Mode,
    pk_r: PK,
    zz: [u8; 64],
    enc: MarshalledPk,
    info: Bytes,
    psk: PSK,
    psk_id: Bytes,
    pk_im: MarshalledPk,
) -> HpkeContext {
    verify_mode(mode, psk, psk_id.clone(), pk_im);

    let pk_rm = marshal(pk_r);
    let kem_id: Kem = Kem::DHKEM_25519;
    let kdf_id: Kdf = Kdf::HKDF_SHA256;
    let aead_id: Aead = Aead::AES_GCM_128;
    let ciphersuite = concat_u16(kem_id, kdf_id, aead_id);
    let psk_id_hash = hash(psk_id);
    let info_hash = hash(info);
    let context = concat_ctx(mode, ciphersuite, enc, pk_rm, pk_im, psk_id_hash, info_hash);

    let secret = extract(psk, zz);
    let nk = Key::capacity();
    let nn = 32;
    let key = expand(
        secret,
        concat_label("hpke key".to_string(), context.clone()),
        nk,
    );
    // TODO: expand always returns Key, which has length 32.
    let nonce = expand(secret, concat_label("hpke nonce".to_string(), context), nn);
    HpkeContext {
        mode: mode,
        kem_id: kem_id,
        kdf_id: kdf_id,
        aead_id: aead_id,
        enc: enc,
        pk_r: pk_r,
        pk_i: pk_im,
        psk_id_hash: psk_id_hash,
        info_hash: info_hash,
    }
}

fn setup_auth_psk_i(pk_r: PK, info: Bytes, psk: PSK, psk_id: Bytes, sk_i: SK) -> HpkeContext {
    let (zz, enc) = auth_encap(pk_r, sk_i);
    let pk_im = marshal(pk(sk_i));
    let key_schedule = key_schedule(Mode::ModePskAuth, pk_r, zz, enc, info, psk, psk_id, pk_im);
    key_schedule
}

fn setup_auth_psk_r(enc: MarshalledPk, sk_r: SK, info: Bytes, psk: PSK, psk_id: Bytes, pk_i: PK) -> HpkeContext {
    let zz = auth_decap(enc, sk_r, pk_i);
    let pk_im = marshal(pk_i);
    let key_schedule = key_schedule(Mode::ModePskAuth, pk(sk_r), zz, enc, info, psk, psk_id, pk_im);
    key_schedule
}

// === TODO: Move Test ===

struct HPKEEncryption<'a> {
    sequence_number: u8,
    plaintext: &'a str,
    aad: &'a str,
    ciphertext: &'a str
}

struct HPKETestVector<'a> {
    mode: u8,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    info: &'a str,
    sk_r: &'a str,
    sk_i: &'a str,
    sk_e: &'a str,
    psk: &'a str,
    psk_id: &'a str,
    pk_r: &'a str,
    pk_i: &'a str,
    pk_e: &'a str,
    enc: &'a str,
    zz: &'a str,
    context: &'a str,
    secret: &'a str,
    key: &'a str,
    nonce: &'a str,
    encryptions: [HPKEEncryption::<'a>; 4]
}

// https://cfrg.github.io/draft-irtf-cfrg-hpke/draft-irtf-cfrg-hpke.html
const HPKE_KAT: [HPKETestVector; 1] = [
    HPKETestVector {
        mode: 3, // AuthPSK
        kem_id: 0x20, // DHKem(Curve25519)
        kdf_id: 1, // HKDF-SHA256
        aead_id: 1, // AES-GCM-128
        info: "4f6465206f6e2061204772656369616e2055726e",
        sk_r: "2d7c739195ba102216de162f9435991aa3ad42aeefdb7e22391ae34bae7e5a13",
        sk_i: "59c77f5734aef369f30d83c7e30c6bf372e120391cdaf13f34c915030284b75d",
        sk_e: "6827bbf4f7ebd0182a8ebc0ea364c7ddae1d1c8a4f58a903fa9f9f9d4228b126",
        psk: "6d656c6c6f6e",
        psk_id: "456e6e796e20447572696e206172616e204d6f726961",
        pk_r: "cc980df06e532bdb6b957f9f5a5caf55c55f46822cdfbd97e76f6ad4c62b322b",
        pk_i: "db6ee4a53276b7bc90657cdde514f948af83c140540797ec717881490afed921",
        pk_e: "bc09d66a6e8a77ce2fe3bf6603f227d5c673f5329a3c9ad031bbdfadbc9b1d28",
        enc: "bc09d66a6e8a77ce2fe3bf6603f227d5c673f5329a3c9ad031bbdfadbc9b1d28",
        zz: "fb907aabc5e9e03f9665c937606c46d8da4932380d297a35e0c6aa3ff641ff3496955ffd7f908cd9f8a476cd230de614d60fa4bdf599ca238580cccd7a7e7b7f",
        context: "03000200010001bc09d66a6e8a77ce2fe3bf6603f227d5c673f5329a3c9ad031bbdfadbc9b1d28cc980df06e532bdb6b957f9f5a5caf55c55f46822cdfbd97e76f6ad4c62b322bdb6ee4a53276b7bc90657cdde514f948af83c140540797ec717881490afed921eca994d516108a16db86e155390f3c3cec6f0aff60ade1ae9e3189140b0f3dea55c4040629c64c5efec2f7230407d612d16289d7c5d7afcf9340280abd2de1ab",
        secret: "5980d041d0343ae0ee09932c03ea7c3e383f30fd55ef4d66c7459e01a78683ea",
        key: "958a60f49b2b9ee8addb9ed96e4fd4fb",
        nonce: "52b1a515904660435ef1feac",
        encryptions: [HPKEEncryption {
            sequence_number: 0,
            plaintext: "4265617574792069732074727574682c20747275746820626561757479",
            aad: "436f756e742d30",
            ciphertext: "08ff327654d2696724eaf57b3899299ee51412ecafb3435f3cd5f31698f52003b0487aa0b3182d237973f3344c"
        },
        HPKEEncryption {
            sequence_number: 1,
            plaintext: "4265617574792069732074727574682c20747275746820626561757479",
            aad: "436f756e742d31",
            ciphertext: "afd8ddcb4329cb3e1fc8a46d3900eb34dcf29b6fc9e293d4ca3c59fd6f4090ced7aef880d54d2a11922dc2134a"
        },
        HPKEEncryption {
            sequence_number: 2,
            plaintext: "4265617574792069732074727574682c20747275746820626561757479",
            aad: "436f756e742d32",
            ciphertext: "1c9ecb83737a1723d22ddd0bd3827b549128035667c58b035e2026d51d040191e6b3c6c91919b80cb879e9177d"
        },
        HPKEEncryption {
            sequence_number: 4,
            plaintext: "4265617574792069732074727574682c20747275746820626561757479",
            aad: "436f756e742d34",
            ciphertext: "f26b7df1e08ba8d5d6702c66a5f6c9801ed051211dc0f1aad9169e17e14922f7b5319e3830ab9c5bf2e9ed8c88"
        }]
    }
];

#[test]
fn test_kat() {
    for kat in HPKE_KAT.iter() {
        let context_i = setup_auth_psk_i(PK::from(kat.pk_r), Bytes::from(kat.info), PSK::from(kat.psk), Bytes::from(kat.psk_id), SK::from(kat.sk_i));
        assert_eq!(kat.mode, context_i.mode as u8);
        assert_eq!(kat.kem_id, context_i.kem_id as u16);
        assert_eq!(kat.kdf_id, context_i.kdf_id as u16);
        assert_eq!(kat.aead_id, context_i.aead_id as u16);
    }
}
