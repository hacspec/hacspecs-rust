#![allow(dead_code)]

// Import hacspec and all needed definitions.
use hacspec::*;
hacspec_imports!();

// Import primitives
use crate::curve25519;

bytes!(PK, 32);
bytes!(SK, 32);
bytes!(MD, 32);
bytes!(Key, 32);
type MarshalledPk = [u8; 32];
type KemId = u16;
type KdfId = u16;
type AeadId = u16;
type Ciphersuite = [u8; 6];

// TODO: ugh, we shouldn't allow derives, but we need it -> add library function for something like this.
#[derive(PartialEq, Copy, Clone)]
enum Mode {
    ModeBase = 0x00,
    ModePsk = 0x01,
    ModeAuth = 0x02,
    ModePskAuth = 0x03,
}

// TODO ...
bytes!(AAD, 42);
bytes!(PSK, 42);

struct HpkeContext {
    // Mode and algorithms
    mode: Mode,
    kem_id: KemId,
    kdf_id: KdfId,
    aead_id: AeadId,

    // Public inputs to this key exchange
    enc: MarshalledPk,
    pk_r: PK,
    pk_i: MarshalledPk,

    // Cryptographic hash of application-supplied pskID
    psk_id_hash: MD,

    // Cryptographic hash of application-supplied info
    info_hash: MD,
}

// TODO: hard-coded x25519 here.
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

// def Decap(enc, skR):
//   pkE = Unmarshal(enc)
//   return DH(skR, pkE)

fn auth_encap(pk_r: PK, sk_i: SK) -> ([u8; 64], MarshalledPk) {
    let (pk_e, sk_e) = generate_key_pair();
    let zz = concat_pk(dh(sk_e, pk_r), dh(sk_i, pk_r));
    let enc = marshal(pk_e);
    (zz, enc)
}

// TODO: this is only x25519 right now. Also re-computes pk.
fn pk(sk: SK) -> PK {
    PK::from(curve25519::secret_to_public(curve25519::SerializedScalar::from(sk.raw())).raw())
}

// def AuthDecap(enc, skR, pkI):
//   pkE = Unmarshal(enc)
//   return concat(DH(skR, pkE), DH(skR, pkI))

fn zero(len: usize) -> Bytes {
    Bytes::new_len(len)
}

// TODO: actually fail or something
fn verify_mode(mode: Mode, psk: PSK, psk_id: String, pk_im: MarshalledPk) {
    let default_pk_im = zero(pk_im.len());
    let default_psk = zero(PSK::capacity());
    let default_psk_id = "";

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

fn concat_u16(a: KemId, b: KdfId, c: AeadId) -> Ciphersuite {
    [
        (a >> 8) as u8,
        (a & 0xFF) as u8,
        (b >> 8) as u8,
        (b & 0xFF) as u8,
        (c >> 8) as u8,
        (c & 0xFF) as u8,
    ]
}

fn hash(s: String) -> MD {
    // TODO: implement SHA2
    MD::new()
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
    // TODO: implement HKDF
    MD::new()
}

fn expand(secret: MD, label: Bytes, nk: usize) -> Key {
    // TODO: implement HKDF
    Key::new()
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
    info: String,
    psk: PSK,
    psk_id: String,
    pk_im: MarshalledPk,
) -> HpkeContext {
    verify_mode(mode, psk, psk_id.clone(), pk_im);

    let pk_rm = marshal(pk_r);
    let kem_id: KemId = 0x0001;
    let kdf_id: KdfId = 0x0001;
    let aead_id: AeadId = 0x0001;
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

fn setup_auth_pski(pk_r: PK, info: String, psk: PSK, psk_id: String, sk_i: SK) -> HpkeContext {
    let (zz, enc) = auth_encap(pk_r, sk_i);
    let pk_im = marshal(pk(sk_i));
    let key_schedule = key_schedule(Mode::ModePskAuth, pk_r, zz, enc, info, psk, psk_id, pk_im);
    key_schedule
}

// def SetupAuthPSKR(enc, skR, info, psk, pskID, pkI):
//   zz = AuthDecap(enc, skR, pkI)
//   pkIm = Marshal(pkI)
//   return KeySchedule(ModePskAuth, pk(skR), zz, enc, info,
//                      psk, pskID, pkIm)

// fn Seal(pk_r: PK, info: String, aad: AAD, msg: Bytes) -> () {
//     let enc, ctx = SetupAuthPSKI(pk_r, info)
//     let ct = ctx.Seal(aad, pt)
//     (enc, ct)
// }

// def Open<MODE>(enc, skR, info, aad, ct, ...):
//   ctx = Setup<MODE>R(enc, skR, info, ...)
//   return ctx.Open(aad, ct)
