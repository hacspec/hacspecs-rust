// Import hacspec and all needed definitions.
use hacspec::prelude::*;

use crate::sha2;
use crate::hmac::hmac;

const HASH_LEN: usize = sha2::HASH_SIZE;
bytes!(PRK, HASH_LEN);

// TODO: do we want to allow Option?
/// Extract a pseudo-random key from input key material (IKM) and optionally a salt.
/// Note that salt can be empty Bytes.
pub fn extract(salt: Bytes, ikm: Bytes) -> PRK {
    // PRK = HMAC-Hash(salt, IKM)
    let salt = if salt.len() > 0 {
        salt
    } else {
        // Use all zero salt if none given.
        Bytes::new_len(HASH_LEN)
    };
    hmac(salt, ikm).raw().into()
}

/// Expand a key k, using potentially empty info, and output length l.
/// Key k must be at least of length HASH_LEN.
/// Output length l can be at most 255*HASH_LEN. 
pub fn expand(k: ByteSlice, info: ByteSlice, l: usize) -> Bytes {
    Bytes::new_len(HASH_LEN*2)
}

#[test]
fn test_kat1() {
    let ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    let salt = "000102030405060708090a0b0c";
    let info = "f0f1f2f3f4f5f6f7f8f9";
    let l = 42;
    let expected_prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
    let expected_okm = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

    let prk = extract(Bytes::from(salt), Bytes::from(ikm));
    assert_eq!(expected_prk, prk.to_hex());
}
