// // Import hacspec and all needed definitions.
// use hacspec::prelude::*;

// use crate::sha2;
// use crate::hmac;
// use hmac::hmac;

// const HASH_LEN: usize = sha2::HASH_SIZE;
// bytes!(PRK, HASH_LEN);

// // TODO: do we want to allow Option?
// /// Extract a pseudo-random key from input key material (IKM) and optionally a salt.
// /// Note that salt can be empty Bytes.
// pub fn extract(salt: Bytes, ikm: Bytes) -> PRK {
//     let salt = if salt.len() > 0 {
//         salt
//     } else {
//         // Use all zero salt if none given.
//         Bytes::new_len(HASH_LEN)
//     };
//     hmac(salt, ikm).raw().into()
// }

// fn build_hmac_txt(t: Bytes, info: Bytes, iteration: u8) -> Bytes {
//     let mut out = Bytes::new();
//     out.extend(t);
//     out.extend(info);
//     out.push(iteration);
//     out
// }

// /// Expand a key prk, using potentially empty info, and output length l.
// /// Key prk must be at least of length HASH_LEN.
// /// Output length l can be at most 255*HASH_LEN. 
// pub fn expand(prk: Bytes, info: Bytes, l: usize) -> Bytes {
//     let n = div_ceil(l, HASH_LEN);
//     debug_assert!(n < u8::max_value().into());
//     let n = n as u8;

//     let mut t_i = hmac::PRK::new();
//     let mut t = Bytes::new();
//     for i in 0..n {
//         let hmac_txt_in = if i == 0 {
//             build_hmac_txt(Bytes::new(), info.clone(), i+1)
//         } else {
//             build_hmac_txt(Bytes::from(t_i.raw()), info.clone(), i+1)
//         };
//         t_i = hmac(prk.clone(), hmac_txt_in);
//         t.extend_from_slice(t_i.raw());
//     }
//     Bytes::from(&t[0..l])
// }
