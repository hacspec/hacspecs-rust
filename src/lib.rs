//!
//! A set of specifications of crypto primitives, written in hacspec-rust
//! See https://crates.io/crates/hacspec for details on hacspec-rust.

// TODO: can we move this?
#![allow(clippy::suspicious_arithmetic_impl)]

// Get hacspec and all depending crates.
extern crate hacspec;
hacspec::hacspec_crates!();

pub mod aes;
pub mod aesgcm;
pub mod blake2b;
pub mod chacha20;
pub mod chacha20poly1305;
pub mod curve25519;
pub mod gf128;
pub mod hpke;
pub mod p256;
pub mod poly1305;
pub mod sha2;
