//!
//! A set of specifications of crypto primitives, written in hacspec-rust
//! See https://crates.io/crates/hacspec for details on hacspec-rust.
//!

// Get hacspec and all depending crates.
extern crate hacspec;
hacspec::hacspec_crates!();

pub mod chacha20;
pub mod chacha20poly1305;
pub mod poly1305;
