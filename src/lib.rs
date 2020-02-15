// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A pure-rust implementation of various cryptographic algorithms, which no dependencies
//! and no foreign code (specially C or assembly).
//!
//! Our goals is to support rust cryptography in various constrained environment like embedded devices and web assembly
//!
//! This is a fork of [Rust-Crypto by DaGenix](https://github.com/DaGenix/rust-crypto),
//! which we owe a debt of gratitude for starting some good quality pure rust implementations
//! of various cryptographic algorithms.
//!
//! Notable Differences with the original sources:
//!
//! * Maintained
//! * Extended ED25519 support for extended secret key (64 bytes) support
//! * Proper implementation of ChaChaPoly1305
//! * Many cryptographic algorithms removed: AES, Blowfish, Fortuna, RC4, RIPEMD160, Whirlpool, MD5, SHA1.
//!
//! As with everything cryptographic implementations, please make sure it suits your security requirements,
//! and review and audit before using.
//!

#![allow(unknown_lints)]
#![warn(clippy::all)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::new_without_default)]
#![allow(clippy::let_and_return)]
#![allow(clippy::redundant_field_names)]
#![allow(clippy::wrong_self_convention)]
#![allow(clippy::suspicious_arithmetic_impl)]
#![allow(clippy::identity_op)]
#![allow(clippy::many_single_char_names)]
#![no_std]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;

pub mod blake2b;
pub mod blake2s;
pub mod buffer;
pub mod chacha20;
pub mod chacha20poly1305;
mod cryptoutil;
pub mod curve25519;
pub mod digest;
pub mod ed25519;
pub mod hkdf;
pub mod hmac;
pub mod mac;
pub mod pbkdf2;
pub mod poly1305;
pub mod salsa20;
pub mod sha2;
pub mod sha3;
mod simd;
pub mod symmetriccipher;
pub mod util;
