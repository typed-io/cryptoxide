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

#![warn(clippy::all)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::new_without_default)]
#![allow(clippy::let_and_return)]
#![allow(clippy::redundant_field_names)]
#![allow(clippy::wrong_self_convention)]
#![allow(clippy::identity_op)]
#![allow(clippy::many_single_char_names)]
#![no_std]
#![cfg_attr(feature = "with-bench", feature(test))]
#![deny(missing_docs)]

#[cfg(test)]
#[cfg(feature = "with-bench")]
extern crate test;

#[cfg(any(
    test,
    feature = "hkdf",
    feature = "pbkdf2",
    feature = "argon2",
    feature = "sha3",
    feature = "digest"
))]
extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;

#[cfg(feature = "aes")]
pub mod aes;

#[cfg(all(feature = "blake2", feature = "digest"))]
pub mod blake2b;

#[cfg(all(feature = "blake2", feature = "digest"))]
pub mod blake2s;

#[cfg(feature = "chacha")]
pub mod chacha;

#[cfg(feature = "chacha")]
pub mod chacha20;

#[cfg(all(feature = "chacha", feature = "poly1305"))]
pub mod chacha20poly1305;

#[cfg(feature = "curve25519")]
pub mod curve25519;

#[cfg(feature = "x25519")]
pub mod x25519;

#[cfg(feature = "digest")]
pub mod digest;

pub mod hashing;

pub mod drg;

#[cfg(feature = "ed25519")]
pub mod ed25519;
#[cfg(feature = "hkdf")]
pub mod hkdf;

pub mod kdf;

#[cfg(feature = "hmac")]
pub mod hmac;
#[cfg(feature = "pbkdf2")]
pub mod pbkdf2;
#[cfg(feature = "poly1305")]
pub mod poly1305;
#[cfg(feature = "scrypt")]
pub mod scrypt;

#[cfg(feature = "salsa")]
pub mod salsa20;

#[cfg(all(feature = "sha1", feature = "digest"))]
pub mod sha1;

#[cfg(all(feature = "sha2", feature = "digest"))]
pub mod sha2;

#[cfg(all(feature = "sha3", feature = "digest"))]
pub mod sha3;

#[cfg(all(feature = "ripemd160", feature = "digest"))]
pub mod ripemd160;

mod cryptoutil;

pub mod constant_time;
