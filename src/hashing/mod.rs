//! Cryptographic Hash Functions root module
//!
//! The simplest way to use this module is to use the function, named
//! after each algorithm, that calculate the digest in one single call:
//!
//! ```
//! use cryptoxide::hashing::sha256;
//!
//! let digest = sha256(b"The quick brown fox jumps over the lazy dog");
//! ```
//!
//! Each individual algorithm is also available as a module that should
//! be imported qualified and export algorithm singleton for each variant
//! of this algorithm along with a `Context` object.
//!
//! The `Context` object keeps the ongoing state of the algorithm, so
//! that the input can be hashed incrementally with either `update` or
//! `update_mut`. Once all the data has been hashed the `Context`
//! can be finalized using `finalize` or `finalize_reset`.
//!
//! The APIs can be used either in a pass-the-context api:
//!
//! ```
//! use cryptoxide::hashing::sha2;
//!
//! let digest = sha2::Context256::new()
//!         .update(b"The quick brown fox jumps over the lazy dog")
//!         .update(b"other data")
//!         .finalize();
//! ```
//!
//! Or using the inplace mutable APIs:
//!
//! ```
//! use cryptoxide::hashing::sha2;
//!
//! let mut context = sha2::Context256::new();
//! context.update_mut(b"The quick brown fox jumps over the lazy dog");
//! context.update_mut(b"other data");
//! let digest = context.finalize_reset();
//! ```
//!

#[cfg(feature = "blake2")]
mod blake2;

#[cfg(feature = "blake2")]
pub mod blake2b;

#[cfg(feature = "blake2")]
pub mod blake2s;

#[cfg(feature = "sha1")]
pub mod sha1;

#[cfg(feature = "sha2")]
pub mod sha2;

#[cfg(feature = "sha3")]
pub mod sha3;

#[cfg(feature = "sha3")]
pub mod keccak;

#[cfg(feature = "ripemd160")]
pub mod ripemd160;

#[cfg(test)]
pub(super) mod tests;

#[cfg(feature = "blake2")]
/// Compute blake2b-224 on the input and return the digest
pub fn blake2b_224(input: &[u8]) -> [u8; 28] {
    blake2b::Blake2b::<224>::new().update(input).finalize()
}

#[cfg(feature = "blake2")]
/// Compute blake2b-256 on the input and return the digest
pub fn blake2b_256(input: &[u8]) -> [u8; 32] {
    blake2b::Blake2b::<256>::new().update(input).finalize()
}

#[cfg(feature = "blake2")]
/// Compute blake2b-384 on the input and return the digest
pub fn blake2b_384(input: &[u8]) -> [u8; 48] {
    blake2b::Blake2b::<384>::new().update(input).finalize()
}

#[cfg(feature = "blake2")]
/// Compute blake2b-512 on the input and return the digest
pub fn blake2b_512(input: &[u8]) -> [u8; 64] {
    blake2b::Blake2b::<512>::new().update(input).finalize()
}

#[cfg(feature = "blake2")]
/// Compute blake2s-224 on the input and return the digest
pub fn blake2s_224(input: &[u8]) -> [u8; 28] {
    blake2s::Blake2s::<224>::new().update(input).finalize()
}

#[cfg(feature = "blake2")]
/// Compute blake2s-256 on the input and return the digest
pub fn blake2s_256(input: &[u8]) -> [u8; 32] {
    blake2s::Blake2s::<256>::new().update(input).finalize()
}

#[cfg(feature = "sha1")]
/// Compute SHA1 on the input and return the digest
pub fn sha1(input: &[u8]) -> [u8; 20] {
    sha1::Sha1::new().update(input).finalize()
}

#[cfg(feature = "sha2")]
/// Compute SHA224 on the input and return the digest
pub fn sha224(input: &[u8]) -> [u8; 28] {
    sha2::Sha224::new().update(input).finalize()
}

#[cfg(feature = "sha2")]
/// Compute SHA256 on the input and return the digest
pub fn sha256(input: &[u8]) -> [u8; 32] {
    sha2::Sha256::new().update(input).finalize()
}

#[cfg(feature = "sha2")]
/// Compute SHA384 on the input and return the digest
pub fn sha384(input: &[u8]) -> [u8; 48] {
    sha2::Sha384::new().update(input).finalize()
}

#[cfg(feature = "sha2")]
/// Compute SHA512 on the input and return the digest
pub fn sha512(input: &[u8]) -> [u8; 64] {
    sha2::Sha512::new().update(input).finalize()
}

#[cfg(feature = "sha3")]
/// Compute SHA3-224 on the input and return the digest
pub fn sha3_224(input: &[u8]) -> [u8; 28] {
    sha3::Sha3_224::new().update(input).finalize()
}

#[cfg(feature = "sha3")]
/// Compute SHA3-256 on the input and return the digest
pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    sha3::Sha3_256::new().update(input).finalize()
}

#[cfg(feature = "sha3")]
/// Compute SHA3-384 on the input and return the digest
pub fn sha3_384(input: &[u8]) -> [u8; 48] {
    sha3::Sha3_384::new().update(input).finalize()
}

#[cfg(feature = "sha3")]
/// Compute SHA3-512 on the input and return the digest
pub fn sha3_512(input: &[u8]) -> [u8; 64] {
    sha3::Sha3_512::new().update(input).finalize()
}

#[cfg(feature = "sha3")]
/// Compute KECCAK224 on the input and return the digest
pub fn keccak224(input: &[u8]) -> [u8; 28] {
    keccak::Keccak224::new().update(input).finalize()
}

#[cfg(feature = "sha3")]
/// Compute KECCAK256 on the input and return the digest
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    keccak::Keccak256::new().update(input).finalize()
}

#[cfg(feature = "sha3")]
/// Compute KECCAK384 on the input and return the digest
pub fn keccak384(input: &[u8]) -> [u8; 48] {
    keccak::Keccak384::new().update(input).finalize()
}

#[cfg(feature = "sha3")]
/// Compute KECCAK512 on the input and return the digest
pub fn keccak512(input: &[u8]) -> [u8; 64] {
    keccak::Keccak512::new().update(input).finalize()
}

#[cfg(feature = "ripemd160")]
/// Compute RIPEMD160 on the input and return the digest
pub fn ripemd160(input: &[u8]) -> [u8; 20] {
    ripemd160::Ripemd160::new().update(input).finalize()
}
