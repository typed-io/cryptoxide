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
