//! ML-DSA, the Module-Lattice-Based Digital Signature Algorithm standardised in
//! [FIPS 204][1]
//!
//! [1]: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf>

use crate::hashing::{sha256, sha512, shake128, shake256};

mod group;
mod poly;

#[cfg(test)]
mod testvectors;

/// The hash function of `HashML-DSA`, the pre hash variant of ML-DSA
///
/// FIPS 204 section 5.4 signs `H(M)` in place of `M`, with the identity of `H`
/// bound into the signature through its object identifier, so that a signature
/// made over the digest of one function cannot be read as one made over the
/// digest of another.
///
/// These are the four hash functions that FIPS 204 Algorithm 4 instantiates.
/// The standard also allows the other approved hash functions, which this crate
/// does not implement here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreHash {
    /// SHA-256, giving a 32 bytes digest
    Sha256,
    /// SHA-512, giving a 64 bytes digest
    Sha512,
    /// SHAKE128 squeezed to 32 bytes, its security strength
    Shake128,
    /// SHAKE256 squeezed to 64 bytes, its security strength
    Shake256,
}

impl PreHash {
    /// Longest digest any of the variants produces
    const MAX_DIGEST: usize = 64;

    /// The DER encoded object identifier of the hash function
    ///
    /// all NIST standard sitting in the same OID tree, only last byte differs
    const fn oid(self) -> [u8; 11] {
        let last = match self {
            PreHash::Sha256 => 0x01,
            PreHash::Sha512 => 0x03,
            PreHash::Shake128 => 0x0b,
            PreHash::Shake256 => 0x0c,
        };
        [
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, last,
        ]
    }

    /// Hash `message` into `out`, returning the digest that was written
    fn hash<'a>(self, message: &[u8], out: &'a mut [u8; Self::MAX_DIGEST]) -> &'a [u8] {
        fn put<const M: usize>(out: &mut [u8; PreHash::MAX_DIGEST], digest: [u8; M]) -> &[u8] {
            out[..M].copy_from_slice(&digest);
            &out[..M]
        }
        match self {
            PreHash::Sha256 => put(out, sha256(message)),
            PreHash::Sha512 => put(out, sha512(message)),
            PreHash::Shake128 => put(out, shake128::<32>(message)),
            PreHash::Shake256 => put(out, shake256::<64>(message)),
        }
    }
}
