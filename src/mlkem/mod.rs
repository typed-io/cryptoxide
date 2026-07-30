//! ML-KEM, the Module-Lattice-Based Key-Encapsulation Mechanism standardised in
//! [FIPS 203][1]
//!
//! A KEM lets a sender establish a shared secret with the holder of a public
//! key, without any interaction beyond sending a single ciphertext. Unlike a
//! Diffie-Hellman exchange it is believed to resist attacks by quantum
//! computers, its security resting on the hardness of the Module Learning With
//! Errors problem rather than on discrete logarithms.
//!
//! Three parameter sets are standardised, in increasing order of security and
//! cost, and each of them has its own keys, ciphertext and entry points, named
//! with a `512`, `768` or `1024` suffix.
//!
//! The [`SharedSecret`] is similar for each parameter sets (32 bytes).
//!
//! Table 3. [FIPS 203][1]:
//!
//! | Parameter set | Encapsulation key | Decapsulation key | Ciphertext |
//! | ------------- | ----------------- | ----------------- | ---------- |
//! | ML-KEM-512    | 800 bytes         | 1632 bytes        | 768 bytes  |
//! | ML-KEM-768    | 1184 bytes        | 2400 bytes        | 1088 bytes |
//! | ML-KEM-1024   | 1568 bytes        | 3168 bytes        | 1568 bytes |
//!
//! # Example
//!
//! ```
//! use cryptoxide::mlkem;
//!
//! // the receiver generates a key pair and publishes its encapsulation key
//! # let (d, z) = ([0u8; 32], [1u8; 32]); // must be random !
//! let (ek, dk) = mlkem::keypair768(&d, &z);
//!
//! // the sender encapsulates a shared secret towards the encapsulation key
//! # let m = [2u8; 32]; // for real use must be proper random; use the getrandom crate !
//! let (ciphertext, sender_secret) = mlkem::encapsulate768(&ek, &m);
//!
//! // the receiver recovers the same shared secret from the ciphertext alone
//! let receiver_secret = mlkem::decapsulate768(&dk, &ciphertext);
//!
//! assert_eq!(sender_secret.as_ref(), receiver_secret.as_ref());
//! ```
//!
//! [1]: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf>

use crate::constant_time::{Choice, CtEqual, CtSelect};
use crate::hashing::{
    sha3::{Sha3_256, Sha3_512},
    shake::Shake256,
};
use poly::ENCODED12;

mod group;
mod kpke;
mod poly;

#[cfg(test)]
mod testvectors;

/// Length in bytes of a shared secret, for every parameter set
pub const SHARED_SECRET_LENGTH: usize = 32;

/// Length in bytes of each of the random seeds taken by key generation and
/// encapsulation, for every parameter set
pub const SEED_LENGTH: usize = 32;

/// Why a byte sequence could not be interpreted as an ML-KEM key or ciphertext
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The input length does not match the parameter set, which is the type
    /// check of FIPS 203 sections 7.2 and 7.3
    InvalidLength,
    /// The encapsulation key contains a coefficient that is not reduced modulo
    /// 3329, which is the modulus check of FIPS 203 section 7.2. Such a key
    /// cannot have been produced by key generation.
    InvalidModulus,
    /// The decapsulation key does not embed the hash of its own encapsulation
    /// key, which is the hash check of FIPS 203 section 7.3
    InvalidHash,
}

/// Shared secret established by an encapsulation and decapsulation exchange
///
/// The three parameter sets all produce a 32 bytes secret, so this type is
/// common to them.
pub struct SharedSecret([u8; SHARED_SECRET_LENGTH]);

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl From<SharedSecret> for [u8; SHARED_SECRET_LENGTH] {
    fn from(secret: SharedSecret) -> Self {
        secret.0
    }
}

impl CtEqual for &SharedSecret {
    fn ct_eq(self, other: Self) -> Choice {
        (&self.0).ct_eq(&other.0)
    }
    fn ct_ne(self, other: Self) -> Choice {
        (&self.0).ct_ne(&other.0)
    }
}

/// FIPS 203 section 4.1 `H`
fn h(data: &[u8]) -> [u8; 32] {
    Sha3_256::new().update(data).finalize()
}

/// FIPS 203 section 4.1 `G`, returning its output as its two 32 bytes halves
fn g(a: &[u8], b: &[u8]) -> ([u8; 32], [u8; 32]) {
    let out = Sha3_512::new().update(a).update(b).finalize();
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    first.copy_from_slice(&out[..32]);
    second.copy_from_slice(&out[32..]);
    (first, second)
}

/// ML-KEM.KeyGen_internal (FIPS 203 Algorithm 16)
fn keygen<const K: usize, const ETA1: usize>(
    d: &[u8; 32],
    z: &[u8; 32],
    ek: &mut [u8],
    dk: &mut [u8],
) {
    assert_eq!(dk.len(), 2 * ENCODED12 * K + 96);

    let (dk_pke, tail) = dk.split_at_mut(ENCODED12 * K);
    kpke::keygen::<K, ETA1>(d, ek, dk_pke);

    // the decapsulation key carries all of what decapsulation needs: the K-PKE
    // key, the matching encapsulation key and its hash, and the seed z from
    // which rejected ciphertexts get their shared secret
    let (dk_ek, tail) = tail.split_at_mut(ENCODED12 * K + 32);
    dk_ek.copy_from_slice(ek);
    let (dk_h, dk_z) = tail.split_at_mut(32);
    dk_h.copy_from_slice(&h(ek));
    dk_z.copy_from_slice(z);
}

/// ML-KEM.Encaps_internal (FIPS 203 Algorithm 17)
fn encaps<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    ek: &[u8],
    m: &[u8; 32],
    ct: &mut [u8],
) -> [u8; 32] {
    // hashing the encapsulation key into the derivation binds the shared secret
    // to the key it was encapsulated against
    let (secret, r) = g(m, &h(ek));
    kpke::encrypt::<K, ETA1, ETA2, DU, DV>(ek, m, &r, ct);
    secret
}

/// ML-KEM.Decaps_internal (FIPS 203 Algorithm 18)
fn decaps<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
    const CT: usize,
>(
    dk: &[u8],
    ct: &[u8; CT],
) -> [u8; 32] {
    assert_eq!(dk.len(), 2 * ENCODED12 * K + 96);
    assert_eq!(ct.len(), CT);

    let (dk_pke, tail) = dk.split_at(ENCODED12 * K);
    let (ek, tail) = tail.split_at(ENCODED12 * K + 32);
    let (hash_ek, z) = tail.split_at(32);

    let m = kpke::decrypt::<K, DU, DV>(dk_pke, ct);
    let (mut secret, r) = g(&m, hash_ek);

    // the secret handed out when the ciphertext is rejected. Deriving it from z
    // keeps a rejection indistinguishable from a success for whoever submitted
    // the ciphertext, which is what makes the implicit rejection of the
    // Fujisaki-Okamoto transform safe.
    let rejected: [u8; 32] = Shake256::new().update(z).update(ct).finalize();

    // a ciphertext that does not encrypt back to itself was not produced by
    // encapsulation. Both secrets are always computed and the choice between
    // them is made by masking, as revealing which one is returned would hand an
    // attacker the decryption oracle the transform is meant to deny.
    let mut reencrypted = [0u8; CT];
    kpke::encrypt::<K, ETA1, ETA2, DU, DV>(ek, &m, &r, &mut reencrypted);

    secret.ct_assign(ct.ct_ne(&reencrypted), &rejected);
    secret
}

/// The modulus check of FIPS 203 section 7.2
///
/// Equivalent to the `ByteEncode12(ByteDecode12(ek)) == ek` of the
/// specification: the round trip is the identity exactly when every 12 bits
/// coefficient of the encoding is already a canonical residue.
fn modulus_check(encoded: &[u8]) -> bool {
    encoded.chunks_exact(3).all(|c| {
        let d0 = (c[0] as u16) | ((c[1] as u16 & 0xf) << 8);
        let d1 = ((c[1] as u16) >> 4) | ((c[2] as u16) << 4);
        d0 < group::Q && d1 < group::Q
    })
}

/// Define the keys, ciphertext and entry points of one parameter set
macro_rules! mlkem_impl {
    (
        $set:expr,
        $ek:ident, $dk:ident, $ct:ident,
        $keypair:ident, $encapsulate:ident, $decapsulate:ident,
        $k:literal, $eta1:literal, $eta2:literal, $du:literal, $dv:literal,
        $ek_len:literal, $dk_len:literal, $ct_len:literal
    ) => {
        #[doc = concat!($set, " encapsulation key, the public half of a key pair")]
        #[derive(Clone)]
        pub struct $ek([u8; $ek_len]);

        #[doc = concat!($set, " decapsulation key, the secret half of a key pair")]
        ///
        /// The encapsulation key it was generated with is embedded in it and can
        /// be recovered with [`encapsulation_key`](Self::encapsulation_key).
        #[derive(Clone)]
        pub struct $dk([u8; $dk_len]);

        #[doc = concat!($set, " ciphertext, sent by the encapsulating to the decapsulating party")]
        #[derive(Clone)]
        pub struct $ct([u8; $ct_len]);

        #[doc = concat!("Generate an ", $set, " key pair from the seeds `d` and `z`")]
        ///
        /// Both seeds must be 32 independent, freshly generated random bytes; see
        /// the [module documentation](crate::mlkem#randomness).
        pub fn $keypair(d: &[u8; SEED_LENGTH], z: &[u8; SEED_LENGTH]) -> ($ek, $dk) {
            let mut ek = [0u8; $ek_len];
            let mut dk = [0u8; $dk_len];
            keygen::<$k, $eta1>(d, z, &mut ek, &mut dk);
            ($ek(ek), $dk(dk))
        }

        #[doc = concat!("Encapsulate a new ", $set, " shared secret towards the holder of `ek`")]
        ///
        /// Returns the shared secret along with the ciphertext to hand over to
        /// that holder. `m` must be 32 freshly generated random bytes and must
        /// never be reused; see the
        /// [module documentation](crate::mlkem#randomness).
        pub fn $encapsulate(ek: &$ek, m: &[u8; SEED_LENGTH]) -> ($ct, SharedSecret) {
            let mut ct = [0u8; $ct_len];
            let secret = encaps::<$k, $eta1, $eta2, $du, $dv>(&ek.0, m, &mut ct);
            ($ct(ct), SharedSecret(secret))
        }

        #[doc = concat!("Recover from `ct` the ", $set, " shared secret encapsulated towards `dk`")]
        ///
        #[doc = concat!("A ciphertext that was not produced by [`", stringify!($encapsulate), "`]")]
        /// against the matching encapsulation key does not make this fail: it
        /// yields an unpredictable secret instead, which the peer cannot compute.
        /// Only once the two parties compare notes, or the exchange fails, does
        /// the difference show.
        pub fn $decapsulate(dk: &$dk, ct: &$ct) -> SharedSecret {
            SharedSecret(decaps::<$k, $eta1, $eta2, $du, $dv, $ct_len>(&dk.0, &ct.0))
        }

        impl $ek {
            /// Length in bytes of the serialised key
            pub const LENGTH: usize = $ek_len;

            // the encoded vector t, ie. the key without its trailing rho
            const VECTOR: usize = $ek_len - 32;

            /// Deserialise an encapsulation key, checking it for the
            /// well-formedness that FIPS 203 section 7.2 requires
            pub fn from_bytes(bytes: [u8; $ek_len]) -> Result<Self, Error> {
                if !modulus_check(&bytes[..Self::VECTOR]) {
                    return Err(Error::InvalidModulus);
                }
                Ok($ek(bytes))
            }
        }

        impl $dk {
            /// Length in bytes of the serialised key
            pub const LENGTH: usize = $dk_len;

            // a decapsulation key is the encoded secret vector s, then the
            // matching encapsulation key, the hash of that key, and the seed z
            const EK: usize = $ek_len - 32;
            const HASH: usize = Self::EK + $ek_len;

            /// Deserialise a decapsulation key, checking it for the consistency
            /// that FIPS 203 section 7.3 requires
            pub fn from_bytes(bytes: [u8; $dk_len]) -> Result<Self, Error> {
                let ek = &bytes[Self::EK..Self::HASH];
                if h(ek) != bytes[Self::HASH..Self::HASH + 32] {
                    return Err(Error::InvalidHash);
                }
                Ok($dk(bytes))
            }

            /// The encapsulation key of the same key pair
            pub fn encapsulation_key(&self) -> $ek {
                let mut ek = [0u8; $ek_len];
                ek.copy_from_slice(&self.0[Self::EK..Self::HASH]);
                $ek(ek)
            }
        }

        impl $ct {
            /// Length in bytes of the serialised ciphertext
            pub const LENGTH: usize = $ct_len;
        }

        impl TryFrom<&[u8]> for $ek {
            type Error = Error;

            fn try_from(value: &[u8]) -> Result<Self, Error> {
                let bytes = <[u8; $ek_len]>::try_from(value).map_err(|_| Error::InvalidLength)?;
                Self::from_bytes(bytes)
            }
        }

        impl TryFrom<&[u8]> for $dk {
            type Error = Error;

            fn try_from(value: &[u8]) -> Result<Self, Error> {
                let bytes = <[u8; $dk_len]>::try_from(value).map_err(|_| Error::InvalidLength)?;
                Self::from_bytes(bytes)
            }
        }

        impl TryFrom<&[u8]> for $ct {
            type Error = Error;

            fn try_from(value: &[u8]) -> Result<Self, Error> {
                <[u8; $ct_len]>::try_from(value)
                    .map($ct)
                    .map_err(|_| Error::InvalidLength)
            }
        }

        impl From<[u8; $ct_len]> for $ct {
            fn from(bytes: [u8; $ct_len]) -> Self {
                $ct(bytes)
            }
        }

        impl AsRef<[u8]> for $ek {
            fn as_ref(&self) -> &[u8] {
                &self.0[..]
            }
        }

        impl AsRef<[u8]> for $dk {
            fn as_ref(&self) -> &[u8] {
                &self.0[..]
            }
        }

        impl AsRef<[u8]> for $ct {
            fn as_ref(&self) -> &[u8] {
                &self.0[..]
            }
        }
    };
}

mlkem_impl!(
    "ML-KEM-512",
    EncapsulationKey512,
    DecapsulationKey512,
    Ciphertext512,
    keypair512,
    encapsulate512,
    decapsulate512,
    // k, eta1, eta2, du, dv
    2,
    3,
    2,
    10,
    4,
    // encapsulation key, decapsulation key and ciphertext lengths
    800,
    1632,
    768
);

mlkem_impl!(
    "ML-KEM-768",
    EncapsulationKey768,
    DecapsulationKey768,
    Ciphertext768,
    keypair768,
    encapsulate768,
    decapsulate768,
    3,
    2,
    2,
    10,
    4,
    1184,
    2400,
    1088
);

mlkem_impl!(
    "ML-KEM-1024",
    EncapsulationKey1024,
    DecapsulationKey1024,
    Ciphertext1024,
    keypair1024,
    encapsulate1024,
    decapsulate1024,
    4,
    2,
    2,
    11,
    5,
    1568,
    3168,
    1568
);

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "with-bench"))]
mod bench {
    use test::Bencher;

    macro_rules! bench_parameter_set {
        ($keypair:ident, $encapsulate:ident, $decapsulate:ident,
         $b_keypair:ident, $b_encapsulate:ident, $b_decapsulate:ident) => {
            #[bench]
            pub fn $b_keypair(bh: &mut Bencher) {
                bh.iter(|| super::$keypair(&[1u8; 32], &[2u8; 32]));
            }

            #[bench]
            pub fn $b_encapsulate(bh: &mut Bencher) {
                let (ek, _) = super::$keypair(&[1u8; 32], &[2u8; 32]);
                bh.iter(|| super::$encapsulate(&ek, &[3u8; 32]));
            }

            #[bench]
            pub fn $b_decapsulate(bh: &mut Bencher) {
                let (ek, dk) = super::$keypair(&[1u8; 32], &[2u8; 32]);
                let (ct, _) = super::$encapsulate(&ek, &[3u8; 32]);
                bh.iter(|| super::$decapsulate(&dk, &ct));
            }
        };
    }

    bench_parameter_set!(
        keypair512,
        encapsulate512,
        decapsulate512,
        keypair_512,
        encapsulate_512,
        decapsulate_512
    );
    bench_parameter_set!(
        keypair768,
        encapsulate768,
        decapsulate768,
        keypair_768,
        encapsulate_768,
        decapsulate_768
    );
    bench_parameter_set!(
        keypair1024,
        encapsulate1024,
        decapsulate1024,
        keypair_1024,
        encapsulate_1024,
        decapsulate_1024
    );
}
