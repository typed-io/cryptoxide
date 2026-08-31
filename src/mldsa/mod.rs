//! ML-DSA, the Module-Lattice-Based Digital Signature Algorithm standardised in
//! [FIPS 204][1]
//!
//! [1]: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf>

use crate::hashing::shake::Shake256;
use crate::hashing::{sha256, sha512, shake128, shake256};

use encoding::{pk_encode, sk_encode};
use poly::{rej_bounded_poly, rej_ntt_poly, Poly};

mod encoding;
mod group;
mod poly;

#[cfg(test)]
mod testvectors;

/// Length in bytes of the seed taken by key generation, for every parameter set
pub const SEED_LENGTH: usize = 32;

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

/// Accumulate `sum_j A[i][j] v[j]` over the row `i` of the matrix `A` that
/// `ExpandA` (FIPS 204 Algorithm 32) derives from `rho`
///
/// The matrix is the largest object of the scheme, so it is never materialised
/// and each row is expanded where it is used. Signing pays for that on every
/// rejection round, which is the price of a working set that does not grow with
/// `k l`.
fn matrix_row_mul<const L: usize>(rho: &[u8; 32], i: usize, v: &[Poly; L]) -> Poly {
    let mut acc = Poly::ZERO;
    for (j, vj) in v.iter().enumerate() {
        acc.mul_acc(&rej_ntt_poly(rho, j as u8, i as u8), vj);
    }
    acc
}

/// ML-DSA.KeyGen_internal (FIPS 204 Algorithm 6)
fn keygen<const K: usize, const L: usize, const ETA: u32, const ETA_BITS: usize>(
    xi: &[u8; SEED_LENGTH],
    pk: &mut [u8],
    sk: &mut [u8],
) {
    // the dimensions of the parameter set are mixed into the seed, so that two
    // of them never derive anything from the same expanded seed
    //
    // seed is layout as : rho (32 bytes) | rho_prime (64 bytes) | k_seed (32 bytes)
    let seeds: [u8; 128] = Shake256::new()
        .update(xi)
        .update(&[K as u8, L as u8])
        .finalize();
    let rho = <&[u8; 32]>::try_from(&seeds[0..32]).unwrap();
    let rho_prime = <&[u8; 64]>::try_from(&seeds[32..96]).unwrap();
    let k_seed = <&[u8; 32]>::try_from(&seeds[96..128]).unwrap();

    let s1: [Poly; L] = core::array::from_fn(|i| rej_bounded_poly::<ETA>(rho_prime, i as u16));
    let s2: [Poly; K] =
        core::array::from_fn(|i| rej_bounded_poly::<ETA>(rho_prime, (L + i) as u16));

    let mut s1_hat = s1;
    for p in s1_hat.iter_mut() {
        p.ntt();
    }

    // t = A s1 + s2, of which the public key keeps only the high bits: dropping
    // the low ones is what makes a public key smaller than t, and the hints of
    // a signature are what let a verifier work without them
    let mut t1 = [Poly::ZERO; K];
    let mut t0 = [Poly::ZERO; K];
    for (i, s2i) in s2.iter().enumerate() {
        let mut t = matrix_row_mul(rho, i, &s1_hat);
        t.inv_ntt();
        t.add_mut(s2i);
        (t1[i], t0[i]) = t.power2round();
    }

    pk_encode::<K>(rho, &t1, pk);
    // tr binds every signature to the public key, and is kept in the signing
    // key so that signing does not have to recompute the public key
    let tr: [u8; 64] = Shake256::new().update(pk).finalize();
    sk_encode::<K, L, ETA_BITS>(rho, k_seed, &tr, &s1, &s2, &t0, ETA, sk);
}

/// Number of bits needed to represent `x`, the `bitlen` of FIPS 204
const fn bitlen(x: u32) -> usize {
    (u32::BITS - x.leading_zeros()) as usize
}

/// Define the keys, signature and entry point of one parameter set
macro_rules! mldsa_impl {
    (
        $set:expr,
        $vk:ident, $sk:ident, $sigt:ident, $keypair:ident,
        $k:literal, $l:literal, $eta:literal, $eta_bits:literal, $tau:literal,
        $gamma1:literal, $gamma1_bits:literal, $gamma2:literal, $w1_bits:literal,
        $omega:literal, $ctilde:literal,
        $vk_len:literal, $sk_len:literal, $sig_len:literal
    ) => {
        // check the literals against the formulas of FIPS 204 section 4 to make the expected invariant holds
        const _: () = {
            assert!($eta == 2 || $eta == 4);
            assert!($eta_bits == bitlen(2 * $eta));
            assert!($gamma1_bits == bitlen(2 * $gamma1 - 1));
            assert!($w1_bits == bitlen((group::Q - 1) / (2 * $gamma2) - 1));
            assert!((group::Q - 1) % (2 * $gamma2) == 0);
            assert!($vk_len == 32 + 32 * 10 * $k);
            assert!($sk_len == 128 + 32 * ($eta_bits * ($k + $l) + group::D * $k));
            assert!($sig_len == $ctilde + 32 * $gamma1_bits * $l + $omega + $k);
        };

        #[doc = concat!($set, " verifying key, the public half of a key pair")]
        #[derive(Clone)]
        pub struct $vk([u8; $vk_len]);

        #[doc = concat!($set, " signing key, the secret half of a key pair")]
        #[derive(Clone)]
        pub struct $sk([u8; $sk_len]);

        #[doc = concat!($set, " signature")]
        #[derive(Clone)]
        pub struct $sigt([u8; $sig_len]);

        #[doc = concat!("Generate an ", $set, " key pair from the seed `xi`")]
        ///
        /// `xi` must be 32 independent, freshly generated random bytes; see the
        /// [module documentation](crate::mldsa#randomness).
        pub fn $keypair(xi: &[u8; SEED_LENGTH]) -> ($vk, $sk) {
            let mut vk = [0u8; $vk_len];
            let mut sk = [0u8; $sk_len];
            keygen::<$k, $l, $eta, $eta_bits>(xi, &mut vk, &mut sk);
            ($vk(vk), $sk(sk))
        }

        impl From<[u8; $vk_len]> for $vk {
            fn from(bytes: [u8; $vk_len]) -> Self {
                $vk(bytes)
            }
        }

        impl From<[u8; $sig_len]> for $sigt {
            fn from(bytes: [u8; $sig_len]) -> Self {
                $sigt(bytes)
            }
        }

        impl AsRef<[u8; $vk_len]> for $vk {
            fn as_ref(&self) -> &[u8; $vk_len] {
                &self.0
            }
        }

        impl AsRef<[u8]> for $vk {
            fn as_ref(&self) -> &[u8] {
                &self.0[..]
            }
        }

        impl AsRef<[u8; $sk_len]> for $sk {
            fn as_ref(&self) -> &[u8; $sk_len] {
                &self.0
            }
        }

        impl AsRef<[u8]> for $sk {
            fn as_ref(&self) -> &[u8] {
                &self.0[..]
            }
        }

        impl AsRef<[u8; $sig_len]> for $sigt {
            fn as_ref(&self) -> &[u8; $sig_len] {
                &self.0
            }
        }

        impl AsRef<[u8]> for $sigt {
            fn as_ref(&self) -> &[u8] {
                &self.0[..]
            }
        }
    };
}

mldsa_impl!(
    "ML-DSA-44",
    VerifyingKey44,
    SigningKey44,
    Signature44,
    keypair44,
    // k, l, eta, bitlen(2 eta), tau
    4,
    4,
    2,
    3,
    39,
    // gamma1, 1 + bitlen(gamma1 - 1), gamma2, bitlen((q-1)/(2 gamma2) - 1)
    131072,
    18,
    95232,
    6,
    // omega, lambda / 4
    80,
    32,
    // verifying key, signing key and signature lengths
    1312,
    2560,
    2420
);

mldsa_impl!(
    "ML-DSA-65",
    VerifyingKey65,
    SigningKey65,
    Signature65,
    keypair65,
    6,
    5,
    4,
    4,
    49,
    524288,
    20,
    261888,
    4,
    55,
    48,
    1952,
    4032,
    3309
);

mldsa_impl!(
    "ML-DSA-87",
    VerifyingKey87,
    SigningKey87,
    Signature87,
    keypair87,
    8,
    7,
    2,
    3,
    60,
    524288,
    20,
    261888,
    4,
    75,
    64,
    2592,
    4896,
    4627
);
