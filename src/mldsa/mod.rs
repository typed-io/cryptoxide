//! ML-DSA, the Module-Lattice-Based Digital Signature Algorithm standardised in
//! [FIPS 204][1]
//!
//! ML-DSA is a assymetric cryptographic signature algorithm that is currently
//! post quantum secure. The security assumption is based on the Module Learning With
//! Error problem and finding short vectors.
//!
//! Three parameter sets are standardised, in increasing order of security and
//! cost, and each of them has its own keys, signature and entry point, named
//! with a `44`, `65` or `87` suffix.
//!
//! Table 2. [FIPS 204][1]:
//!
//! | Parameter set | Verifying key | Signing key | Signature   |
//! | ------------- | ------------- | ----------- | ----------- |
//! | ML-DSA-44     | 1312 bytes    | 2560 bytes  | 2420 bytes  |
//! | ML-DSA-65     | 1952 bytes    | 4032 bytes  | 3309 bytes  |
//! | ML-DSA-87     | 2592 bytes    | 4896 bytes  | 4627 bytes  |
//!
//! [1]: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf>

use crate::constant_time::CtEqual;
use crate::hashing::shake::Shake256;
use crate::hashing::{sha256, sha512, shake128, shake256};
use crate::mldsa::encoding::{
    pk_decode, sig_decode, sig_encode, sk_decode, SigningKeyErrorInvalidRange,
};
use crate::mldsa::poly::{expand_mask_poly, sample_in_ball, Hint};

use encoding::{pk_encode, sk_encode};
use poly::{rej_bounded_poly, rej_ntt_poly, Poly};

mod encoding;
mod group;
mod poly;

#[cfg(test)]
mod testvectors;

/// Length in bytes of the seed taken by key generation, for every parameter set
pub const SEED_LENGTH: usize = 32;

/// Length in bytes of the extra randomness taken by signing, for every parameter set
pub const RANDOMIZER_LENGTH: usize = 32;

/// Longest context string a signature can be bound to
pub const MAX_CONTEXT_LENGTH: usize = 255;

/// Widest `w1` encoding of any parameter set, the 6 bits of ML-DSA-44
const MAX_W1_BITS: usize = 6;

/// Longest commitment hash of any parameter set, the `lambda / 4` of ML-DSA-87
const MAX_CTILDE: usize = 64;

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

/// ML-DSA.Sign_internal (FIPS 204 Algorithm 7)
fn sign_internal<
    const K: usize,
    const L: usize,
    const ETA: u32,
    const ETA_BITS: usize,
    const TAU: usize,
    const GAMMA1: u32,
    const GAMMA1_BITS: usize,
    const GAMMA2: u32,
    const W1_BITS: usize,
    const OMEGA: usize,
    const CTILDE: usize,
>(
    sk: &[u8],
    m_prime: &[&[u8]],
    rnd: &[u8; RANDOMIZER_LENGTH],
    sig: &mut [u8],
) -> Result<(), SigningKeyErrorInvalidRange> {
    let parts = sk_decode::<K, L, ETA_BITS>(sk, ETA)?;
    // the largest a coefficient of `c s` can be, for `s` bounded by eta
    let beta = TAU as u32 * ETA;

    let mut s1_hat = parts.s1;
    let mut s2_hat = parts.s2;
    let mut t0_hat = parts.t0;
    for p in s1_hat
        .iter_mut()
        .chain(s2_hat.iter_mut())
        .chain(t0_hat.iter_mut())
    {
        p.ntt();
    }

    // mu binds the message to the public key, through the tr the signing key
    // carries
    let mut hasher = Shake256::new().update(&parts.tr);
    for piece in m_prime {
        hasher.update_mut(piece);
    }
    let mu: [u8; 64] = hasher.finalize();

    // the mask is derived from the secret K, the caller's rnd and mu. With a
    // fresh rnd this is the hedged variant, with zeros the deterministic one;
    // either way two different messages never share a mask.
    let rho_prime2: [u8; 64] = Shake256::new()
        .update(&parts.k_seed)
        .update(rnd)
        .update(&mu)
        .finalize();

    let mut kappa: u16 = 0;
    loop {
        let y: [Poly; L] = core::array::from_fn(|i| {
            expand_mask_poly::<GAMMA1, GAMMA1_BITS>(&rho_prime2, kappa + i as u16)
        });

        // w = A y. Its high bits are the commitment: they are all the verifier
        // will be able to recompute, and they are what the challenge hashes.
        let mut w = [Poly::ZERO; K];
        let mut commit = Shake256::new().update(&mu);
        {
            let mut y_hat = y;
            for p in y_hat.iter_mut() {
                p.ntt();
            }
            let mut w1_packed = [0u8; 32 * MAX_W1_BITS];
            let w1_packed = &mut w1_packed[..32 * W1_BITS];
            for (i, wi) in w.iter_mut().enumerate() {
                *wi = matrix_row_mul(&parts.rho, i, &y_hat);
                wi.inv_ntt();
                // w1Encode (Algorithm 28), streamed row by row into the hash
                wi.high_bits::<GAMMA2>().simple_pack::<W1_BITS>(w1_packed);
                commit.update_mut(w1_packed);
            }
        }

        let mut c_tilde = [0u8; MAX_CTILDE];
        let c_tilde = &mut c_tilde[..CTILDE];
        commit.finalize_at(c_tilde);

        let mut c = sample_in_ball::<TAU>(c_tilde);
        c.ntt();

        // z = y + c s1 is the response. The mask has to hide c s1 completely,
        // so a z that came out too large is thrown away rather than published:
        // its distribution would otherwise depend on s1.
        let mut z = [Poly::ZERO; L];
        let mut retry = false;
        for ((zi, yi), s1i) in z.iter_mut().zip(y.iter()).zip(s1_hat.iter()) {
            zi.mul_acc(&c, s1i);
            zi.inv_ntt();
            zi.add_mut(yi);
            retry |= zi.norm() >= GAMMA1 - beta;
        }

        // w - c s2 has to keep the high bits of w, up to the one step a hint can
        // describe, or the verifier could not recompute the commitment
        for (wi, s2i) in w.iter_mut().zip(s2_hat.iter()) {
            let mut cs2 = Poly::ZERO;
            cs2.mul_acc(&c, s2i);
            cs2.inv_ntt();
            wi.sub_mut(&cs2);
            retry |= wi.low_bits_norm::<GAMMA2>() >= GAMMA2 - beta;
        }

        if !retry {
            let mut hint = [Hint::ZERO; K];
            let mut ones = 0;
            for (hi, (wi, t0i)) in hint.iter_mut().zip(w.iter().zip(t0_hat.iter())) {
                let mut ct0 = Poly::ZERO;
                ct0.mul_acc(&c, t0i);
                ct0.inv_ntt();
                retry |= ct0.norm() >= GAMMA2;
                // the verifier reaches w - c s2 + c t0, since the public key
                // dropped t0; the hint says where that lands in another interval
                let mut approx = *wi;
                approx.add_mut(&ct0);
                *hi = Poly::make_hint::<GAMMA2>(&approx, wi);
                ones += hi.count();
            }
            // a hint too large would not fit its encoding, which reserves room
            // for omega positions in total
            if !retry && ones <= OMEGA as u32 {
                sig_encode::<K, L, GAMMA1_BITS, OMEGA>(c_tilde, &z, &hint, GAMMA1, sig);
                return Ok(());
            }
        }

        kappa += L as u16;
    }
}

/// ML-DSA.Verify_internal (FIPS 204 Algorithm 8)
fn verify_internal<
    const K: usize,
    const L: usize,
    const ETA: u32,
    const TAU: usize,
    const GAMMA1: u32,
    const GAMMA1_BITS: usize,
    const GAMMA2: u32,
    const W1_BITS: usize,
    const OMEGA: usize,
    const CTILDE: usize,
>(
    pk: &[u8],
    m_prime: &[&[u8]],
    sig: &[u8],
) -> bool {
    let beta = TAU as u32 * ETA;

    let Some((z, hint)) = sig_decode::<K, L, GAMMA1_BITS, OMEGA>(sig, CTILDE, GAMMA1) else {
        // the hint did not have the one encoding the specification gives it
        return false;
    };
    let c_tilde = &sig[..CTILDE];

    // only a signer holding s1 can answer with a short z; a forger that picked
    // z freely would be caught here
    if z.iter().any(|p| p.norm() >= GAMMA1 - beta) {
        return false;
    }

    let (rho, t1) = pk_decode::<K>(pk);

    let tr: [u8; 64] = Shake256::new().update(pk).finalize();
    let mut hasher = Shake256::new().update(&tr);
    for piece in m_prime {
        hasher.update_mut(piece);
    }
    let mu: [u8; 64] = hasher.finalize();

    let mut c = sample_in_ball::<TAU>(c_tilde);
    c.ntt();

    let mut z_hat = z;
    for p in z_hat.iter_mut() {
        p.ntt();
    }

    // A z - c t1 2^d equals w - c s2 + c t0, ie. w up to the low bits the
    // public key does not carry; the hints put the high bits back where the
    // signer saw them
    let mut commit = Shake256::new().update(&mu);
    let mut w1_packed = [0u8; 32 * MAX_W1_BITS];
    let w1_packed = &mut w1_packed[..32 * W1_BITS];
    for (i, (t1i, hi)) in t1.iter().zip(hint.iter()).enumerate() {
        let mut approx = matrix_row_mul(rho, i, &z_hat);
        let mut ct1 = t1i.scale_2d();
        ct1.ntt();
        let mut prod = Poly::ZERO;
        prod.mul_acc(&c, &ct1);
        approx.sub_mut(&prod);
        approx.inv_ntt();
        approx
            .use_hint::<GAMMA2>(hi)
            .simple_pack::<W1_BITS>(w1_packed);
        commit.update_mut(w1_packed);
    }

    let mut expected = [0u8; MAX_CTILDE];
    let expected = &mut expected[..CTILDE];
    commit.finalize_at(expected);

    c_tilde.ct_eq(&expected[..]).is_true()
}

/// Recompute the public `t1` of a signing key, by redoing the `t = A s1 + s2`
/// of key generation and rounding it the same way
fn public_from_secret<const K: usize, const L: usize, const ETA_BITS: usize>(
    sk: &[u8],
    eta: u32,
    pk: &mut [u8],
) {
    let parts = sk_decode::<K, L, ETA_BITS>(sk, eta)
        .expect("a signing key is checked when it is deserialised");

    let mut s1_hat = parts.s1;
    for p in s1_hat.iter_mut() {
        p.ntt();
    }

    let mut t1 = [Poly::ZERO; K];
    for (i, (t1i, s2i)) in t1.iter_mut().zip(parts.s2.iter()).enumerate() {
        let mut t = matrix_row_mul(&parts.rho, i, &s1_hat);
        t.inv_ntt();
        t.add_mut(s2i);
        (*t1i, _) = t.power2round();
    }

    pk_encode::<K>(&parts.rho, &t1, pk);
}

/// Potential Error that can happens during signing operation
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningError {
    /// Invalid Context Length. only support up to [`MAX_CONTEXT_LENGTH`] bytes
    InvalidContextLength,
    /// Signing Key has invalid range
    SigningKeyInvalidRange,
}

/// Build the message representative `M'` and hand its pieces to `f`
///
/// `M'` is the concatenation of a domain separator, the length prefixed context
/// string and the message, in the pure case, or the digest and its object
/// identifier in the pre hashed one. It is passed along as its pieces so that a
/// large message never has to be copied into a buffer of its own.
fn message_representative<T>(
    prehash: Option<PreHash>,
    message: &[u8],
    context: &[u8],
    f: impl FnOnce(&[&[u8]]) -> Result<T, SigningError>,
) -> Result<T, SigningError> {
    if context.len() > MAX_CONTEXT_LENGTH {
        return Err(SigningError::InvalidContextLength);
    }
    match prehash {
        None => f(&[&[0u8, context.len() as u8], context, message]),
        Some(ph) => {
            let mut buf = [0u8; PreHash::MAX_DIGEST];
            let digest = ph.hash(message, &mut buf);
            f(&[&[1u8, context.len() as u8], context, &ph.oid(), digest])
        }
    }
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

        impl $sk {
            /// Length in bytes of the serialised key
            pub const LENGTH: usize = $sk_len;

            /// Deserialise a signing key, checking the range that FIPS 204
            /// requires of the `s1` and `s2` it encodes
            ///
            /// The `tr` that the key carries is not cross checked against the
            /// vectors it accompanies, which FIPS 204 does not ask for either:
            /// a key whose `tr` does not belong to it simply signs nothing that
            /// its own verifying key accepts.
            pub fn from_bytes(bytes: [u8; $sk_len]) -> Result<Self, SigningKeyErrorInvalidRange> {
                sk_decode::<$k, $l, $eta_bits>(&bytes, $eta)?;
                Ok($sk(bytes))
            }

            /// The verifying key of the same key pair
            ///
            /// A signing key carries only the hash of its verifying key, so
            /// this recomputes `t` from the secret vectors and costs about as
            /// much as key generation. Keep the key returned by
            #[doc = concat!("[`", stringify!($keypair), "`] instead when there is one to keep.")]
            pub fn verifying_key(&self) -> $vk {
                let mut vk = [0u8; $vk_len];
                public_from_secret::<$k, $l, $eta_bits>(&self.0, $eta, &mut vk);
                $vk(vk)
            }

            #[doc = concat!("Sign `message` with this ", $set, " key, hedging with `rnd`")]
            ///
            /// `rnd` must be 32 freshly generated random bytes, and does not
            /// have to be kept secret; see the
            /// [module documentation](crate::mldsa#randomness). `context` is
            /// bound into the signature and must be at most
            /// [`MAX_CONTEXT_LENGTH`] bytes, which is the only way this can
            /// fail.
            pub fn sign(
                &self,
                message: &[u8],
                context: &[u8],
                rnd: &[u8; RANDOMIZER_LENGTH],
            ) -> Result<$sigt, SigningError> {
                self.sign_with(None, message, context, rnd)
            }

            #[doc = concat!("Sign `message` with this ", $set, " key, without any randomness")]
            ///
            /// This is the deterministic variant of FIPS 204: the same message
            /// and context always give the same signature. Prefer
            /// [`sign`](Self::sign) where fresh randomness is available.
            pub fn sign_deterministic(
                &self,
                message: &[u8],
                context: &[u8],
            ) -> Result<$sigt, SigningError> {
                self.sign_with(None, message, context, &[0u8; RANDOMIZER_LENGTH])
            }

            /// Sign a digest of `message` rather than the message itself,
            /// hedging with `rnd`
            ///
            /// This is `HashML-DSA` (FIPS 204 section 5.4); the signature it
            /// produces is not interchangeable with the one
            /// [`sign`](Self::sign) makes over the same message.
            pub fn sign_prehash(
                &self,
                prehash: PreHash,
                message: &[u8],
                context: &[u8],
                rnd: &[u8; RANDOMIZER_LENGTH],
            ) -> Result<$sigt, SigningError> {
                self.sign_with(Some(prehash), message, context, rnd)
            }

            /// Sign a digest of `message` rather than the message itself,
            /// without any randomness
            pub fn sign_prehash_deterministic(
                &self,
                prehash: PreHash,
                message: &[u8],
                context: &[u8],
            ) -> Result<$sigt, SigningError> {
                self.sign_with(Some(prehash), message, context, &[0u8; RANDOMIZER_LENGTH])
            }

            fn sign_with(
                &self,
                prehash: Option<PreHash>,
                message: &[u8],
                context: &[u8],
                rnd: &[u8; RANDOMIZER_LENGTH],
            ) -> Result<$sigt, SigningError> {
                let mut sig = [0u8; $sig_len];
                message_representative(prehash, message, context, |m| {
                    sign_internal::<
                        $k,
                        $l,
                        $eta,
                        $eta_bits,
                        $tau,
                        $gamma1,
                        $gamma1_bits,
                        $gamma2,
                        $w1_bits,
                        $omega,
                        $ctilde,
                    >(&self.0, m, rnd, &mut sig)
                    .map_err(|_: SigningKeyErrorInvalidRange| SigningError::SigningKeyInvalidRange)
                })?;
                Ok($sigt(sig))
            }

            /// Raw bytes array for the signing key
            pub fn bytes(&self) -> &[u8; $sk_len] {
                &self.0
            }
        }

        impl $vk {
            /// Length in bytes of the serialised key
            pub const LENGTH: usize = $vk_len;

            /// Deserialise a verifying key
            ///
            /// Verifying Key doesn't need a particular structure, any bytes encoding
            /// lead to a valid verifying key.
            pub fn from_bytes(bytes: [u8; $vk_len]) -> Self {
                $vk(bytes)
            }

            #[doc = concat!("Verify an ", $set, " signature over `message`")]
            ///
            /// `context` must be the one the signature was made with, and the
            /// signature must have been made by
            #[doc = concat!("[`", stringify!($sk), "::sign`] rather than by one of the")]
            /// pre hash methods, or this returns false.
            pub fn verify(&self, message: &[u8], context: &[u8], signature: &$sigt) -> bool {
                self.verify_with(None, message, context, signature)
            }

            #[doc = concat!("Verify a signature made by [`", stringify!($sk), "::sign_prehash`]")]
            ///
            /// `prehash` must be the hash function the signer used: a signature
            /// over a digest of one function is not accepted as one over the
            /// digest of another.
            pub fn verify_prehash(
                &self,
                prehash: PreHash,
                message: &[u8],
                context: &[u8],
                signature: &$sigt,
            ) -> bool {
                self.verify_with(Some(prehash), message, context, signature)
            }

            fn verify_with(
                &self,
                prehash: Option<PreHash>,
                message: &[u8],
                context: &[u8],
                signature: &$sigt,
            ) -> bool {
                message_representative(prehash, message, context, |m| {
                    Ok(verify_internal::<
                        $k,
                        $l,
                        $eta,
                        $tau,
                        $gamma1,
                        $gamma1_bits,
                        $gamma2,
                        $w1_bits,
                        $omega,
                        $ctilde,
                    >(&self.0, m, &signature.0))
                })
                .unwrap_or(false)
            }

            /// Raw bytes array for the verifying key
            pub fn bytes(&self) -> &[u8; $vk_len] {
                &self.0
            }
        }

        impl $sigt {
            /// Length in bytes of the serialised signature
            pub const LENGTH: usize = $sig_len;

            /// Deserialise a signature
            ///
            /// Only the length is checked here. If the hints are malformed
            /// it will be decided during verification.
            ///
            /// Ideally we would distinguish bytes from signature but it leads
            /// to some difficulties related to const generics; it might
            /// be re-evaluated later providing a validating signature object in
            /// the future.
            pub fn from_bytes(bytes: [u8; $sig_len]) -> Self {
                $sigt(bytes)
            }

            /// Raw bytes array for the signature
            pub fn bytes(&self) -> &[u8; $sig_len] {
                &self.0
            }
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

        impl AsRef<[u8]> for $vk {
            fn as_ref(&self) -> &[u8] {
                &self.0[..]
            }
        }

        impl AsRef<[u8]> for $sk {
            fn as_ref(&self) -> &[u8] {
                &self.0[..]
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

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "with-bench"))]
mod bench {}
