//! Serialisation of the ML-DSA keys and signatures (FIPS 204 section 7.2)

use crate::mldsa::poly::N;

use super::group::D;
use super::poly::{Hint, Poly};

/// Number of bits per coefficient of the encoded `t1`, ie. `bitlen(Q-1) - D`
const T1_BITS: usize = 10;

/// Size in bytes of one encoded polynomial of `t1`
pub(super) const T1_ENCODED: usize = 32 * T1_BITS;

/// Size in bytes of one encoded polynomial of `t0`, whose coefficients take the
/// `D` bits that `Power2Round` dropped
const T0_ENCODED: usize = 32 * D;

/// Size in bytes of the seeds and hash that a signing key starts with:
/// `rho`, `K` and `tr`
pub(super) const SK_HEAD: usize = 32 + 32 + 64;

/// FIPS 204 Algorithm 22 `pkEncode`
pub(super) fn pk_encode<const K: usize>(rho: &[u8; 32], t1: &[Poly; K], pk: &mut [u8]) {
    assert_eq!(pk.len(), 32 + K * T1_ENCODED);

    let (out_rho, out_t1) = pk.split_at_mut(32);
    out_rho.copy_from_slice(rho);
    for (p, chunk) in t1.iter().zip(out_t1.chunks_exact_mut(T1_ENCODED)) {
        p.simple_pack::<T1_BITS>(chunk);
    }
}

/// FIPS 204 Algorithm 24 `skEncode`
#[allow(clippy::too_many_arguments)]
pub(super) fn sk_encode<const K: usize, const L: usize, const ETA_BITS: usize>(
    rho: &[u8; 32],
    k_seed: &[u8; 32],
    tr: &[u8; 64],
    s1: &[Poly; L],
    s2: &[Poly; K],
    t0: &[Poly; K],
    eta: u32,
    sk: &mut [u8],
) {
    let s_len = 32 * ETA_BITS;
    assert_eq!(sk.len(), SK_HEAD + (L + K) * s_len + K * T0_ENCODED);

    let (head, tail) = sk.split_at_mut(SK_HEAD);
    head[..32].copy_from_slice(rho);
    head[32..64].copy_from_slice(k_seed);
    head[64..].copy_from_slice(tr);

    let (out_s1, tail) = tail.split_at_mut(L * s_len);
    let (out_s2, out_t0) = tail.split_at_mut(K * s_len);
    for (p, chunk) in s1.iter().zip(out_s1.chunks_exact_mut(s_len)) {
        p.signed_pack::<ETA_BITS>(eta as i32, chunk);
    }
    for (p, chunk) in s2.iter().zip(out_s2.chunks_exact_mut(s_len)) {
        p.signed_pack::<ETA_BITS>(eta as i32, chunk);
    }
    for (p, chunk) in t0.iter().zip(out_t0.chunks_exact_mut(T0_ENCODED)) {
        p.signed_pack::<D>(1 << (D - 1), chunk);
    }
}

/// The parts of a signing key, as FIPS 204 Algorithm 25 `skDecode` recovers them
pub(super) struct SigningKeyParts<const K: usize, const L: usize> {
    pub(super) rho: [u8; 32],
    pub(super) k_seed: [u8; 32],
    pub(super) tr: [u8; 64],
    pub(super) s1: [Poly; L],
    pub(super) s2: [Poly; K],
    pub(super) t0: [Poly; K],
}

/// The signing key holds a coefficient of `s1` or `s2` outside of the
/// `-eta ..= eta` that key generation produces. Such a key cannot have been
/// produced by key generation.
#[derive(Clone, Copy, Debug)]
pub struct SigningKeyErrorInvalidRange;

/// FIPS 204 Algorithm 25 `skDecode`
///
/// Return Err if the signing key holds a coefficient of `s1` or `s2` outside of the
/// `-eta ..= eta` that key generation produces. Such a key cannot have been
/// produced by key generation
pub(super) fn sk_decode<const K: usize, const L: usize, const ETA_BITS: usize>(
    sk: &[u8],
    eta: u32,
) -> Result<SigningKeyParts<K, L>, SigningKeyErrorInvalidRange> {
    let s_len = 32 * ETA_BITS;
    assert_eq!(sk.len(), SK_HEAD + (L + K) * s_len + K * T0_ENCODED);

    let (head, tail) = sk.split_at(SK_HEAD);
    let (in_s1, tail) = tail.split_at(L * s_len);
    let (in_s2, in_t0) = tail.split_at(K * s_len);

    let s1: [Poly; L] = core::array::from_fn(|i| {
        Poly::signed_unpack::<ETA_BITS>(&in_s1[i * s_len..(i + 1) * s_len], eta as i32)
    });
    let s2: [Poly; K] = core::array::from_fn(|i| {
        Poly::signed_unpack::<ETA_BITS>(&in_s2[i * s_len..(i + 1) * s_len], eta as i32)
    });

    // the encoding gives each coefficient of s1 and s2 one more value than the
    // -eta..=eta they are meant to hold, so a key that key generation did not
    // produce can decode out of range. Everything else in a signing key of the
    // right length is well formed by construction.
    if s1.iter().chain(s2.iter()).any(|p| p.norm() > eta) {
        return Err(SigningKeyErrorInvalidRange);
    }

    let t0: [Poly; K] = core::array::from_fn(|i| {
        Poly::signed_unpack::<D>(&in_t0[i * T0_ENCODED..(i + 1) * T0_ENCODED], 1 << (D - 1))
    });

    let mut parts = SigningKeyParts {
        rho: [0u8; 32],
        k_seed: [0u8; 32],
        tr: [0u8; 64],
        s1,
        s2,
        t0,
    };
    parts.rho.copy_from_slice(&head[..32]);
    parts.k_seed.copy_from_slice(&head[32..64]);
    parts.tr.copy_from_slice(&head[64..]);
    Ok(parts)
}

/// FIPS 204 Algorithm 26 `sigEncode`
pub(super) fn sig_encode<
    const K: usize,
    const L: usize,
    const GAMMA1_BITS: usize,
    const OMEGA: usize,
>(
    c_tilde: &[u8],
    z: &[Poly; L],
    h: &[Hint; K],
    gamma1: u32,
    sig: &mut [u8],
) {
    let z_len = 32 * GAMMA1_BITS;
    assert_eq!(sig.len(), c_tilde.len() + L * z_len + OMEGA + K);

    let (out_c, tail) = sig.split_at_mut(c_tilde.len());
    out_c.copy_from_slice(c_tilde);
    let (out_z, out_h) = tail.split_at_mut(L * z_len);
    for (p, chunk) in z.iter().zip(out_z.chunks_exact_mut(z_len)) {
        p.signed_pack::<GAMMA1_BITS>(gamma1 as i32, chunk);
    }
    hint_pack::<K, OMEGA>(h, out_h);
}

/// FIPS 204 Algorithm 20 `HintBitPack`
///
/// The hint is written as the sorted positions of its set bits, followed by one
/// running total per polynomial saying where that polynomial's positions end.
fn hint_pack<const K: usize, const OMEGA: usize>(h: &[Hint; K], out: &mut [u8]) {
    assert_eq!(out.len(), OMEGA + K);

    out.fill(0);
    let mut index = 0;
    for (i, hi) in h.iter().enumerate() {
        for j in 0..N {
            if hi.get(j) {
                out[index] = j as u8;
                index += 1;
            }
        }
        out[OMEGA + i] = index as u8;
    }
}
