//! Serialisation of the ML-DSA keys and signatures (FIPS 204 section 7.2)

use super::group::D;
use super::poly::Poly;

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
