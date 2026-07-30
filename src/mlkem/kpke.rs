//! K-PKE, the IND-CPA secure public key encryption scheme underlying ML-KEM
//! (FIPS 203 section 5)
//!
//! K-PKE is deterministic: all of its randomness is passed in explicitly. It is
//! only a building block and offers no chosen ciphertext security of its own,
//! hence its confinement to this crate.

use super::poly::{sample_cbd, sample_ntt, Poly, ENCODED12};
use crate::hashing::{sha3::Sha3_512, shake::Shake256};

/// Largest `64 * ETA` used by any parameter set, ie. the `eta = 3` of ML-KEM-512
const MAX_PRF_OUTPUT: usize = 64 * 3;

/// Sample a polynomial from the centered binomial distribution seeded by
/// `PRF_eta(s, n)`, the pseudo random function of FIPS 203 section 4.1
fn cbd<const ETA: usize>(s: &[u8; 32], n: u8) -> Poly {
    let mut buf = [0u8; MAX_PRF_OUTPUT];
    let buf = &mut buf[..64 * ETA];
    Shake256::new().update(s).update(&[n]).finalize_at(buf);
    sample_cbd::<ETA>(buf)
}

/// K-PKE.KeyGen (FIPS 203 Algorithm 13)
///
/// Expands the seed `d` into an encapsulation key of `384 * K + 32` bytes and a
/// decapsulation key of `384 * K` bytes.
pub(super) fn keygen<const K: usize, const ETA1: usize>(
    d: &[u8; 32],
    ek: &mut [u8],
    dk: &mut [u8],
) {
    assert_eq!(ek.len(), ENCODED12 * K + 32);
    assert_eq!(dk.len(), ENCODED12 * K);

    // the length of the seed is bound to the parameter set, so that two
    // parameter sets never derive anything from the same expanded seed
    let g = Sha3_512::new().update(d).update(&[K as u8]).finalize();
    let (rho, sigma) = seeds(&g);

    let mut s: [Poly; K] = core::array::from_fn(|i| cbd::<ETA1>(sigma, i as u8));
    let mut e: [Poly; K] = core::array::from_fn(|i| cbd::<ETA1>(sigma, (K + i) as u8));
    for p in s.iter_mut().chain(e.iter_mut()) {
        p.ntt();
    }

    // t = A s + e, one row of A at a time so that the whole matrix, which is
    // the largest object in the scheme, is never materialised
    for (i, ei) in e.iter().enumerate() {
        let mut t = *ei;
        for (j, sj) in s.iter().enumerate() {
            t.mul_acc(&sample_ntt(rho, j as u8, i as u8), sj);
        }
        t.encode::<12>(&mut ek[i * ENCODED12..(i + 1) * ENCODED12]);
    }
    ek[ENCODED12 * K..].copy_from_slice(rho);

    for (i, si) in s.iter().enumerate() {
        si.encode::<12>(&mut dk[i * ENCODED12..(i + 1) * ENCODED12]);
    }
}

/// K-PKE.Encrypt (FIPS 203 Algorithm 14)
///
/// Encrypts the 32 bytes `m` under `ek` using `r` as randomness, into a
/// ciphertext of `32 * (DU * K + DV)` bytes.
pub(super) fn encrypt<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    ek: &[u8],
    m: &[u8; 32],
    r: &[u8; 32],
    ct: &mut [u8],
) {
    assert_eq!(ek.len(), ENCODED12 * K + 32);
    assert_eq!(ct.len(), 32 * (DU * K + DV));

    let t: [Poly; K] =
        core::array::from_fn(|i| Poly::decode::<12>(&ek[i * ENCODED12..(i + 1) * ENCODED12]));
    let rho = array32(&ek[ENCODED12 * K..]);

    let mut y: [Poly; K] = core::array::from_fn(|i| cbd::<ETA1>(r, i as u8));
    let e1: [Poly; K] = core::array::from_fn(|i| cbd::<ETA2>(r, (K + i) as u8));
    let e2 = cbd::<ETA2>(r, (2 * K) as u8);
    for p in y.iter_mut() {
        p.ntt();
    }

    let (c1, c2) = ct.split_at_mut(32 * DU * K);

    // u = NTT^-1(A^t y) + e1, transposing A by swapping the two seed bytes
    for (i, e1i) in e1.iter().enumerate() {
        let mut u = Poly::ZERO;
        for (j, yj) in y.iter().enumerate() {
            u.mul_acc(&sample_ntt(rho, i as u8, j as u8), yj);
        }
        u.inv_ntt();
        u.add_mut(e1i);
        u.compress_encode::<DU>(&mut c1[i * 32 * DU..(i + 1) * 32 * DU]);
    }

    // v = NTT^-1(t^t y) + e2 + Decompress_1(m), the message bits landing on the
    // two extremes of the field so that a small enough error is recoverable
    let mut v = Poly::ZERO;
    for (tj, yj) in t.iter().zip(y.iter()) {
        v.mul_acc(tj, yj);
    }
    v.inv_ntt();
    v.add_mut(&e2);
    v.add_mut(&Poly::decode_decompress::<1>(m));
    v.compress_encode::<DV>(c2);
}

/// K-PKE.Decrypt (FIPS 203 Algorithm 15)
pub(super) fn decrypt<const K: usize, const DU: usize, const DV: usize>(
    dk: &[u8],
    ct: &[u8],
) -> [u8; 32] {
    assert_eq!(dk.len(), ENCODED12 * K);
    assert_eq!(ct.len(), 32 * (DU * K + DV));

    let (c1, c2) = ct.split_at(32 * DU * K);

    let mut u: [Poly; K] = core::array::from_fn(|i| {
        Poly::decode_decompress::<DU>(&c1[i * 32 * DU..(i + 1) * 32 * DU])
    });
    for p in u.iter_mut() {
        p.ntt();
    }

    // w = v - s^t u is the message plus the noise accumulated by the scheme
    let mut su = Poly::ZERO;
    for (i, ui) in u.iter().enumerate() {
        su.mul_acc(
            &Poly::decode::<12>(&dk[i * ENCODED12..(i + 1) * ENCODED12]),
            ui,
        );
    }
    su.inv_ntt();

    let mut w = Poly::decode_decompress::<DV>(c2);
    w.sub_mut(&su);

    let mut m = [0u8; 32];
    w.compress_encode::<1>(&mut m);
    m
}

/// Split the 64 bytes output of `G` into its two 32 bytes halves
fn seeds(g: &[u8; 64]) -> (&[u8; 32], &[u8; 32]) {
    let (a, b) = g.split_at(32);
    (array32(a), array32(b))
}

fn array32(s: &[u8]) -> &[u8; 32] {
    <&[u8; 32]>::try_from(s).unwrap()
}
