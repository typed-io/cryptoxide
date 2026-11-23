//! WOTS+, the Winternitz One-Time Signature scheme (FIPS 205 section 5)
//!
//! A WOTS+ key is `len` hash chains of length `w - 1` that start at secret
//! values. A message is cut into `len1` digits, followed by `len2` digits of a
//! checksum, and each digit says how far along its chain the signature
//! reveals. Moving forward is easy and moving back is not, and the checksum
//! makes sure that anything a forger could derive from a signature by moving
//! some chains forward has to move others back.

use super::address::{Adrs, AdrsType};
use super::hash::Hasher;
use super::params::{LG_W, MAX_LEN, ParameterSet, W};

/// `chain` (FIPS 205 Algorithm 5): `steps` iterations of `F` from position `start`
fn chain<const N: usize, H: Hasher<N>>(
    hs: &H,
    mut x: [u8; N],
    start: u32,
    steps: u32,
    adrs: &mut Adrs,
) -> [u8; N] {
    for j in start..start + steps {
        adrs.set_hash(j);
        x = hs.f(adrs, &x);
    }
    x
}

/// The `len` digits of a message and its checksum (FIPS 205 Algorithm 7, lines 1 to 9)
fn digits<const N: usize, P: ParameterSet<N>>(m: &[u8; N]) -> [u8; MAX_LEN] {
    const _: () = assert!(LG_W == 4);
    let mut d = [0u8; MAX_LEN];
    // base_2b(M, lg_w, len1), each byte is two digits, most significant first
    for (pair, byte) in d.as_chunks_mut::<2>().0.iter_mut().zip(m.iter()) {
        pair[0] = byte >> 4;
        pair[1] = byte & 0xf;
    }
    let csum: u32 = d[..P::LEN1].iter().map(|&x| W - 1 - x as u32).sum();
    // the checksum shifted to the top of toByte(csum, 2), and read back as its
    // len2 = 3 first digits: the low 4 bits of the 16 are left out, so the 3
    // digits are exactly the 12 bits of the checksum
    d[P::LEN1] = (csum >> 8) as u8 & 0xf;
    d[P::LEN1 + 1] = (csum >> 4) as u8 & 0xf;
    d[P::LEN1 + 2] = csum as u8 & 0xf;
    d
}

/// `wots_pkGen` (FIPS 205 Algorithm 6) of two key pairs at once
///
/// `adrs` are the `WOTS_HASH` addresses of the two key pairs. Their chains are
/// all the same length, so the two key pairs are walked in lockstep, two calls
/// of each hash function at a time.
pub(super) fn pk_gen_x2<const N: usize, P: ParameterSet<N>>(
    hs: &P::Hash,
    sk_seed: &[u8; N],
    adrs: [Adrs; 2],
) -> [[u8; N]; 2] {
    let mut sk_adrs = adrs.map(|a| a.with_type_keeping_keypair(AdrsType::WotsPrf));
    let mut chain_adrs = adrs;
    let mut tops = [[[0u8; N]; MAX_LEN]; 2];
    let [tops0, tops1] = &mut tops;
    for (i, (top0, top1)) in tops0
        .iter_mut()
        .zip(tops1.iter_mut())
        .take(P::LEN)
        .enumerate()
    {
        sk_adrs.iter_mut().for_each(|a| a.set_chain(i as u32));
        chain_adrs.iter_mut().for_each(|a| a.set_chain(i as u32));
        let mut x = hs.prf_x2([&sk_adrs[0], &sk_adrs[1]], sk_seed);
        for j in 0..W - 1 {
            chain_adrs.iter_mut().for_each(|a| a.set_hash(j));
            x = hs.f_x2([&chain_adrs[0], &chain_adrs[1]], [&x[0], &x[1]]);
        }
        [*top0, *top1] = x;
    }
    let pk_adrs = adrs.map(|a| a.with_type_keeping_keypair(AdrsType::WotsPk));
    hs.t_x2(
        [&pk_adrs[0], &pk_adrs[1]],
        [&tops[0][..P::LEN], &tops[1][..P::LEN]],
    )
}

/// `wots_sign` (FIPS 205 Algorithm 7) of `m`, into the `len n` bytes of `sig`
///
/// `adrs` is the `WOTS_HASH` address of the key pair.
pub(super) fn sign<const N: usize, P: ParameterSet<N>>(
    hs: &P::Hash,
    m: &[u8; N],
    sk_seed: &[u8; N],
    adrs: &Adrs,
    sig: &mut [u8],
) {
    let digits = digits::<N, P>(m);
    let mut sk_adrs = adrs.with_type_keeping_keypair(AdrsType::WotsPrf);
    let mut chain_adrs = *adrs;
    for (i, (out, &digit)) in sig
        .as_chunks_mut::<N>()
        .0
        .iter_mut()
        .zip(digits[..P::LEN].iter())
        .enumerate()
    {
        sk_adrs.set_chain(i as u32);
        chain_adrs.set_chain(i as u32);
        let sk = hs.prf(&sk_adrs, sk_seed);
        *out = chain(hs, sk, 0, digit as u32, &mut chain_adrs);
    }
}

/// `wots_pkFromSig` (FIPS 205 Algorithm 8), the public key that `sig` is a
/// signature of `m` under, if it is one at all
///
/// `adrs` is the `WOTS_HASH` address of the key pair.
pub(super) fn pk_from_sig<const N: usize, P: ParameterSet<N>>(
    hs: &P::Hash,
    sig: &[u8],
    m: &[u8; N],
    adrs: &Adrs,
) -> [u8; N] {
    let digits = digits::<N, P>(m);
    let mut chain_adrs = *adrs;
    let mut tops = [[0u8; N]; MAX_LEN];
    for (i, (top, (s, &digit))) in tops
        .iter_mut()
        .zip(sig.as_chunks::<N>().0.iter().zip(digits[..P::LEN].iter()))
        .enumerate()
    {
        chain_adrs.set_chain(i as u32);
        *top = chain(hs, *s, digit as u32, W - 1 - digit as u32, &mut chain_adrs);
    }
    let pk_adrs = adrs.with_type_keeping_keypair(AdrsType::WotsPk);
    hs.t(&pk_adrs, &tops[..P::LEN])
}
