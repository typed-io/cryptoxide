//! FORS, the Forest Of Random Subsets few-time signature scheme (FIPS 205
//! section 8)
//!
//! A FORS key is `k` Merkle trees of height `a`, whose leaves are the hashes
//! of secret values. A message digest is cut into `k` indices of `a` bits, and
//! the signature reveals, in each tree, the secret value of the leaf at its
//! index along with its authentication path. The public key is the hash of
//! the `k` roots.
//!
//! The key pair a message is signed with is picked by the digest of the
//! message, so a FORS key signs only the few messages that happen to land on
//! it, and each of them reveals only one leaf per tree.

use super::address::{Adrs, AdrsType};
use super::hash::Hasher;
use super::params::{MAX_A, MAX_K, ParameterSet};
use super::tree::treehash;

/// `base_2b` (FIPS 205 Algorithm 4): the first `out.len()` integers of `b`
/// bits of `x`, most significant bits first
fn base_2b(x: &[u8], b: usize, out: &mut [u32]) {
    let mut bytes = x.iter();
    let mut bits = 0;
    let mut total: u32 = 0;
    for o in out.iter_mut() {
        while bits < b {
            total = (total << 8) | *bytes.next().unwrap() as u32;
            bits += 8;
        }
        bits -= b;
        *o = total >> bits;
        // only the bits not yet read are kept, which bounds `total` to b + 7 bits
        total &= (1 << bits) - 1;
    }
}

/// The FORS indices of a message digest `md`, an integer of `a` bits per tree
fn indices<const N: usize, P: ParameterSet<N>>(md: &[u8]) -> [u32; MAX_K] {
    let mut indices = [0u32; MAX_K];
    base_2b(md, P::A, &mut indices[..P::K]);
    indices
}

/// The public key of a FORS key pair, the hash of the roots of its trees
fn pk_from_roots<const N: usize, P: ParameterSet<N>>(
    hs: &P::Hash,
    adrs: &Adrs,
    roots: &[[u8; N]],
) -> [u8; N] {
    let pk_adrs = adrs.with_type_keeping_keypair(AdrsType::ForsRoots);
    hs.t(&pk_adrs, roots)
}

/// `fors_sign` (FIPS 205 Algorithm 16) of the digest `md`, into the
/// `k (1 + a) n` bytes of `sig`, returning the public key of the key pair
///
/// `adrs` is the `FORS_TREE` address of the key pair. The roots of the trees
/// come out of computing their authentication paths, so the public key that
/// `fors_pkFromSig` (Algorithm 17) would recompute from the signature is here
/// for free.
pub(super) fn sign<const N: usize, P: ParameterSet<N>>(
    hs: &P::Hash,
    md: &[u8],
    sk_seed: &[u8; N],
    adrs: &Adrs,
    sig: &mut [u8],
) -> [u8; N] {
    let indices = indices::<N, P>(md);
    let mut roots = [[0u8; N]; MAX_K];

    // the secret value of leaf i, `fors_skGen` (Algorithm 14)
    let sk_adrs = adrs.with_type_keeping_keypair(AdrsType::ForsPrf);
    let secret_pair = |i: u32| {
        let mut a = sk_adrs;
        a.set_tree_index(i);
        let mut b = sk_adrs;
        b.set_tree_index(i + 1);
        hs.prf_x2([&a, &b], sk_seed)
    };

    for (t, (part, root)) in sig
        .chunks_exact_mut((1 + P::A) * N)
        .zip(roots.iter_mut())
        .enumerate()
    {
        let first = (t << P::A) as u32;
        let target = first + indices[t];
        let mut auth = [[0u8; N]; MAX_A];
        let mut secret = [0u8; N];

        *root = treehash(
            first,
            P::A,
            Some(target),
            &mut auth[..P::A],
            // the leaves are the hashes of the secret values, `fors_node` at
            // height 0
            |i| {
                let sk = secret_pair(i);
                // the secret value of the target leaf is part of the signature
                if i == target & !1 {
                    secret = sk[(target & 1) as usize];
                }
                let mut a = *adrs;
                a.set_tree_height(0);
                a.set_tree_index(i);
                let mut b = a;
                b.set_tree_index(i + 1);
                hs.f_x2([&a, &b], [&sk[0], &sk[1]])
            },
            |left, right, z, i| {
                let mut a = *adrs;
                a.set_tree_height(z);
                a.set_tree_index(i);
                hs.h(&a, left, right)
            },
        );

        let (sk_part, auth_part) = part.split_at_mut(N);
        sk_part.copy_from_slice(&secret);
        auth_part.copy_from_slice(auth[..P::A].as_flattened());
    }

    pk_from_roots::<N, P>(hs, adrs, &roots[..P::K])
}

/// `fors_pkFromSig` (FIPS 205 Algorithm 17), the public key that `sig` is a
/// signature of the digest `md` under
///
/// `adrs` is the `FORS_TREE` address of the key pair.
pub(super) fn pk_from_sig<const N: usize, P: ParameterSet<N>>(
    hs: &P::Hash,
    sig: &[u8],
    md: &[u8],
    adrs: &Adrs,
) -> [u8; N] {
    let indices = indices::<N, P>(md);
    let mut roots = [[0u8; N]; MAX_K];
    let mut a = *adrs;

    for (t, (part, root)) in sig
        .chunks_exact((1 + P::A) * N)
        .zip(roots.iter_mut())
        .enumerate()
    {
        let (sk, auth) = part.split_first_chunk::<N>().unwrap();
        let leaf = ((t << P::A) as u32) + indices[t];

        a.set_tree_height(0);
        a.set_tree_index(leaf);
        let mut node = hs.f(&a, sk);

        for (j, sibling) in auth.as_chunks::<N>().0.iter().enumerate() {
            a.set_tree_height(j as u32 + 1);
            a.set_tree_index(leaf >> (j + 1));
            node = if (indices[t] >> j) & 1 == 0 {
                hs.h(&a, &node, sibling)
            } else {
                hs.h(&a, sibling, &node)
            };
        }
        *root = node;
    }

    pk_from_roots::<N, P>(hs, adrs, &roots[..P::K])
}

#[cfg(test)]
mod tests {
    use super::base_2b;

    #[test]
    fn base_2b_reads_most_significant_bits_first() {
        let mut out = [0u32; 4];
        base_2b(&[0b1010_1100, 0b0101_1111, 0b0000_0001], 6, &mut out);
        assert_eq!(out, [0b101011, 0b000101, 0b111100, 0b000001]);

        let mut out = [0u32; 2];
        base_2b(&[0xab, 0xcd, 0xef], 12, &mut out);
        assert_eq!(out, [0xabc, 0xdef]);

        let mut out = [0u32; 1];
        base_2b(&[0xff, 0xff], 14, &mut out);
        assert_eq!(out, [0x3fff]);
    }
}
