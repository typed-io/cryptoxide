//! The Merkle trees of SLH-DSA: XMSS (FIPS 205 section 6) and the hypertree
//! of XMSS trees (section 7), along with the tree hash both XMSS and FORS
//! compute their trees with
//!
//! FIPS 205 specifies the node of a tree recursively (`xmss_node` and
//! `fors_node`), and an authentication path as the nodes next to the path
//! from a leaf to the root, each computed on its own. They are computed here
//! instead by a single pass over the leaves of the tree, which produces every
//! node exactly once and keeps only a stack of one node per height, picking
//! the root and the authentication path as they go by.

use super::address::{Adrs, AdrsType};
use super::hash::Hasher;
use super::params::{MAX_A, MAX_HP, ParameterSet};
use super::wots;
use crate::constant_time::CtEqual;

/// Height of the highest tree, of either kind
const MAX_HEIGHT: usize = if MAX_A > MAX_HP { MAX_A } else { MAX_HP };

/// The root of the tree of height `height` whose leaves are numbered from
/// `first`, and the authentication path of its leaf `target` into `auth`
///
/// `leaves(i)` gives the leaves `i` and `i + 1`, so that a pair of leaves can
/// be computed at once, and `node(left, right, z, i)` gives the node of index
/// `i` at height `z` from its two children. The indices are those of the whole
/// row of the tree they are in, `i >> z` for the leaf `i` below them, which is
/// how FORS numbers the nodes of its `k` trees. `height` is at least 1.
pub(super) fn treehash<const N: usize>(
    first: u32,
    height: usize,
    target: Option<u32>,
    auth: &mut [[u8; N]],
    mut leaves: impl FnMut(u32) -> [[u8; N]; 2],
    mut node: impl FnMut(&[u8; N], &[u8; N], u32, u32) -> [u8; N],
) -> [u8; N] {
    debug_assert!((1..=MAX_HEIGHT).contains(&height));
    // whether the node of index `index` at height `z` is on the authentication
    // path, the sibling of the node of the target leaf at that height
    let mut keep = |z: u32, index: u32, value: &[u8; N]| {
        if let Some(target) = target
            && index == (target >> z) ^ 1
        {
            auth[z as usize] = *value;
        }
    };

    // the nodes waiting for their sibling, the higher the older, of strictly
    // decreasing heights from the bottom of the stack
    let mut stack = [[0u8; N]; MAX_HEIGHT];
    let mut heights = [0u32; MAX_HEIGHT];
    let mut sp = 0;

    for leaf in (first..first + (1 << height)).step_by(2) {
        let [l, r] = leaves(leaf);
        keep(0, leaf, &l);
        keep(0, leaf + 1, &r);
        let mut z = 1;
        let mut value = node(&l, &r, z, leaf >> z);
        keep(z, leaf >> z, &value);
        while sp > 0 && heights[sp - 1] == z {
            sp -= 1;
            z += 1;
            value = node(&stack[sp], &value, z, leaf >> z);
            keep(z, leaf >> z, &value);
        }
        stack[sp] = value;
        heights[sp] = z;
        sp += 1;
    }
    debug_assert!(sp == 1 && heights[0] == height as u32);
    stack[0]
}

/// The XMSS tree whose layer and tree addresses are those of `adrs`: its root,
/// and the authentication path of its leaf `target` into `auth`
fn xmss_tree<const N: usize, P: ParameterSet<N>>(
    hs: &P::Hash,
    sk_seed: &[u8; N],
    adrs: &Adrs,
    target: Option<u32>,
    auth: &mut [[u8; N]],
) -> [u8; N] {
    treehash(
        0,
        P::HP,
        target,
        auth,
        // the leaves are the WOTS+ public keys, `xmss_node` at height 0
        |i| {
            let mut a = *adrs;
            a.set_type_and_clear(AdrsType::WotsHash);
            a.set_keypair(i);
            let mut b = a;
            b.set_keypair(i + 1);
            wots::pk_gen_x2::<N, P>(hs, sk_seed, [a, b])
        },
        |left, right, z, i| {
            let mut a = *adrs;
            a.set_type_and_clear(AdrsType::Tree);
            a.set_tree_height(z);
            a.set_tree_index(i);
            hs.h(&a, left, right)
        },
    )
}

/// The root of the top XMSS tree of the hypertree, the `PK.root` of the key
/// (FIPS 205 Algorithm 18, lines 1 to 3)
pub(super) fn root<const N: usize, P: ParameterSet<N>>(hs: &P::Hash, sk_seed: &[u8; N]) -> [u8; N] {
    let mut adrs = Adrs::ZERO;
    adrs.set_layer(P::D as u32 - 1);
    xmss_tree::<N, P>(hs, sk_seed, &adrs, None, &mut [])
}

/// `xmss_sign` (FIPS 205 Algorithm 10) of `m` with the key pair `idx`, into
/// the `(len + h') n` bytes of `sig`, returning the root of the tree
///
/// The root is the public key of the tree, which the next layer of the
/// hypertree signs, and which [`xmss_pk_from_sig`] would recompute from the
/// signature.
fn xmss_sign<const N: usize, P: ParameterSet<N>>(
    hs: &P::Hash,
    m: &[u8; N],
    sk_seed: &[u8; N],
    idx: u32,
    adrs: &Adrs,
    sig: &mut [u8],
) -> [u8; N] {
    let (wots_sig, auth_sig) = sig.split_at_mut(P::LEN * N);

    let mut auth = [[0u8; N]; MAX_HP];
    let root = xmss_tree::<N, P>(hs, sk_seed, adrs, Some(idx), &mut auth[..P::HP]);
    auth_sig.copy_from_slice(auth[..P::HP].as_flattened());

    let mut wots_adrs = *adrs;
    wots_adrs.set_type_and_clear(AdrsType::WotsHash);
    wots_adrs.set_keypair(idx);
    wots::sign::<N, P>(hs, m, sk_seed, &wots_adrs, wots_sig);
    root
}

/// `xmss_pkFromSig` (FIPS 205 Algorithm 11), the root of the tree that `sig`
/// is a signature of `m` with the key pair `idx` under
fn xmss_pk_from_sig<const N: usize, P: ParameterSet<N>>(
    hs: &P::Hash,
    idx: u32,
    sig: &[u8],
    m: &[u8; N],
    adrs: &Adrs,
) -> [u8; N] {
    let (wots_sig, auth) = sig.split_at(P::LEN * N);

    let mut a = *adrs;
    a.set_type_and_clear(AdrsType::WotsHash);
    a.set_keypair(idx);
    let mut node = wots::pk_from_sig::<N, P>(hs, wots_sig, m, &a);

    a.set_type_and_clear(AdrsType::Tree);
    for (k, sibling) in auth.as_chunks::<N>().0.iter().enumerate() {
        a.set_tree_height(k as u32 + 1);
        a.set_tree_index(idx >> (k + 1));
        node = if (idx >> k) & 1 == 0 {
            hs.h(&a, &node, sibling)
        } else {
            hs.h(&a, sibling, &node)
        };
    }
    node
}

/// Split the index of a tree into the index of its parent tree in the layer
/// above, and the index of its root among the leaves of that parent tree
fn parent<const N: usize, P: ParameterSet<N>>(idx_tree: u64) -> (u64, u32) {
    let leaf = (idx_tree & ((1 << P::HP) - 1)) as u32;
    (idx_tree >> P::HP, leaf)
}

/// `ht_sign` (FIPS 205 Algorithm 12) of `m`, into the `d (len + h') n` bytes of
/// `sig`, with the key pair `idx_leaf` of the bottom tree `idx_tree`
pub(super) fn ht_sign<const N: usize, P: ParameterSet<N>>(
    hs: &P::Hash,
    m: &[u8; N],
    sk_seed: &[u8; N],
    mut idx_tree: u64,
    mut idx_leaf: u32,
    sig: &mut [u8],
) {
    let mut adrs = Adrs::ZERO;
    let mut m = *m;
    for (layer, xmss_sig) in sig.chunks_exact_mut(P::SIG_XMSS).enumerate() {
        if layer > 0 {
            (idx_tree, idx_leaf) = parent::<N, P>(idx_tree);
        }
        adrs.set_layer(layer as u32);
        adrs.set_tree(idx_tree);
        // each layer signs the root of the tree below it
        m = xmss_sign::<N, P>(hs, &m, sk_seed, idx_leaf, &adrs, xmss_sig);
    }
}

/// `ht_verify` (FIPS 205 Algorithm 13) of the signature `sig` of `m` with the
/// key pair `idx_leaf` of the bottom tree `idx_tree`
pub(super) fn ht_verify<const N: usize, P: ParameterSet<N>>(
    hs: &P::Hash,
    m: &[u8; N],
    sig: &[u8],
    mut idx_tree: u64,
    mut idx_leaf: u32,
    pk_root: &[u8; N],
) -> bool {
    let mut adrs = Adrs::ZERO;
    let mut node = *m;
    for (layer, xmss_sig) in sig.chunks_exact(P::SIG_XMSS).enumerate() {
        if layer > 0 {
            (idx_tree, idx_leaf) = parent::<N, P>(idx_tree);
        }
        adrs.set_layer(layer as u32);
        adrs.set_tree(idx_tree);
        node = xmss_pk_from_sig::<N, P>(hs, idx_leaf, xmss_sig, &node, &adrs);
    }
    node.ct_eq(pk_root).is_true()
}
