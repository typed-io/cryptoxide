//! The parameters of an SLH-DSA parameter set (FIPS 205 section 11, Table 2)

use super::hash::Hasher;

/// Largest `len` of any parameter set, the `2 n + 3` of the `n = 32` ones
pub(super) const MAX_LEN: usize = 2 * 32 + 3;

/// Largest XMSS tree height `h'` of any parameter set, of the `s` ones
pub(super) const MAX_HP: usize = 9;

/// Largest FORS tree height `a` of any parameter set
pub(super) const MAX_A: usize = 14;

/// Largest number of FORS trees `k` of any parameter set
pub(super) const MAX_K: usize = 35;

/// Largest message digest length `m` of any parameter set
pub(super) const MAX_M: usize = 49;

/// Base 2 logarithm of the Winternitz parameter `w`, 4 for every parameter set
pub(super) const LG_W: usize = 4;

/// The Winternitz parameter `w`, the length of a WOTS+ hash chain plus one
pub(super) const W: u32 = 1 << LG_W;

/// The parameters of a set with `N` bytes hashes
///
/// The hash length is a const generic rather than an associated constant, as
/// that is what lets the hashes be arrays of `N` bytes; the parameters the
/// sizes of the other arrays depend on are bounded by the `MAX_` constants
/// instead.
pub(super) trait ParameterSet<const N: usize> {
    /// Total height `h` of the hypertree
    const H: usize;
    /// Number of layers `d` of the hypertree
    const D: usize;
    /// Height `h' = h / d` of each XMSS tree
    const HP: usize;
    /// Height `a` of each FORS tree
    const A: usize;
    /// Number `k` of FORS trees
    const K: usize;
    /// Length in bytes `m` of the message digest
    const M: usize;

    /// The hash function family
    type Hash: Hasher<N>;

    /// Number of `lg_w` bits digits of an `N` bytes message, `8 n / lg_w`
    const LEN1: usize = 8 * N / LG_W;
    /// Number of digits of the checksum, 3 for every parameter set
    const LEN2: usize = 3;
    /// Number of WOTS+ hash chains
    const LEN: usize = Self::LEN1 + Self::LEN2;

    /// Length in bytes of a FORS signature, a secret value and an
    /// authentication path per tree
    const SIG_FORS: usize = Self::K * (1 + Self::A) * N;
    /// Length in bytes of an XMSS signature, a WOTS+ signature and an
    /// authentication path
    const SIG_XMSS: usize = (Self::LEN + Self::HP) * N;
    /// Length in bytes of an SLH-DSA signature, the randomizer, the FORS
    /// signature and one XMSS signature per layer
    const SIG: usize = N + Self::SIG_FORS + Self::D * Self::SIG_XMSS;

    /// Length in bytes of the part of the digest that FORS signs, `ceil(k a / 8)`
    const MD_BYTES: usize = (Self::K * Self::A).div_ceil(8);
    /// Length in bytes of the part of the digest giving the XMSS tree index
    const TREE_BYTES: usize = (Self::H - Self::HP).div_ceil(8);
    /// Length in bytes of the part of the digest giving the leaf index
    const LEAF_BYTES: usize = Self::HP.div_ceil(8);
}
