//! The tweakable hash functions of SLH-DSA (FIPS 205 section 4.1)
//!
//! A parameter set is instantiated with one of two families of hash
//! functions, SHAKE ([`shake`](super::shake)) or SHA2 ([`sha2`](super::sha2)),
//! and the rest of the scheme only ever hashes through the [`Hasher`] trait.

use super::address::Adrs;

/// The functions `PRF`, `F`, `H`, `T_l`, `PRF_msg` and `H_msg` of a parameter
/// set with `N` bytes hashes
///
/// All of the functions but the two message ones are keyed by the public
/// seed `PK.seed`, which is fixed for the lifetime of a key, so an instance
/// holds it along with whatever the family precomputes from it.
///
/// The `_x2` variants compute two independent calls at once. The SHAKE family
/// overrides them to permute two Keccak states together, which costs no more
/// than one on a backend that holds two lanes per register; the default is to
/// make the two calls in turn.
pub(super) trait Hasher<const N: usize>: Sized {
    /// Key the functions with the public seed
    fn new(pk_seed: &[u8; N]) -> Self;

    /// `PRF(PK.seed, SK.seed, ADRS)`, the derivation of the secret values
    fn prf(&self, adrs: &Adrs, sk_seed: &[u8; N]) -> [u8; N];

    /// `F(PK.seed, ADRS, M1)`, of one `N` bytes block
    fn f(&self, adrs: &Adrs, m: &[u8; N]) -> [u8; N];

    /// `H(PK.seed, ADRS, M2)`, of two `N` bytes blocks
    fn h(&self, adrs: &Adrs, left: &[u8; N], right: &[u8; N]) -> [u8; N];

    /// `T_l(PK.seed, ADRS, M_l)`, of `l` blocks of `N` bytes
    fn t(&self, adrs: &Adrs, m: &[[u8; N]]) -> [u8; N];

    /// Two `PRF` calls with the same secret seed
    fn prf_x2(&self, adrs: [&Adrs; 2], sk_seed: &[u8; N]) -> [[u8; N]; 2] {
        [self.prf(adrs[0], sk_seed), self.prf(adrs[1], sk_seed)]
    }

    /// Two `F` calls
    fn f_x2(&self, adrs: [&Adrs; 2], m: [&[u8; N]; 2]) -> [[u8; N]; 2] {
        [self.f(adrs[0], m[0]), self.f(adrs[1], m[1])]
    }

    /// Two `T_l` calls, of the same length `l`
    fn t_x2(&self, adrs: [&Adrs; 2], m: [&[[u8; N]]; 2]) -> [[u8; N]; 2] {
        [self.t(adrs[0], m[0]), self.t(adrs[1], m[1])]
    }

    /// `PRF_msg(SK.prf, opt_rand, M)`, the randomizer `R` of a signature
    ///
    /// The message is given as the pieces it is the concatenation of.
    fn prf_msg(sk_prf: &[u8; N], opt_rand: &[u8; N], m: &[&[u8]]) -> [u8; N];

    /// `H_msg(R, PK.seed, PK.root, M)`, the digest of the message, into all of `out`
    ///
    /// The message is given as the pieces it is the concatenation of.
    fn h_msg(r: &[u8; N], pk_seed: &[u8; N], pk_root: &[u8; N], m: &[&[u8]], out: &mut [u8]);
}
