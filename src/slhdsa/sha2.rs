//! The SHA2 family of the SLH-DSA hash functions (FIPS 205 section 11.2)
//!
//! The keyed functions hash `PK.seed`, padded with zeros to a whole block, and
//! then the compressed address `ADRSc` and their input:
//!
//! * `PRF(PK.seed, SK.seed, ADRS) = SHA-256(PK.seed || 0^(64-n) || ADRSc || SK.seed)`
//! * `F(PK.seed, ADRS, M) = SHA-256(PK.seed || 0^(64-n) || ADRSc || M)`
//! * `H`, `T_l(PK.seed, ADRS, M) = SHA-X(PK.seed || 0^(B-n) || ADRSc || M)`
//! * `PRF_msg(SK.prf, opt_rand, M) = HMAC-SHA-X(SK.prf, opt_rand || M)`
//! * `H_msg(R, PK.seed, PK.root, M) = MGF1-SHA-X(R || PK.seed || SHA-X(R || PK.seed || PK.root || M), m)`
//!
//! all truncated to `n` bytes but `H_msg`, where `SHA-X` is SHA-256 (block
//! size `B` of 64 bytes) at security category 1, the `n = 16` parameter sets,
//! and SHA-512 (`B` of 128 bytes) at categories 3 and 5.
//!
//! The first block of the keyed functions is the same for the lifetime of a
//! key, so its compression is done once; what remains of `PRF`, `F` and `H`
//! then fits in a single compression.

use super::address::Adrs;
use super::hash::Hasher;
use crate::hashing::sha2::raw::{H256, H512, compress256, compress512};
use crate::hashing::sha2::{Sha256, Sha512};
use crate::hmac;

/// Resume a SHA-256 from `state`, where one 64 bytes block was compressed,
/// over the concatenation of `pieces`, and finish it
fn sha256_resume(mut state: [u32; 8], pieces: &[&[u8]]) -> [u8; 32] {
    let mut block = [0u8; 64];
    let mut fill = 0;
    let mut total = 64u64;
    for piece in pieces {
        total += piece.len() as u64;
        let mut piece: &[u8] = piece;
        while !piece.is_empty() {
            let take = core::cmp::min(64 - fill, piece.len());
            block[fill..fill + take].copy_from_slice(&piece[..take]);
            fill += take;
            piece = &piece[take..];
            if fill == 64 {
                compress256(&mut state, &block);
                fill = 0;
            }
        }
    }
    block[fill] = 0x80;
    block[fill + 1..].fill(0);
    if fill + 1 > 64 - 8 {
        compress256(&mut state, &block);
        block = [0u8; 64];
    }
    block[64 - 8..].copy_from_slice(&(total * 8).to_be_bytes());
    compress256(&mut state, &block);

    let mut out = [0u8; 32];
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(state.iter()) {
        *chunk = word.to_be_bytes();
    }
    out
}

/// Resume a SHA-512 from `state`, where one 128 bytes block was compressed,
/// over the concatenation of `pieces`, and finish it
fn sha512_resume(mut state: [u64; 8], pieces: &[&[u8]]) -> [u8; 64] {
    let mut block = [0u8; 128];
    let mut fill = 0;
    let mut total = 128u128;
    for piece in pieces {
        total += piece.len() as u128;
        let mut piece: &[u8] = piece;
        while !piece.is_empty() {
            let take = core::cmp::min(128 - fill, piece.len());
            block[fill..fill + take].copy_from_slice(&piece[..take]);
            fill += take;
            piece = &piece[take..];
            if fill == 128 {
                compress512(&mut state, &block);
                fill = 0;
            }
        }
    }
    block[fill] = 0x80;
    block[fill + 1..].fill(0);
    if fill + 1 > 128 - 16 {
        compress512(&mut state, &block);
        block = [0u8; 128];
    }
    block[128 - 16..].copy_from_slice(&(total * 8).to_be_bytes());
    compress512(&mut state, &block);

    let mut out = [0u8; 64];
    for (chunk, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(state.iter()) {
        *chunk = word.to_be_bytes();
    }
    out
}

/// The first `N` bytes of a digest
fn trunc<const N: usize, const D: usize>(digest: [u8; D]) -> [u8; N] {
    digest[..N].try_into().unwrap()
}

/// `MGF1` (RFC 8017 appendix B.2.1) over the digest `D` of `hash`, into all of `out`
fn mgf1<const D: usize>(seed: &[&[u8]], out: &mut [u8], hash: impl Fn(&[&[u8]]) -> [u8; D]) {
    for (counter, chunk) in out.chunks_mut(D).enumerate() {
        let counter = (counter as u32).to_be_bytes();
        let digest = hash(&[seed[0], seed[1], seed[2], &counter]);
        chunk.copy_from_slice(&digest[..chunk.len()]);
    }
}

/// The SHA2 hash functions, keyed by a public seed of `N` bytes
pub(super) struct Sha2Hasher<const N: usize> {
    /// SHA-256 state after `PK.seed || 0^(64-n)`
    seeded256: [u32; 8],
    /// SHA-512 state after `PK.seed || 0^(128-n)`, only used when `N > 16`
    seeded512: [u64; 8],
}

impl<const N: usize> Sha2Hasher<N> {
    /// Whether this is security category 1, which uses SHA-256 throughout
    const CATEGORY1: bool = N == 16;

    fn sha256(&self, adrs: &Adrs, m: &[u8]) -> [u8; N] {
        trunc(sha256_resume(self.seeded256, &[&adrs.compressed(), m]))
    }

    /// The function of `H` and `T_l`, which depends on the category, over `a || b`
    fn sha_x(&self, adrs: &Adrs, a: &[u8], b: &[u8]) -> [u8; N] {
        let pieces = [&adrs.compressed()[..], a, b];
        if Self::CATEGORY1 {
            trunc(sha256_resume(self.seeded256, &pieces))
        } else {
            trunc(sha512_resume(self.seeded512, &pieces))
        }
    }
}

impl<const N: usize> Hasher<N> for Sha2Hasher<N> {
    fn new(pk_seed: &[u8; N]) -> Self {
        let mut seeded256 = H256;
        let mut block = [0u8; 64];
        block[..N].copy_from_slice(pk_seed);
        compress256(&mut seeded256, &block);

        let mut seeded512 = H512;
        if !Self::CATEGORY1 {
            let mut block = [0u8; 128];
            block[..N].copy_from_slice(pk_seed);
            compress512(&mut seeded512, &block);
        }
        Self {
            seeded256,
            seeded512,
        }
    }

    fn prf(&self, adrs: &Adrs, sk_seed: &[u8; N]) -> [u8; N] {
        self.sha256(adrs, sk_seed)
    }

    fn f(&self, adrs: &Adrs, m: &[u8; N]) -> [u8; N] {
        self.sha256(adrs, m)
    }

    fn h(&self, adrs: &Adrs, left: &[u8; N], right: &[u8; N]) -> [u8; N] {
        self.sha_x(adrs, left, right)
    }

    fn t(&self, adrs: &Adrs, m: &[[u8; N]]) -> [u8; N] {
        self.sha_x(adrs, m.as_flattened(), &[])
    }

    fn prf_msg(sk_prf: &[u8; N], opt_rand: &[u8; N], m: &[&[u8]]) -> [u8; N] {
        fn run<A: hmac::Algorithm>(key: &[u8], opt_rand: &[u8], m: &[&[u8]], out: &mut [u8]) {
            let mut ctx = hmac::Context::<A>::new(key);
            ctx.update(opt_rand);
            for piece in m {
                ctx.update(piece);
            }
            let mut tag = [0u8; 64];
            let tag = &mut tag[..A::OUTPUT_SIZE];
            ctx.finalize_at(tag);
            out.copy_from_slice(&tag[..out.len()]);
        }
        let mut out = [0u8; N];
        if Self::CATEGORY1 {
            run::<Sha256>(sk_prf, opt_rand, m, &mut out);
        } else {
            run::<Sha512>(sk_prf, opt_rand, m, &mut out);
        }
        out
    }

    fn h_msg(r: &[u8; N], pk_seed: &[u8; N], pk_root: &[u8; N], m: &[&[u8]], out: &mut [u8]) {
        if Self::CATEGORY1 {
            let mut ctx = Sha256::new().update(r).update(pk_seed).update(pk_root);
            for piece in m {
                ctx.update_mut(piece);
            }
            let inner = ctx.finalize();
            mgf1(&[r, pk_seed, &inner], out, |pieces| {
                let mut ctx = Sha256::new();
                pieces.iter().for_each(|p| ctx.update_mut(p));
                ctx.finalize()
            });
        } else {
            let mut ctx = Sha512::new().update(r).update(pk_seed).update(pk_root);
            for piece in m {
                ctx.update_mut(piece);
            }
            let inner = ctx.finalize();
            mgf1(&[r, pk_seed, &inner], out, |pieces| {
                let mut ctx = Sha512::new();
                pieces.iter().for_each(|p| ctx.update_mut(p));
                ctx.finalize()
            });
        }
    }
}
