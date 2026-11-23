//! The SHAKE family of the SLH-DSA hash functions (FIPS 205 section 11.1)
//!
//! Every function is SHAKE256 over the concatenation of its inputs:
//!
//! * `PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed || ADRS || SK.seed, 8n)`
//! * `F`, `H`, `T_l(PK.seed, ADRS, M) = SHAKE256(PK.seed || ADRS || M, 8n)`
//! * `PRF_msg(SK.prf, opt_rand, M) = SHAKE256(SK.prf || opt_rand || M, 8n)`
//! * `H_msg(R, PK.seed, PK.root, M) = SHAKE256(R || PK.seed || PK.root || M, 8m)`
//!
//! All but the two message functions take inputs that are whole numbers of
//! 8 bytes words, and all of them but `T_l` fit in a single block of the
//! sponge. They are computed here directly on the lanes of the Keccak state,
//! leaving out the byte oriented buffering of the generic SHAKE context, which
//! would otherwise dominate the cost of a 64 to 128 bytes input.

use super::address::Adrs;
use super::hash::Hasher;
use crate::hashing::sha3::{keccak_f_x2, keccak_p};
use crate::hashing::shake::Shake256;

/// The rate of SHAKE256 in 8 bytes lanes, 136 bytes
const RATE_LANES: usize = 17;

/// `W` SHAKE256 sponges absorbing, in lockstep, inputs of the same length
#[derive(Clone)]
struct Lanes<const W: usize> {
    states: [[u64; 25]; W],
    /// The next lane to absorb into, the same for every sponge
    pos: usize,
}

impl<const W: usize> Lanes<W> {
    const fn new() -> Self {
        Self {
            states: [[0; 25]; W],
            pos: 0,
        }
    }

    fn permute(&mut self) {
        match <&mut [[u64; 25]; 2]>::try_from(&mut self.states[..]) {
            Ok(pair) => keccak_f_x2(pair),
            Err(_) => self.states.iter_mut().for_each(keccak_p),
        }
    }

    /// Absorb one input per sponge, all of the same length, a multiple of 8
    fn absorb(&mut self, inputs: [&[u8]; W]) {
        let len = inputs[0].len();
        debug_assert!(len.is_multiple_of(8) && inputs.iter().all(|i| i.len() == len));
        for offset in (0..len).step_by(8) {
            for (state, input) in self.states.iter_mut().zip(inputs.iter()) {
                let word = &input[offset..offset + 8];
                state[self.pos] ^= u64::from_le_bytes(word.try_into().unwrap());
            }
            self.pos += 1;
            if self.pos == RATE_LANES {
                self.permute();
                self.pos = 0;
            }
        }
    }

    /// Pad, and squeeze the first `N` bytes of every sponge, `N` a multiple of 8
    fn finish<const N: usize>(mut self) -> [[u8; N]; W] {
        for state in self.states.iter_mut() {
            // the SHAKE domain separation 1111 and the first bit of pad10*1,
            // then its closing bit at the very end of the rate
            state[self.pos] ^= 0x1f;
            state[RATE_LANES - 1] ^= 0x80 << 56;
        }
        self.permute();
        let mut out = [[0u8; N]; W];
        for (o, state) in out.iter_mut().zip(self.states.iter()) {
            for (chunk, lane) in o.as_chunks_mut::<8>().0.iter_mut().zip(state.iter()) {
                *chunk = lane.to_le_bytes();
            }
        }
        out
    }
}

/// The SHAKE hash functions, keyed by a public seed of `N` bytes
pub(super) struct ShakeHasher<const N: usize> {
    /// One sponge that absorbed `PK.seed`, the prefix of all the keyed calls
    seeded: Lanes<1>,
    /// Two sponges that each absorbed `PK.seed`
    seeded_x2: Lanes<2>,
}

impl<const N: usize> Hasher<N> for ShakeHasher<N> {
    fn new(pk_seed: &[u8; N]) -> Self {
        let mut seeded = Lanes::new();
        seeded.absorb([pk_seed]);
        let mut seeded_x2 = Lanes::new();
        seeded_x2.absorb([pk_seed, pk_seed]);
        Self { seeded, seeded_x2 }
    }

    fn prf(&self, adrs: &Adrs, sk_seed: &[u8; N]) -> [u8; N] {
        self.f(adrs, sk_seed)
    }

    fn f(&self, adrs: &Adrs, m: &[u8; N]) -> [u8; N] {
        let mut s = self.seeded.clone();
        s.absorb([&adrs.0]);
        s.absorb([m]);
        let [out] = s.finish();
        out
    }

    fn h(&self, adrs: &Adrs, left: &[u8; N], right: &[u8; N]) -> [u8; N] {
        let mut s = self.seeded.clone();
        s.absorb([&adrs.0]);
        s.absorb([left]);
        s.absorb([right]);
        let [out] = s.finish();
        out
    }

    fn t(&self, adrs: &Adrs, m: &[[u8; N]]) -> [u8; N] {
        let mut s = self.seeded.clone();
        s.absorb([&adrs.0]);
        s.absorb([m.as_flattened()]);
        let [out] = s.finish();
        out
    }

    fn prf_x2(&self, adrs: [&Adrs; 2], sk_seed: &[u8; N]) -> [[u8; N]; 2] {
        self.f_x2(adrs, [sk_seed, sk_seed])
    }

    fn f_x2(&self, adrs: [&Adrs; 2], m: [&[u8; N]; 2]) -> [[u8; N]; 2] {
        let mut s = self.seeded_x2.clone();
        s.absorb([&adrs[0].0, &adrs[1].0]);
        s.absorb([m[0], m[1]]);
        s.finish()
    }

    fn t_x2(&self, adrs: [&Adrs; 2], m: [&[[u8; N]]; 2]) -> [[u8; N]; 2] {
        let mut s = self.seeded_x2.clone();
        s.absorb([&adrs[0].0, &adrs[1].0]);
        s.absorb([m[0].as_flattened(), m[1].as_flattened()]);
        s.finish()
    }

    fn prf_msg(sk_prf: &[u8; N], opt_rand: &[u8; N], m: &[&[u8]]) -> [u8; N] {
        let mut ctx = Shake256::new().update(sk_prf).update(opt_rand);
        for piece in m {
            ctx.update_mut(piece);
        }
        ctx.finalize()
    }

    fn h_msg(r: &[u8; N], pk_seed: &[u8; N], pk_root: &[u8; N], m: &[&[u8]], out: &mut [u8]) {
        let mut ctx = Shake256::new().update(r).update(pk_seed).update(pk_root);
        for piece in m {
            ctx.update_mut(piece);
        }
        ctx.finalize_at(out)
    }
}
