//! Keccak-f[1600] permutation using the ARMv8.2 SHA-3 crypto extensions
//! (`eor3`, `rax1`, `xar`, `bcax`), gated on the `sha3` target feature.
//!
//! Each of the 25 state lanes is held in a `uint64x2_t`. Every operation used
//! (EOR3 / RAX1 / XAR / BCAX / EOR) is element-wise, so the two 64-bit elements
//! of the register file carry two entirely independent sponges: [`permute_x2`]
//! runs both at once for the price of one, and [`keccak_f`], which has only one
//! state to offer, duplicates it into both elements and reads element 0 back.
//!
//! The win over the portable backend comes from the fused instructions (3-way
//! XOR, XOR+rotate, bit-clear+XOR); the win of `permute_x2` over two
//! [`keccak_f`] calls comes from the second element, which a single sponge
//! leaves computing a redundant copy of the first.
//!
//! The step order matches the portable `reference` backend:
//!   * Theta computes the column parities `c[x]` (two `eor3` each) and the
//!     `d[x] = c[x-1] ^ rol(c[x+1], 1)` correction (one `rax1` each).
//!   * Rho+Pi moves lane `src` to lane `dst` rotated left by `r`. The Theta
//!     correction `d[src % 5]` is folded into the same `xar`, which computes
//!     `ror(a ^ b, imm)`; since `rol(x, r) == ror(x, 64 - r)`, the immediate is
//!     `(64 - r) % 64`. The (dst, src, d-index, imm) table below is the direct
//!     translation of the reference PIL/ROTC permutation.
//!   * Chi is one `bcax` per lane, `s'[x] = b[x] ^ (~b[x+1] & b[x+2])`.
//!   * Iota XORs the round constant into lane 0.

use core::arch::aarch64::*;

use crate::cryptoutil::{read_u64v_le, write_u64v_le};

use super::RC;

/// The 24 rounds, on 25 lanes each holding two independent sponges.
#[inline]
unsafe fn rounds(s: &mut [uint64x2_t; 25]) {
    let zero = vdupq_n_u64(0);
    let mut c = [zero; 5];
    let mut d = [zero; 5];
    let mut b = [zero; 25];

    for &rc in RC.iter() {
        // Theta: column parities and the rotate-and-xor correction.
        for x in 0..5 {
            c[x] = veor3q_u64(veor3q_u64(s[x], s[x + 5], s[x + 10]), s[x + 15], s[x + 20]);
        }
        d[0] = vrax1q_u64(c[4], c[1]);
        d[1] = vrax1q_u64(c[0], c[2]);
        d[2] = vrax1q_u64(c[1], c[3]);
        d[3] = vrax1q_u64(c[2], c[4]);
        d[4] = vrax1q_u64(c[3], c[0]);

        // Rho + Pi, with the Theta correction folded into each XAR.
        b[0] = vxarq_u64::<0>(s[0], d[0]);
        b[1] = vxarq_u64::<20>(s[6], d[1]);
        b[2] = vxarq_u64::<21>(s[12], d[2]);
        b[3] = vxarq_u64::<43>(s[18], d[3]);
        b[4] = vxarq_u64::<50>(s[24], d[4]);
        b[5] = vxarq_u64::<36>(s[3], d[3]);
        b[6] = vxarq_u64::<44>(s[9], d[4]);
        b[7] = vxarq_u64::<61>(s[10], d[0]);
        b[8] = vxarq_u64::<19>(s[16], d[1]);
        b[9] = vxarq_u64::<3>(s[22], d[2]);
        b[10] = vxarq_u64::<63>(s[1], d[1]);
        b[11] = vxarq_u64::<58>(s[7], d[2]);
        b[12] = vxarq_u64::<39>(s[13], d[3]);
        b[13] = vxarq_u64::<56>(s[19], d[4]);
        b[14] = vxarq_u64::<46>(s[20], d[0]);
        b[15] = vxarq_u64::<37>(s[4], d[4]);
        b[16] = vxarq_u64::<28>(s[5], d[0]);
        b[17] = vxarq_u64::<54>(s[11], d[1]);
        b[18] = vxarq_u64::<49>(s[17], d[2]);
        b[19] = vxarq_u64::<8>(s[23], d[3]);
        b[20] = vxarq_u64::<2>(s[2], d[2]);
        b[21] = vxarq_u64::<9>(s[8], d[3]);
        b[22] = vxarq_u64::<25>(s[14], d[4]);
        b[23] = vxarq_u64::<23>(s[15], d[0]);
        b[24] = vxarq_u64::<62>(s[21], d[1]);

        // Chi: s'[x] = b[x] ^ (~b[x+1] & b[x+2]) per row.
        for y in 0..5 {
            let o = 5 * y;
            s[o] = vbcaxq_u64(b[o], b[o + 2], b[o + 1]);
            s[o + 1] = vbcaxq_u64(b[o + 1], b[o + 3], b[o + 2]);
            s[o + 2] = vbcaxq_u64(b[o + 2], b[o + 4], b[o + 3]);
            s[o + 3] = vbcaxq_u64(b[o + 3], b[o], b[o + 4]);
            s[o + 4] = vbcaxq_u64(b[o + 4], b[o + 1], b[o]);
        }

        // Iota
        s[0] = veorq_u64(s[0], vdupq_n_u64(rc));
    }
}

/// Permute two independent sponge states at once, one per 64-bit element.
pub(super) fn permute_x2(states: &mut [[u64; 25]; 2]) {
    unsafe {
        let (a, b) = states.split_at_mut(1);
        let (a, b) = (&mut a[0], &mut b[0]);

        let mut s = [vdupq_n_u64(0); 25];
        for i in 0..25 {
            s[i] = vsetq_lane_u64::<1>(b[i], vdupq_n_u64(a[i]));
        }

        rounds(&mut s);

        for i in 0..25 {
            a[i] = vgetq_lane_u64::<0>(s[i]);
            b[i] = vgetq_lane_u64::<1>(s[i]);
        }
    }
}

pub(super) fn keccak_f(state: &mut [u8; super::super::B]) {
    let mut words = [0u64; 25];
    read_u64v_le(&mut words, state);

    unsafe {
        // one sponge only, so both elements carry the same copy of it
        let mut s = [vdupq_n_u64(0); 25];
        for i in 0..25 {
            s[i] = vdupq_n_u64(words[i]);
        }

        rounds(&mut s);

        for i in 0..25 {
            words[i] = vgetq_lane_u64::<0>(s[i]);
        }
    }

    write_u64v_le(state, &words);
}
