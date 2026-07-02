//! Poly1305 arithmetic backend using 3 unsaturated 44-bits limbs and 64x64->128
//! bits multiplications.
//!
//! This is the backend used on 64-bits architectures, where it is roughly twice
//! as fast as the 32-bits backend thanks to the wide multiplier. It is a port of
//! Andrew Moon's poly1305-donna-64 <https://github.com/floodyberry/poly1305-donna>.

use crate::cryptoutil::{read_u64_le, write_u64_le};

#[derive(Clone)]
pub(super) struct State {
    r: [u64; 3],
    h: [u64; 3],
    pad: [u64; 2],
}

impl State {
    pub(super) fn new(key: &[u8; 32]) -> Self {
        let t0 = read_u64_le(&key[0..8]);
        let t1 = read_u64_le(&key[8..16]);

        // r &= 0xffffffc0ffffffc0ffffffc0fffffff
        let r = [
            t0 & 0xffc_0fff_ffff,
            ((t0 >> 44) | (t1 << 20)) & 0xfff_ffc0_ffff,
            (t1 >> 24) & 0xf_ffff_fc0f,
        ];

        let pad = [read_u64_le(&key[16..24]), read_u64_le(&key[24..32])];

        State {
            r,
            h: [0u64; 3],
            pad,
        }
    }

    pub(super) fn reset(&mut self) {
        self.h = [0u64; 3];
    }

    /// Process one or more complete 16-bytes blocks.
    ///
    /// `m` length must be a non-zero multiple of 16. `partial` is true only for
    /// the last (zero-padded) block which already contains its 0x01 terminator,
    /// in which case the implicit high `2^128` bit is not added.
    #[rustfmt::skip]
    pub(super) fn blocks(&mut self, m: &[u8], partial: bool) {
        // 1 << 128
        let hibit : u64 = if partial { 0 } else { 1 << 40 };

        let r0 = self.r[0];
        let r1 = self.r[1];
        let r2 = self.r[2];

        let s1 = r1 * (5 << 2);
        let s2 = r2 * (5 << 2);

        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];

        for block in m.chunks_exact(16) {
            let t0 = read_u64_le(&block[0..8]);
            let t1 = read_u64_le(&block[8..16]);

            // h += m
            h0 += t0 & 0xfff_ffff_ffff;
            h1 += ((t0 >> 44) | (t1 << 20)) & 0xfff_ffff_ffff;
            h2 += ((t1 >> 24) & 0x3ff_ffff_ffff) | hibit;

            // h *= r
            let     d0 = (h0 as u128 * r0 as u128) + (h1 as u128 * s2 as u128) + (h2 as u128 * s1 as u128);
            let mut d1 = (h0 as u128 * r1 as u128) + (h1 as u128 * r0 as u128) + (h2 as u128 * s2 as u128);
            let mut d2 = (h0 as u128 * r2 as u128) + (h1 as u128 * r1 as u128) + (h2 as u128 * r0 as u128);

            // (partial) h %= p
            let mut c : u64;
                             c = (d0 >> 44) as u64; h0 = d0 as u64 & 0xfff_ffff_ffff;
            d1 += c as u128; c = (d1 >> 44) as u64; h1 = d1 as u64 & 0xfff_ffff_ffff;
            d2 += c as u128; c = (d2 >> 42) as u64; h2 = d2 as u64 & 0x3ff_ffff_ffff;
            h0 += c * 5;     c = h0 >> 44;          h0 &= 0xfff_ffff_ffff;
            h1 += c;
        }

        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
    }

    /// Fully reduce the accumulator, add the pad and serialize the 16-bytes tag.
    #[rustfmt::skip]
    pub(super) fn finish(&mut self) -> [u8; 16] {
        // fully carry h
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];

        let mut c : u64;
                     c = h1 >> 44; h1 &= 0xfff_ffff_ffff;
        h2 += c;     c = h2 >> 42; h2 &= 0x3ff_ffff_ffff;
        h0 += c * 5; c = h0 >> 44; h0 &= 0xfff_ffff_ffff;
        h1 += c;     c = h1 >> 44; h1 &= 0xfff_ffff_ffff;
        h2 += c;     c = h2 >> 42; h2 &= 0x3ff_ffff_ffff;
        h0 += c * 5; c = h0 >> 44; h0 &= 0xfff_ffff_ffff;
        h1 += c;

        // compute h + -p
        let mut g0 = h0.wrapping_add(5); c = g0 >> 44; g0 &= 0xfff_ffff_ffff;
        let mut g1 = h1.wrapping_add(c); c = g1 >> 44; g1 &= 0xfff_ffff_ffff;
        let mut g2 = h2.wrapping_add(c).wrapping_sub(1 << 42);

        // select h if h < p, or h + -p if h >= p
        let mut mask = (g2 >> (64 - 1)).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;

        // h = (h + pad)
        let t0 = self.pad[0];
        let t1 = self.pad[1];

        h0 +=  t0 & 0xfff_ffff_ffff                            ; c = h0 >> 44; h0 &= 0xfff_ffff_ffff;
        h1 += (((t0 >> 44) | (t1 << 20)) & 0xffff_ffff_fff) + c; c = h1 >> 44; h1 &= 0xfff_ffff_ffff;
        h2 += ((t1 >> 24) & 0x3ff_ffff_ffff) + c               ;               h2 &= 0x3ff_ffff_ffff;

        // mac = h % (2^128)
        h0 |= h1 << 44;
        h1 = (h1 >> 20) | (h2 << 24);

        let mut tag = [0u8; 16];
        write_u64_le(&mut tag[0..8], h0);
        write_u64_le(&mut tag[8..16], h1);
        tag
    }
}
