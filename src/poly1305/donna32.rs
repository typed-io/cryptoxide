//! Poly1305 arithmetic backend using 5 unsaturated 26-bits limbs and 32x32->64
//! bits multiplications.
//!
//! This is the portable backend, used on 32-bits architectures (and when the
//! `force-32bits` feature is enabled). It is a port of Andrew Moon's
//! poly1305-donna-32 <https://github.com/floodyberry/poly1305-donna>.

use crate::cryptoutil::{read_u32_le, write_u32_le};

#[derive(Clone)]
pub(super) struct State {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
}

#[inline(always)]
fn mul64(a: u32, b: u32) -> u64 {
    a as u64 * b as u64
}

impl State {
    pub(super) fn new(key: &[u8; 32]) -> Self {
        // r &= 0xffffffc0ffffffc0ffffffc0fffffff
        let r = [
            (read_u32_le(&key[0..4])) & 0x3ffffff,
            (read_u32_le(&key[3..7]) >> 2) & 0x3ffff03,
            (read_u32_le(&key[6..10]) >> 4) & 0x3ffc0ff,
            (read_u32_le(&key[9..13]) >> 6) & 0x3f03fff,
            (read_u32_le(&key[12..16]) >> 8) & 0x00fffff,
        ];

        let pad = [
            read_u32_le(&key[16..20]),
            read_u32_le(&key[20..24]),
            read_u32_le(&key[24..28]),
            read_u32_le(&key[28..32]),
        ];

        State {
            r,
            h: [0u32; 5],
            pad,
        }
    }

    pub(super) fn reset(&mut self) {
        self.h = [0u32; 5];
    }

    /// Process one or more complete 16-bytes blocks.
    ///
    /// `m` length must be a non-zero multiple of 16. `partial` is true only for
    /// the last (zero-padded) block which already contains its 0x01 terminator,
    /// in which case the implicit high `2^128` bit is not added.
    #[rustfmt::skip]
    pub(super) fn blocks(&mut self, m: &[u8], partial: bool) {
        let hibit : u32 = if partial { 0 } else { 1 << 24 };

        let r0 = self.r[0];
        let r1 = self.r[1];
        let r2 = self.r[2];
        let r3 = self.r[3];
        let r4 = self.r[4];

        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        for block in m.chunks_exact(16) {
            // h += m
            h0 += (read_u32_le(&block[0..4])      ) & 0x3ffffff;
            h1 += (read_u32_le(&block[3..7]) >> 2  ) & 0x3ffffff;
            h2 += (read_u32_le(&block[6..10]) >> 4 ) & 0x3ffffff;
            h3 += (read_u32_le(&block[9..13]) >> 6 ) & 0x3ffffff;
            h4 += (read_u32_le(&block[12..16]) >> 8) | hibit;

            // h *= r
            let     d0 = mul64(h0, r0) + mul64(h1, s4) + mul64(h2, s3) + mul64(h3, s2) + mul64(h4, s1);
            let mut d1 = mul64(h0, r1) + mul64(h1, r0) + mul64(h2, s4) + mul64(h3, s3) + mul64(h4, s2);
            let mut d2 = mul64(h0, r2) + mul64(h1, r1) + mul64(h2, r0) + mul64(h3, s4) + mul64(h4, s3);
            let mut d3 = mul64(h0, r3) + mul64(h1, r2) + mul64(h2, r1) + mul64(h3, r0) + mul64(h4, s4);
            let mut d4 = mul64(h0, r4) + mul64(h1, r3) + mul64(h2, r2) + mul64(h3, r1) + mul64(h4, r0);

            // (partial) h %= p
            let mut c : u32;
                            c = (d0 >> 26) as u32; h0 = d0 as u32 & 0x3ffffff;
            d1 += c as u64; c = (d1 >> 26) as u32; h1 = d1 as u32 & 0x3ffffff;
            d2 += c as u64; c = (d2 >> 26) as u32; h2 = d2 as u32 & 0x3ffffff;
            d3 += c as u64; c = (d3 >> 26) as u32; h3 = d3 as u32 & 0x3ffffff;
            d4 += c as u64; c = (d4 >> 26) as u32; h4 = d4 as u32 & 0x3ffffff;
            h0 += c * 5;    c = h0 >> 26; h0 &= 0x3ffffff;
            h1 += c;
        }

        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
        self.h[3] = h3;
        self.h[4] = h4;
    }

    /// Fully reduce the accumulator, add the pad and serialize the 16-bytes tag.
    #[rustfmt::skip]
    pub(super) fn finish(&mut self) -> [u8; 16] {
        // fully carry h
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        let mut c : u32;
                     c = h1 >> 26; h1 &= 0x3ffffff;
        h2 +=     c; c = h2 >> 26; h2 &= 0x3ffffff;
        h3 +=     c; c = h3 >> 26; h3 &= 0x3ffffff;
        h4 +=     c; c = h4 >> 26; h4 &= 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 +=     c;

        // compute h + -p
        let mut g0 = h0.wrapping_add(5); c = g0 >> 26; g0 &= 0x3ffffff;
        let mut g1 = h1.wrapping_add(c); c = g1 >> 26; g1 &= 0x3ffffff;
        let mut g2 = h2.wrapping_add(c); c = g2 >> 26; g2 &= 0x3ffffff;
        let mut g3 = h3.wrapping_add(c); c = g3 >> 26; g3 &= 0x3ffffff;
        let mut g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        // select h if h < p, or h + -p if h >= p
        let mut mask = (g4 >> (32 - 1)).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        g4 &= mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // h = h % (2^128)
        h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
        h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
        h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
        h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

        // h = mac = (h + pad) % (2^128)
        let mut f : u64;
        f = h0 as u64 + self.pad[0] as u64            ; h0 = f as u32;
        f = h1 as u64 + self.pad[1] as u64 + (f >> 32); h1 = f as u32;
        f = h2 as u64 + self.pad[2] as u64 + (f >> 32); h2 = f as u32;
        f = h3 as u64 + self.pad[3] as u64 + (f >> 32); h3 = f as u32;

        let mut tag = [0u8; 16];
        write_u32_le(&mut tag[0..4], h0);
        write_u32_le(&mut tag[4..8], h1);
        write_u32_le(&mut tag[8..12], h2);
        write_u32_le(&mut tag[12..16], h3);
        tag
    }
}
