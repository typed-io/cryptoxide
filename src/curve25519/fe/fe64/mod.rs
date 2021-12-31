//! Field Element implementation for 64-bits native arch using unsaturated 51-bits limbs.
//!
//! arithmetic calculation helpers:
//!
//! * ed25519-donna: https://github.com/floodyberry/ed25519-donna
//! * Sandy2x: New Curve25519 Speed Records

use crate::constant_time::{ct_array64_maybe_set, ct_array64_maybe_swap_with, Choice, CtEqual};
use core::ops::{Add, Mul, Neg, Sub};

pub mod precomp;

/// Field Element in \Z/(2^255-19)
#[derive(Clone)]
pub struct Fe(pub(crate) [u64; 5]);

impl CtEqual for &Fe {
    fn ct_eq(self, other: Self) -> Choice {
        let p1 = self.to_bytes();
        let p2 = other.to_bytes();
        p1.ct_eq(&p2)
    }
    fn ct_ne(self, other: Self) -> Choice {
        self.ct_eq(other).negate()
    }
}
impl PartialEq for Fe {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).is_true()
    }
}
impl Eq for Fe {}

impl Fe {
    pub const ZERO: Fe = Fe([0, 0, 0, 0, 0]);
    pub const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    pub const SQRTM1: Fe = Fe([
        0x61B274A0EA0B0,
        0xD5A5FC8F189D,
        0x7EF5E9CBD0C60,
        0x78595A6804C9E,
        0x2B8324804FC1D,
    ]);
    pub const D: Fe = Fe([
        0x34DCA135978A3,
        0x1A8283B156EBD,
        0x5E7A26001C029,
        0x739C663A03CBB,
        0x52036CEE2B6FF,
    ]);
    pub const D2: Fe = Fe([
        0x69B9426B2F159,
        0x35050762ADD7A,
        0x3CF44C0038052,
        0x6738CC7407977,
        0x2406D9DC56DFF,
    ]);
}

impl Add for &Fe {
    type Output = Fe;

    #[rustfmt::skip]
    fn add(self, rhs: &Fe) -> Fe {
        let Fe([f0, f1, f2, f3, f4]) = *self;
        let Fe([g0, g1, g2, g3, g4]) = *rhs;
        let mut h0 = f0 + g0    ; let c = h0 >> 51; h0 &= MASK;
        let mut h1 = f1 + g1 + c; let c = h1 >> 51; h1 &= MASK;
        let mut h2 = f2 + g2 + c; let c = h2 >> 51; h2 &= MASK;
        let mut h3 = f3 + g3 + c; let c = h3 >> 51; h3 &= MASK;
        let mut h4 = f4 + g4 + c; let c = h4 >> 51; h4 &= MASK;
        h0 += c * 19;
        Fe([h0, h1, h2, h3, h4])
    }
}

impl Sub for &Fe {
    type Output = Fe;

    #[rustfmt::skip]
    fn sub(self, rhs: &Fe) -> Fe {
        // multiple of P
        const FOUR_P0: u64 = 0x1fffffffffffb4;
        const FOUR_P1234: u64 = 0x1ffffffffffffc;

        let Fe([f0, f1, f2, f3, f4]) = *self;
        let Fe([g0, g1, g2, g3, g4]) = *rhs;

        let mut h0 = f0 + FOUR_P0    - g0    ; let c = h0 >> 51; h0 &= MASK;
        let mut h1 = f1 + FOUR_P1234 - g1 + c; let c = h1 >> 51; h1 &= MASK;
        let mut h2 = f2 + FOUR_P1234 - g2 + c; let c = h2 >> 51; h2 &= MASK;
        let mut h3 = f3 + FOUR_P1234 - g3 + c; let c = h3 >> 51; h3 &= MASK;
        let mut h4 = f4 + FOUR_P1234 - g4 + c; let c = h4 >> 51; h4 &= MASK;
        h0 += c * 19;
        Fe([h0, h1, h2, h3, h4])
    }
}

impl Neg for &Fe {
    type Output = Fe;

    fn neg(self) -> Fe {
        &Fe::ZERO - &self
    }
}

impl Mul for &Fe {
    type Output = Fe;

    fn mul(self, rhs: &Fe) -> Fe {
        let Fe([f0, f1, f2, f3, f4]) = *self;
        let Fe([g0, g1, g2, g3, g4]) = *rhs;
        todo!()
    }
}

const MASK: u64 = (1 << 51) - 1;

impl Fe {
    /// Create the Field Element from its little-endian byte representation (256 bits)
    ///
    /// Note that it doesn't verify that the bytes
    /// are actually representing an element in the
    /// range of the field, but will automatically wrap
    /// the bytes to be in the range
    pub const fn from_bytes(bytes: &[u8; 32]) -> Fe {
        // load 8 bytes from input[ofs..ofs+7] as little endian u64
        #[inline]
        const fn load(bytes: &[u8; 32], ofs: usize) -> u64 {
            (bytes[ofs] as u64)
                | ((bytes[ofs + 1] as u64) << 8)
                | ((bytes[ofs + 2] as u64) << 16)
                | ((bytes[ofs + 3] as u64) << 24)
                | ((bytes[ofs + 4] as u64) << 32)
                | ((bytes[ofs + 5] as u64) << 40)
                | ((bytes[ofs + 6] as u64) << 48)
                | ((bytes[ofs + 7] as u64) << 56)
        }

        // maps from bytes at:
        // * bit 0 (byte 0 shift 0)
        // * bit 51 (byte 6 shift 3)
        // * bit 102 (byte 12 shift 6)
        // * bit 153 (byte 19 shift 1)
        // * bit 204 (byte 25 shift 4)
        let x0 = load(bytes, 0) & MASK;
        let x1 = (load(bytes, 6) >> 3) & MASK;
        let x2 = (load(bytes, 12) >> 6) & MASK;
        let x3 = (load(bytes, 19) >> 1) & MASK;
        let x4 = (load(bytes, 24) >> 12) & MASK;
        Fe([x0, x1, x2, x3, x4])
    }

    /// Represent the Field Element as little-endian canonical bytes (256 bits)
    ///
    /// Due to the field size, it's guarantee that the highest bit is always 0
    pub const fn to_bytes(&self) -> [u8; 32] {
        let Fe(t) = *self;

        #[inline]
        const fn carry_full(t: &[u64; 5]) -> [u64; 5] {
            let t1 = t[1] + (t[0] >> 51);
            let t2 = t[2] + (t1 >> 51);
            let t3 = t[3] + (t2 >> 51);
            let t4 = t[4] + (t3 >> 51);
            let t0 = (t[0] & MASK) + 19 * (t4 >> 51);
            [t0, t1 & MASK, t2 & MASK, t3 & MASK, t4 & MASK]
        }

        #[inline]
        const fn carry_final(t: &[u64; 5]) -> [u64; 5] {
            let t1 = t[1] + (t[0] >> 51);
            let t2 = t[2] + (t1 >> 51);
            let t3 = t[3] + (t2 >> 51);
            let t4 = t[4] + (t3 >> 51);
            [t[0] & MASK, t1 & MASK, t2 & MASK, t3 & MASK, t4 & MASK]
        }

        let t = carry_full(&t);
        let mut t = carry_full(&t);
        t[0] += 19;
        let mut t = carry_full(&t);

        t[0] += (MASK + 1) - 19;
        t[1] += MASK;
        t[2] += MASK;
        t[3] += MASK;
        t[4] += MASK;

        let t = carry_final(&t);

        let out0 = t[0] | t[1] << 51;
        let out1 = (t[1] >> 13) | (t[2] << 38);
        let out2 = (t[2] >> 26) | (t[3] << 25);
        let out3 = (t[3] >> 39) | (t[4] << 12);

        let mut out = [0u8; 32];

        macro_rules! write8 {
            ($ofs:literal, $v:ident) => {
                let x = $v.to_le_bytes();
                out[$ofs] = x[0];
                out[$ofs + 1] = x[1];
                out[$ofs + 2] = x[2];
                out[$ofs + 3] = x[3];
                out[$ofs + 4] = x[4];
                out[$ofs + 5] = x[5];
                out[$ofs + 6] = x[6];
                out[$ofs + 7] = x[7];
            };
        }
        write8!(0, out0);
        write8!(8, out1);
        write8!(16, out2);
        write8!(24, out3);
        out
    }

    pub fn invert(&self) -> Fe {
        let z1 = self;
        let z2 = z1.square();
        let z8 = z2.square().square();
        let z9 = z1 * &z8;
        let z11 = &z2 * &z9;
        let z22 = z11.square();
        let z_5_0 = &z9 * &z22;
        let z_10_5 = (0..5).fold(z_5_0.clone(), |z_5_n, _| z_5_n.square());
        let z_10_0 = &z_10_5 * &z_5_0;
        let z_20_10 = (0..10).fold(z_10_0.clone(), |x, _| x.square());
        let z_20_0 = &z_20_10 * &z_10_0;
        let z_40_20 = (0..20).fold(z_20_0.clone(), |x, _| x.square());
        let z_40_0 = &z_40_20 * &z_20_0;
        let z_50_10 = (0..10).fold(z_40_0, |x, _| x.square());
        let z_50_0 = &z_50_10 * &z_10_0;
        let z_100_50 = (0..50).fold(z_50_0.clone(), |x, _| x.square());
        let z_100_0 = &z_100_50 * &z_50_0;
        let z_200_100 = (0..100).fold(z_100_0.clone(), |x, _| x.square());
        let z_200_0 = &z_200_100 * &z_100_0;
        let z_250_50 = (0..50).fold(z_200_0, |x, _| x.square());
        let z_250_0 = &z_250_50 * &z_50_0;
        let z_255_5 = (0..5).fold(z_250_0, |x, _| x.square());
        let z_255_21 = &z_255_5 * &z11;

        z_255_21
    }
    pub fn mul_121666(&self) -> Fe {
        todo!()
    }
    pub fn square(&self) -> Fe {
        todo!()
    }
    pub fn square_and_double(&self) -> Fe {
        todo!()
    }
    pub fn pow25523(&self) -> Fe {
        let z2 = self.square();
        let z8 = (0..2).fold(z2.clone(), |x, _| x.square());
        let z9 = self * &z8;
        let z11 = &z2 * &z9;
        let z22 = z11.square();
        let z_5_0 = &z9 * &z22;
        let z_10_5 = (0..5).fold(z_5_0.clone(), |x, _| x.square());
        let z_10_0 = &z_10_5 * &z_5_0;
        let z_20_10 = (0..10).fold(z_10_0.clone(), |x, _| x.square());
        let z_20_0 = &z_20_10 * &z_10_0;
        let z_40_20 = (0..20).fold(z_20_0.clone(), |x, _| x.square());
        let z_40_0 = &z_40_20 * &z_20_0;
        let z_50_10 = (0..10).fold(z_40_0, |x, _| x.square());
        let z_50_0 = &z_50_10 * &z_10_0;
        let z_100_50 = (0..50).fold(z_50_0.clone(), |x, _| x.square());
        let z_100_0 = &z_100_50 * &z_50_0;
        let z_200_100 = (0..100).fold(z_100_0.clone(), |x, _| x.square());
        let z_200_0 = &z_200_100 * &z_100_0;
        let z_250_50 = (0..50).fold(z_200_0, |x, _| x.square());
        let z_250_0 = &z_250_50 * &z_50_0;
        let z_252_2 = (0..2).fold(z_250_0, |x, _| x.square());
        let z_252_3 = &z_252_2 * self;

        z_252_3
    }
    pub fn is_nonzero(&self) -> bool {
        CtEqual::ct_ne(&self.to_bytes(), &[0; 32]).into()
    }
    pub fn is_negative(&self) -> bool {
        (self.to_bytes()[0] & 1) != 0
    }

    pub(crate) fn maybe_swap_with(&mut self, rhs: &mut Fe, do_swap: Choice) {
        ct_array64_maybe_swap_with(&mut self.0, &mut rhs.0, do_swap);
    }

    pub(crate) fn maybe_set(&mut self, rhs: &Fe, do_swap: Choice) {
        ct_array64_maybe_set(&mut self.0, &rhs.0, do_swap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prop_bytes(bytes: &[u8; 32]) {
        let f = Fe::from_bytes(bytes);
        let got_bytes = f.to_bytes();
        assert_eq!(&got_bytes, bytes)
    }

    #[test]
    fn bytes_serialization() {
        prop_bytes(&[0; 32]);
        prop_bytes(&[1; 32]);
        prop_bytes(&[2; 32]);
        prop_bytes(&[0x5f; 32]);
        prop_bytes(&[
            0, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4,
            5, 1, 0,
        ]);

        // 2^255-20 FieldElement representation
        let fe25520 = Fe([
            0x7FFFFFFFFFFEC,
            0x7FFFFFFFFFFFF,
            0x7FFFFFFFFFFFF,
            0x7FFFFFFFFFFFF,
            0x7FFFFFFFFFFFF,
        ]);

        // 2^255-19 FieldElement representation
        let fe25519 = Fe([
            0x7FFFFFFFFFFED,
            0x7FFFFFFFFFFFF,
            0x7FFFFFFFFFFFF,
            0x7FFFFFFFFFFFF,
            0x7FFFFFFFFFFFF,
        ]);

        // 2^255-18 FieldElement representation
        let fe25518 = Fe([
            0x7FFFFFFFFFFEE,
            0x7FFFFFFFFFFFF,
            0x7FFFFFFFFFFFF,
            0x7FFFFFFFFFFFF,
            0x7FFFFFFFFFFFF,
        ]);
        assert_eq!(Fe::ZERO.to_bytes(), fe25519.to_bytes());
        assert_eq!(Fe::ONE.to_bytes(), fe25518.to_bytes());
        assert_eq!((&Fe::ZERO - &Fe::ONE).to_bytes(), fe25520.to_bytes());
    }
}
