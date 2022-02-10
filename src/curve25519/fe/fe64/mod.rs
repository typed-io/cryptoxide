//! Field Element implementation for 64-bits native arch using unsaturated 51-bits limbs.
//!
//! arithmetic calculation helpers:
//!
//! * [ed25519-donna](https://github.com/floodyberry/ed25519-donna)
//! * Sandy2x: New Curve25519 Speed Records

use crate::constant_time::{ct_array64_maybe_set, ct_array64_maybe_swap_with, Choice, CtEqual};
use core::ops::{Add, Mul, Neg, Sub};

pub mod precomp;

// multiple of P
const FOUR_P0: u64 = 0x1fffffffffffb4;
const FOUR_P1234: u64 = 0x1ffffffffffffc;

/// Field Element in ℤ/(2^255-19)
#[derive(Clone)]
pub struct Fe(pub(crate) [u64; 5]);

impl CtEqual for &Fe {
    fn ct_eq(self, other: Self) -> Choice {
        let p1 = self.to_packed();
        let p2 = other.to_packed();
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

#[inline]
const fn mul128(a: u64, b: u64) -> u128 {
    a as u128 * b as u128
}

#[inline]
fn shl128(v: u128, shift: usize) -> u64 {
    ((v << shift) >> 64) as u64
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

    #[rustfmt::skip]
    fn neg(self) -> Fe {
        let Fe([g0, g1, g2, g3, g4]) = *self;

        let mut h0 = FOUR_P0    - g0    ; let c = h0 >> 51; h0 &= MASK;
        let mut h1 = FOUR_P1234 - g1 + c; let c = h1 >> 51; h1 &= MASK;
        let mut h2 = FOUR_P1234 - g2 + c; let c = h2 >> 51; h2 &= MASK;
        let mut h3 = FOUR_P1234 - g3 + c; let c = h3 >> 51; h3 &= MASK;
        let mut h4 = FOUR_P1234 - g4 + c; let c = h4 >> 51; h4 &= MASK;
        h0 += c * 19;
        Fe([h0, h1, h2, h3, h4])
    }
}

impl Mul for &Fe {
    type Output = Fe;

    #[rustfmt::skip]
    fn mul(self, rhs: &Fe) -> Fe {
        let Fe([mut r0, mut r1, mut r2, mut r3, mut r4]) = *self;
        let Fe([s0, s1, s2, s3, s4]) = *rhs;

        let mut t0 = mul128(r0, s0);
        let mut t1 = mul128(r0, s1) + mul128(r1, s0);
        let mut t2 = mul128(r0, s2) + mul128(r2, s0) + mul128(r1, s1);
        let mut t3 = mul128(r0, s3) + mul128(r3, s0) + mul128(r1, s2) + mul128(r2, s1);
        let mut t4 = mul128(r0, s4) + mul128(r4, s0) + mul128(r3, s1) + mul128(r1, s3) + mul128(r2, s2);

        r1 *= 19;
        r2 *= 19;
        r3 *= 19;
        r4 *= 19;

        t0 += mul128(r4, s1) + mul128(r1, s4) + mul128(r2, s3) + mul128(r3, s2);
        t1 += mul128(r4, s2) + mul128(r2, s4) + mul128(r3, s3);
        t2 += mul128(r4, s3) + mul128(r3, s4);
        t3 += mul128(r4, s4);

        r0 = (t0 as u64) & MASK; let c = (t0 >> 51) as u64; t1 += c as u128;
        r1 = (t1 as u64) & MASK; let c = (t1 >> 51) as u64; t2 += c as u128;
        r2 = (t2 as u64) & MASK; let c = (t2 >> 51) as u64; t3 += c as u128;
        r3 = (t3 as u64) & MASK; let c = (t3 >> 51) as u64; t4 += c as u128;
        r4 = (t4 as u64) & MASK; let c = (t4 >> 51) as u64; r0 += c * 19;
                                 let c = r0 >> 51         ; r0 = r0 & MASK;
        r1 += c;

        Fe([r0, r1, r2, r3, r4])
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

    pub(crate) const fn to_packed(&self) -> [u64; 4] {
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
        [out0, out1, out2, out3]
    }

    /// Represent the Field Element as little-endian canonical bytes (256 bits)
    ///
    /// Due to the field size, it's guarantee that the highest bit is always 0
    pub const fn to_bytes(&self) -> [u8; 32] {
        let [out0, out1, out2, out3] = self.to_packed();
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

    #[rustfmt::skip]
    pub(crate) const fn mul_small<const S0: u32>(&self) -> Fe {
        let Fe([mut r0, mut r1, mut r2, mut r3, mut r4]) = *self;
        let s0 = S0 as u64;

        let t0 = mul128(r0, s0);
        let mut t1 = mul128(r1, s0);
        let mut t2 = mul128(r2, s0);
        let mut t3 = mul128(r3, s0);
        let mut t4 = mul128(r4, s0);

        r0 = (t0 as u64) & MASK; let c = (t0 >> 51) as u64; t1 += c as u128;
        r1 = (t1 as u64) & MASK; let c = (t1 >> 51) as u64; t2 += c as u128;
        r2 = (t2 as u64) & MASK; let c = (t2 >> 51) as u64; t3 += c as u128;
        r3 = (t3 as u64) & MASK; let c = (t3 >> 51) as u64; t4 += c as u128;
        r4 = (t4 as u64) & MASK; let c = (t4 >> 51) as u64; r0 += c * 19;
                                 let c = r0 >> 51         ; r0 = r0 & MASK;
        r1 += c;

        Fe([r0, r1, r2, r3, r4])
    }

    #[rustfmt::skip]
    pub(crate) fn negate_mut(&mut self) {
        self.0[0] = FOUR_P0    - self.0[0]    ; let c = self.0[0] >> 51; self.0[0] &= MASK;
        self.0[1] = FOUR_P1234 - self.0[1] + c; let c = self.0[1] >> 51; self.0[1] &= MASK;
        self.0[2] = FOUR_P1234 - self.0[2] + c; let c = self.0[2] >> 51; self.0[2] &= MASK;
        self.0[3] = FOUR_P1234 - self.0[3] + c; let c = self.0[3] >> 51; self.0[3] &= MASK;
        self.0[4] = FOUR_P1234 - self.0[4] + c; let c = self.0[4] >> 51; self.0[4] &= MASK;
        self.0[0] += c * 19;
    }

    /// Compute the square of the field element
    #[rustfmt::skip]
    pub fn square(&self) -> Fe {
        let Fe([mut r0, mut r1, mut r2, mut r3, mut r4]) = *self;

        let d0 = r0 * 2;
        let d1 = r1 * 2;
        let d2 = r2 * 2 * 19;
        let d419 = r4 * 19;
        let d4 = d419 * 2;

        let t0 = mul128(r0, r0) + mul128(d4, r1) + mul128(d2 ,r3     );
        let t1 = mul128(d0, r1) + mul128(d4, r2) + mul128(r3 ,r3 * 19);
        let t2 = mul128(d0, r2) + mul128(r1, r1) + mul128(d4 ,r3     );
        let t3 = mul128(d0, r3) + mul128(d1, r2) + mul128(r4 ,d419   );
        let t4 = mul128(d0, r4) + mul128(d1, r3) + mul128(r2 ,r2     );

        r0 = (t0 as u64) & MASK;
        r1 = (t1 as u64) & MASK; let c = shl128(t0, 13); r1 += c;
        r2 = (t2 as u64) & MASK; let c = shl128(t1, 13); r2 += c;
        r3 = (t3 as u64) & MASK; let c = shl128(t2, 13); r3 += c;
        r4 = (t4 as u64) & MASK; let c = shl128(t3, 13); r4 += c;
                                 let c = shl128(t4, 13); r0 += c * 19;
                      let c = r0 >> 51; r0 &= MASK;
        r1 += c     ; let c = r1 >> 51; r1 &= MASK;
        r2 += c     ; let c = r2 >> 51; r2 &= MASK;
        r3 += c     ; let c = r3 >> 51; r3 &= MASK;
        r4 += c     ; let c = r4 >> 51; r4 &= MASK;
        r0 += c * 19;

        Fe([r0, r1, r2, r3, r4])
    }

    /// Compute the (2^N) square of the field element
    ///
    /// This is performed by repeated squaring of the element
    ///
    /// square_repeadtly(n) = ((X^2)^2)^2... = X^(2^N)
    #[rustfmt::skip]
    pub fn square_repeatdly(&self, n: usize) -> Fe {
        let Fe([mut r0, mut r1, mut r2, mut r3, mut r4]) = *self;

        for _ in 0..n {
            let d0 = r0 * 2;
            let d1 = r1 * 2;
            let d2 = r2 * 2 * 19;
            let d419 = r4 * 19;
            let d4 = d419 * 2;

            let t0 = mul128(r0, r0) + mul128(d4, r1) + mul128(d2 ,r3     );
            let t1 = mul128(d0, r1) + mul128(d4, r2) + mul128(r3 ,r3 * 19);
            let t2 = mul128(d0, r2) + mul128(r1, r1) + mul128(d4 ,r3     );
            let t3 = mul128(d0, r3) + mul128(d1, r2) + mul128(r4 ,d419   );
            let t4 = mul128(d0, r4) + mul128(d1, r3) + mul128(r2 ,r2     );

            r0 = (t0 as u64) & MASK;
            r1 = (t1 as u64) & MASK; let c = shl128(t0, 13); r1 += c;
            r2 = (t2 as u64) & MASK; let c = shl128(t1, 13); r2 += c;
            r3 = (t3 as u64) & MASK; let c = shl128(t2, 13); r3 += c;
            r4 = (t4 as u64) & MASK; let c = shl128(t3, 13); r4 += c;
                                     let c = shl128(t4, 13); r0 += c * 19;
                          let c = r0 >> 51; r0 &= MASK;
            r1 += c     ; let c = r1 >> 51; r1 &= MASK;
            r2 += c     ; let c = r2 >> 51; r2 &= MASK;
            r3 += c     ; let c = r3 >> 51; r3 &= MASK;
            r4 += c     ; let c = r4 >> 51; r4 &= MASK;
            r0 += c * 19;
        }

        Fe([r0, r1, r2, r3, r4])
    }

    /// Compute the square of the element and returns its double
    ///
    /// this is more efficient than squaring and adding the result together
    pub fn square_and_double(&self) -> Fe {
        let mut x = self.square();
        for e in x.0.iter_mut() {
            *e *= 2;
        }
        x
    }

    pub fn is_nonzero(&self) -> bool {
        CtEqual::ct_ne(&self.to_bytes(), &[0; 32]).into()
    }

    pub fn is_negative(&self) -> bool {
        (self.to_packed()[0] & 1) != 0
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
