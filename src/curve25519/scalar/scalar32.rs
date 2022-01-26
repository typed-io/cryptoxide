use super::super::fe::load::{load_3i, load_4i};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scalar([u8; 32]);

impl Scalar {
    pub const ZERO: Self = Scalar([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);

    pub const fn from_bytes(bytes: &[u8; 32]) -> Self {
        Scalar(*bytes)
    }

    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn from_bytes_canonical(bytes: &[u8; 32]) -> Option<Self> {
        const L: [u8; 32] = [
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a,
            0x5c, 0xf5, 0xd3, 0xed,
        ];

        fn check_s_lt_l(s: &[u8; 32]) -> bool {
            let mut c: u8 = 0;
            let mut n: u8 = 1;

            let mut i = 31;
            loop {
                c |= ((((s[i] as i32) - (L[i] as i32)) >> 8) as u8) & n;
                n &= ((((s[i] ^ L[i]) as i32) - 1) >> 8) as u8;
                if i == 0 {
                    break;
                } else {
                    i -= 1;
                }
            }

            c == 0
        }

        if check_s_lt_l(bytes) {
            None
        } else {
            Some(Scalar::from_bytes(bytes))
        }
    }

    #[inline]
    pub(crate) fn bits(&self) -> [i8; 256] {
        let a: &[u8; 32] = &self.0;
        let mut r = [0i8; 256];
        for i in 0..256 {
            r[i] = (1 & (a[i >> 3] >> (i & 7))) as i8;
        }
        r
    }

    /// Get the scalar in a form of 64 nibbles
    ///
    /// nibble is a group of 4-bits
    pub(crate) fn nibbles(&self) -> [i8; 64] {
        let mut es: [i8; 64] = [0; 64];
        let a = self.0;

        for i in 0..32 {
            es[2 * i + 0] = ((a[i] >> 0) & 0b1111) as i8;
            es[2 * i + 1] = ((a[i] >> 4) & 0b1111) as i8;
        }
        es
    }

    /// Create a new scalar from 64 bytes (512 bits) reducing
    /// the scalar to an element of the field
    ///
    /// Input is a little endian 512 bits scalar value:
    /// s[0]+256*s[1]+...+256^63*s[63] = s
    ///
    /// And the output scalar is a `s % order of field`
    #[rustfmt::skip]
    #[must_use]
    pub fn reduce_from_wide_bytes(s: &[u8; 64]) -> Scalar {
        let mut s0: i64 = 2097151 & load_3i(s);
        let mut s1: i64 = 2097151 & (load_4i(&s[2..6]) >> 5);
        let mut s2: i64 = 2097151 & (load_3i(&s[5..8]) >> 2);
        let mut s3: i64 = 2097151 & (load_4i(&s[7..11]) >> 7);
        let mut s4: i64 = 2097151 & (load_4i(&s[10..14]) >> 4);
        let mut s5: i64 = 2097151 & (load_3i(&s[13..16]) >> 1);
        let mut s6: i64 = 2097151 & (load_4i(&s[15..19]) >> 6);
        let mut s7: i64 = 2097151 & (load_3i(&s[18..21]) >> 3);
        let mut s8: i64 = 2097151 & load_3i(&s[21..24]);
        let mut s9: i64 = 2097151 & (load_4i(&s[23..27]) >> 5);
        let mut s10: i64 = 2097151 & (load_3i(&s[26..29]) >> 2);
        let mut s11: i64 = 2097151 & (load_4i(&s[28..32]) >> 7);
        let mut s12: i64 = 2097151 & (load_4i(&s[31..35]) >> 4);
        let mut s13: i64 = 2097151 & (load_3i(&s[34..37]) >> 1);
        let mut s14: i64 = 2097151 & (load_4i(&s[36..40]) >> 6);
        let mut s15: i64 = 2097151 & (load_3i(&s[39..42]) >> 3);
        let mut s16: i64 = 2097151 & load_3i(&s[42..45]);
        let mut s17: i64 = 2097151 & (load_4i(&s[44..48]) >> 5);
        let s18: i64 = 2097151 & (load_3i(&s[47..50]) >> 2);
        let s19: i64 = 2097151 & (load_4i(&s[49..53]) >> 7);
        let s20: i64 = 2097151 & (load_4i(&s[52..56]) >> 4);
        let s21: i64 = 2097151 & (load_3i(&s[55..58]) >> 1);
        let s22: i64 = 2097151 & (load_4i(&s[57..61]) >> 6);
        let s23: i64 = load_4i(&s[60..64]) >> 3;
        let mut carry0: i64;
        let mut carry1: i64;
        let mut carry2: i64;
        let mut carry3: i64;
        let mut carry4: i64;
        let mut carry5: i64;
        let mut carry6: i64;
        let mut carry7: i64;
        let mut carry8: i64;
        let mut carry9: i64;
        let mut carry10: i64;
        let mut carry11: i64;
        let carry12: i64;
        let carry13: i64;
        let carry14: i64;
        let carry15: i64;
        let carry16: i64;

        s11 += s23 * 666643;
        s12 += s23 * 470296;
        s13 += s23 * 654183;
        s14 -= s23 * 997805;
        s15 += s23 * 136657;
        s16 -= s23 * 683901;


        s10 += s22 * 666643;
        s11 += s22 * 470296;
        s12 += s22 * 654183;
        s13 -= s22 * 997805;
        s14 += s22 * 136657;
        s15 -= s22 * 683901;


        s9 += s21 * 666643;
        s10 += s21 * 470296;
        s11 += s21 * 654183;
        s12 -= s21 * 997805;
        s13 += s21 * 136657;
        s14 -= s21 * 683901;


        s8 += s20 * 666643;
        s9 += s20 * 470296;
        s10 += s20 * 654183;
        s11 -= s20 * 997805;
        s12 += s20 * 136657;
        s13 -= s20 * 683901;


        s7 += s19 * 666643;
        s8 += s19 * 470296;
        s9 += s19 * 654183;
        s10 -= s19 * 997805;
        s11 += s19 * 136657;
        s12 -= s19 * 683901;


        s6 += s18 * 666643;
        s7 += s18 * 470296;
        s8 += s18 * 654183;
        s9 -= s18 * 997805;
        s10 += s18 * 136657;
        s11 -= s18 * 683901;


        carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
        carry12 = (s12 + (1<<20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
        carry14 = (s14 + (1<<20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
        carry16 = (s16 + (1<<20)) >> 21; s17 += carry16; s16 -= carry16 << 21;

        carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry13 = (s13 + (1<<20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
        carry15 = (s15 + (1<<20)) >> 21; s16 += carry15; s15 -= carry15 << 21;

        s5 += s17 * 666643;
        s6 += s17 * 470296;
        s7 += s17 * 654183;
        s8 -= s17 * 997805;
        s9 += s17 * 136657;
        s10 -= s17 * 683901;


        s4 += s16 * 666643;
        s5 += s16 * 470296;
        s6 += s16 * 654183;
        s7 -= s16 * 997805;
        s8 += s16 * 136657;
        s9 -= s16 * 683901;


        s3 += s15 * 666643;
        s4 += s15 * 470296;
        s5 += s15 * 654183;
        s6 -= s15 * 997805;
        s7 += s15 * 136657;
        s8 -= s15 * 683901;


        s2 += s14 * 666643;
        s3 += s14 * 470296;
        s4 += s14 * 654183;
        s5 -= s14 * 997805;
        s6 += s14 * 136657;
        s7 -= s14 * 683901;


        s1 += s13 * 666643;
        s2 += s13 * 470296;
        s3 += s13 * 654183;
        s4 -= s13 * 997805;
        s5 += s13 * 136657;
        s6 -= s13 * 683901;


        s0 += s12 * 666643;
        s1 += s12 * 470296;
        s2 += s12 * 654183;
        s3 -= s12 * 997805;
        s4 += s12 * 136657;
        s5 -= s12 * 683901;
        s12 = 0;

        carry0 = (s0 + (1<<20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry2 = (s2 + (1<<20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry4 = (s4 + (1<<20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;

        carry1 = (s1 + (1<<20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry3 = (s3 + (1<<20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry5 = (s5 + (1<<20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;

        s0 += s12 * 666643;
        s1 += s12 * 470296;
        s2 += s12 * 654183;
        s3 -= s12 * 997805;
        s4 += s12 * 136657;
        s5 -= s12 * 683901;
        s12 = 0;

        carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
        carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;

        s0 += s12 * 666643;
        s1 += s12 * 470296;
        s2 += s12 * 654183;
        s3 -= s12 * 997805;
        s4 += s12 * 136657;
        s5 -= s12 * 683901;


        carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

        let mut out = [0u8; 32];
        out[0] = (s0 >> 0) as u8;
        out[1] = (s0 >> 8) as u8;
        out[2] = ((s0 >> 16) | (s1 << 5)) as u8;
        out[3] = (s1 >> 3) as u8;
        out[4] = (s1 >> 11) as u8;
        out[5] = ((s1 >> 19) | (s2 << 2)) as u8;
        out[6] = (s2 >> 6) as u8;
        out[7] = ((s2 >> 14) | (s3 << 7)) as u8;
        out[8] = (s3 >> 1) as u8;
        out[9] = (s3 >> 9) as u8;
        out[10] = ((s3 >> 17) | (s4 << 4)) as u8;
        out[11] = (s4 >> 4) as u8;
        out[12] = (s4 >> 12) as u8;
        out[13] = ((s4 >> 20) | (s5 << 1)) as u8;
        out[14] = (s5 >> 7) as u8;
        out[15] = ((s5 >> 15) | (s6 << 6)) as u8;
        out[16] = (s6 >> 2) as u8;
        out[17] = (s6 >> 10) as u8;
        out[18] = ((s6 >> 18) | (s7 << 3)) as u8;
        out[19] = (s7 >> 5) as u8;
        out[20] = (s7 >> 13) as u8;
        out[21] = (s8 >> 0) as u8;
        out[22] = (s8 >> 8) as u8;
        out[23] = ((s8 >> 16) | (s9 << 5)) as u8;
        out[24] = (s9 >> 3) as u8;
        out[25] = (s9 >> 11) as u8;
        out[26] = ((s9 >> 19) | (s10 << 2)) as u8;
        out[27] = (s10 >> 6) as u8;
        out[28] = ((s10 >> 14) | (s11 << 7)) as u8;
        out[29] = (s11 >> 1) as u8;
        out[30] = (s11 >> 9) as u8;
        out[31] = (s11 >> 17) as u8;
        Scalar(out)
    }
}

/*
Input:
    a[0]+256*a[1]+...+256^31*a[31] = a
    b[0]+256*b[1]+...+256^31*b[31] = b
    c[0]+256*c[1]+...+256^31*c[31] = c

Output:
    s[0]+256*s[1]+...+256^31*s[31] = (ab+c) mod l
    where l = 2^252 + 27742317777372353535851937790883648493.
*/
#[rustfmt::skip]
pub(crate) fn muladd(Scalar(a): &Scalar, Scalar(b): &Scalar, Scalar(c): &Scalar) -> Scalar {
    let a0 = 2097151 & load_3i(&a[0..3]);
    let a1 = 2097151 & (load_4i(&a[2..6]) >> 5);
    let a2 = 2097151 & (load_3i(&a[5..8]) >> 2);
    let a3 = 2097151 & (load_4i(&a[7..11]) >> 7);
    let a4 = 2097151 & (load_4i(&a[10..14]) >> 4);
    let a5 = 2097151 & (load_3i(&a[13..16]) >> 1);
    let a6 = 2097151 & (load_4i(&a[15..19]) >> 6);
    let a7 = 2097151 & (load_3i(&a[18..21]) >> 3);
    let a8 = 2097151 & load_3i(&a[21..24]);
    let a9 = 2097151 & (load_4i(&a[23..27]) >> 5);
    let a10 = 2097151 & (load_3i(&a[26..29]) >> 2);
    let a11 = load_4i(&a[28..32]) >> 7;
    let b0 = 2097151 & load_3i(&b[0..3]);
    let b1 = 2097151 & (load_4i(&b[2..6]) >> 5);
    let b2 = 2097151 & (load_3i(&b[5..8]) >> 2);
    let b3 = 2097151 & (load_4i(&b[7..11]) >> 7);
    let b4 = 2097151 & (load_4i(&b[10..14]) >> 4);
    let b5 = 2097151 & (load_3i(&b[13..16]) >> 1);
    let b6 = 2097151 & (load_4i(&b[15..19]) >> 6);
    let b7 = 2097151 & (load_3i(&b[18..21]) >> 3);
    let b8 = 2097151 & load_3i(&b[21..24]);
    let b9 = 2097151 & (load_4i(&b[23..27]) >> 5);
    let b10 = 2097151 & (load_3i(&b[26..29]) >> 2);
    let b11 = load_4i(&b[28..32]) >> 7;
    let c0 = 2097151 & load_3i(&c[0..3]);
    let c1 = 2097151 & (load_4i(&c[2..6]) >> 5);
    let c2 = 2097151 & (load_3i(&c[5..8]) >> 2);
    let c3 = 2097151 & (load_4i(&c[7..11]) >> 7);
    let c4 = 2097151 & (load_4i(&c[10..14]) >> 4);
    let c5 = 2097151 & (load_3i(&c[13..16]) >> 1);
    let c6 = 2097151 & (load_4i(&c[15..19]) >> 6);
    let c7 = 2097151 & (load_3i(&c[18..21]) >> 3);
    let c8 = 2097151 & load_3i(&c[21..24]);
    let c9 = 2097151 & (load_4i(&c[23..27]) >> 5);
    let c10 = 2097151 & (load_3i(&c[26..29]) >> 2);
    let c11 = load_4i(&c[28..32]) >> 7;
    let mut s0: i64;
    let mut s1: i64;
    let mut s2: i64;
    let mut s3: i64;
    let mut s4: i64;
    let mut s5: i64;
    let mut s6: i64;
    let mut s7: i64;
    let mut s8: i64;
    let mut s9: i64;
    let mut s10: i64;
    let mut s11: i64;
    let mut s12: i64;
    let mut s13: i64;
    let mut s14: i64;
    let mut s15: i64;
    let mut s16: i64;
    let mut s17: i64;
    let mut s18: i64;
    let mut s19: i64;
    let mut s20: i64;
    let mut s21: i64;
    let mut s22: i64;
    let mut s23: i64;
    let mut carry0: i64;
    let mut carry1: i64;
    let mut carry2: i64;
    let mut carry3: i64;
    let mut carry4: i64;
    let mut carry5: i64;
    let mut carry6: i64;
    let mut carry7: i64;
    let mut carry8: i64;
    let mut carry9: i64;
    let mut carry10: i64;
    let mut carry11: i64;
    let mut carry12: i64;
    let mut carry13: i64;
    let mut carry14: i64;
    let mut carry15: i64;
    let mut carry16: i64;
    let carry17: i64;
    let carry18: i64;
    let carry19: i64;
    let carry20: i64;
    let carry21: i64;
    let carry22: i64;

    s0 = c0 + a0*b0;
    s1 = c1 + a0*b1 + a1*b0;
    s2 = c2 + a0*b2 + a1*b1 + a2*b0;
    s3 = c3 + a0*b3 + a1*b2 + a2*b1 + a3*b0;
    s4 = c4 + a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0;
    s5 = c5 + a0*b5 + a1*b4 + a2*b3 + a3*b2 + a4*b1 + a5*b0;
    s6 = c6 + a0*b6 + a1*b5 + a2*b4 + a3*b3 + a4*b2 + a5*b1 + a6*b0;
    s7 = c7 + a0*b7 + a1*b6 + a2*b5 + a3*b4 + a4*b3 + a5*b2 + a6*b1 + a7*b0;
    s8 = c8 + a0*b8 + a1*b7 + a2*b6 + a3*b5 + a4*b4 + a5*b3 + a6*b2 + a7*b1 + a8*b0;
    s9 = c9 + a0*b9 + a1*b8 + a2*b7 + a3*b6 + a4*b5 + a5*b4 + a6*b3 + a7*b2 + a8*b1 + a9*b0;
    s10 = c10 + a0*b10 + a1*b9 + a2*b8 + a3*b7 + a4*b6 + a5*b5 + a6*b4 + a7*b3 + a8*b2 + a9*b1 + a10*b0;
    s11 = c11 + a0*b11 + a1*b10 + a2*b9 + a3*b8 + a4*b7 + a5*b6 + a6*b5 + a7*b4 + a8*b3 + a9*b2 + a10*b1 + a11*b0;
    s12 = a1*b11 + a2*b10 + a3*b9 + a4*b8 + a5*b7 + a6*b6 + a7*b5 + a8*b4 + a9*b3 + a10*b2 + a11*b1;
    s13 = a2*b11 + a3*b10 + a4*b9 + a5*b8 + a6*b7 + a7*b6 + a8*b5 + a9*b4 + a10*b3 + a11*b2;
    s14 = a3*b11 + a4*b10 + a5*b9 + a6*b8 + a7*b7 + a8*b6 + a9*b5 + a10*b4 + a11*b3;
    s15 = a4*b11 + a5*b10 + a6*b9 + a7*b8 + a8*b7 + a9*b6 + a10*b5 + a11*b4;
    s16 = a5*b11 + a6*b10 + a7*b9 + a8*b8 + a9*b7 + a10*b6 + a11*b5;
    s17 = a6*b11 + a7*b10 + a8*b9 + a9*b8 + a10*b7 + a11*b6;
    s18 = a7*b11 + a8*b10 + a9*b9 + a10*b8 + a11*b7;
    s19 = a8*b11 + a9*b10 + a10*b9 + a11*b8;
    s20 = a9*b11 + a10*b10 + a11*b9;
    s21 = a10*b11 + a11*b10;
    s22 = a11*b11;
    s23 = 0;

    carry0 = (s0 + (1<<20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry2 = (s2 + (1<<20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry4 = (s4 + (1<<20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
    carry12 = (s12 + (1<<20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
    carry14 = (s14 + (1<<20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
    carry16 = (s16 + (1<<20)) >> 21; s17 += carry16; s16 -= carry16 << 21;
    carry18 = (s18 + (1<<20)) >> 21; s19 += carry18; s18 -= carry18 << 21;
    carry20 = (s20 + (1<<20)) >> 21; s21 += carry20; s20 -= carry20 << 21;
    carry22 = (s22 + (1<<20)) >> 21; s23 += carry22; s22 -= carry22 << 21;

    carry1 = (s1 + (1<<20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry3 = (s3 + (1<<20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry5 = (s5 + (1<<20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
    carry13 = (s13 + (1<<20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
    carry15 = (s15 + (1<<20)) >> 21; s16 += carry15; s15 -= carry15 << 21;
    carry17 = (s17 + (1<<20)) >> 21; s18 += carry17; s17 -= carry17 << 21;
    carry19 = (s19 + (1<<20)) >> 21; s20 += carry19; s19 -= carry19 << 21;
    carry21 = (s21 + (1<<20)) >> 21; s22 += carry21; s21 -= carry21 << 21;

    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;


    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;


    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;


    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;


    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;


    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;


    carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
    carry12 = (s12 + (1<<20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
    carry14 = (s14 + (1<<20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
    carry16 = (s16 + (1<<20)) >> 21; s17 += carry16; s16 -= carry16 << 21;

    carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
    carry13 = (s13 + (1<<20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
    carry15 = (s15 + (1<<20)) >> 21; s16 += carry15; s15 -= carry15 << 21;

    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;


    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;


    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;


    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;


    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;


    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = (s0 + (1<<20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry2 = (s2 + (1<<20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry4 = (s4 + (1<<20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;

    carry1 = (s1 + (1<<20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry3 = (s3 + (1<<20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry5 = (s5 + (1<<20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
    carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;


    carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

    let mut s = [0u8; 32];
    s[0] = (s0 >> 0) as u8;
    s[1] = (s0 >> 8) as u8;
    s[2] = ((s0 >> 16) | (s1 << 5)) as u8;
    s[3] = (s1 >> 3) as u8;
    s[4] = (s1 >> 11) as u8;
    s[5] = ((s1 >> 19) | (s2 << 2)) as u8;
    s[6] = (s2 >> 6) as u8;
    s[7] = ((s2 >> 14) | (s3 << 7)) as u8;
    s[8] = (s3 >> 1) as u8;
    s[9] = (s3 >> 9) as u8;
    s[10] = ((s3 >> 17) | (s4 << 4)) as u8;
    s[11] = (s4 >> 4) as u8;
    s[12] = (s4 >> 12) as u8;
    s[13] = ((s4 >> 20) | (s5 << 1)) as u8;
    s[14] = (s5 >> 7) as u8;
    s[15] = ((s5 >> 15) | (s6 << 6)) as u8;
    s[16] = (s6 >> 2) as u8;
    s[17] = (s6 >> 10) as u8;
    s[18] = ((s6 >> 18) | (s7 << 3)) as u8;
    s[19] = (s7 >> 5) as u8;
    s[20] = (s7 >> 13) as u8;
    s[21] = (s8 >> 0) as u8;
    s[22] = (s8 >> 8) as u8;
    s[23] = ((s8 >> 16) | (s9 << 5)) as u8;
    s[24] = (s9 >> 3) as u8;
    s[25] = (s9 >> 11) as u8;
    s[26] = ((s9 >> 19) | (s10 << 2)) as u8;
    s[27] = (s10 >> 6) as u8;
    s[28] = ((s10 >> 14) | (s11 << 7)) as u8;
    s[29] = (s11 >> 1) as u8;
    s[30] = (s11 >> 9) as u8;
    s[31] = (s11 >> 17) as u8;
    Scalar(s)
}
