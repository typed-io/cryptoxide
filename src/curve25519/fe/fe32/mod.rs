use crate::constant_time::{ct_array32_maybe_set, ct_array32_maybe_swap_with, Choice, CtEqual};
use core::cmp::{Eq, PartialEq};
use core::ops::{Add, Mul, Neg, Sub};

pub mod precomp;

use super::load::{load_3i, load_4i};

/// Field Element in ℤ/(2^255-19)
///
/// An element t, entries `t[0]...t[9]`, represents the integer
/// `t[0]+2^26*t[1]+2^51*t[2]+2^77*t[3]+2^102*t[4]+...+2^230*t[9]`.
/// Bounds on each t[i] vary depending on context.
#[derive(Clone)]
pub struct Fe(pub(crate) [i32; 10]);

impl PartialEq for Fe {
    fn eq(&self, other: &Fe) -> bool {
        let &Fe(self_elems) = self;
        let &Fe(other_elems) = other;
        self_elems == other_elems
    }
}
impl Eq for Fe {}

impl Fe {
    pub const ZERO: Fe = Fe([0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    pub const ONE: Fe = Fe([1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    pub const SQRTM1: Fe = Fe([
        -32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686,
        11406482,
    ]);
    pub const D: Fe = Fe([
        -10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448,
        -12055116,
    ]);
    pub const D2: Fe = Fe([
        -21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968,
        9444199,
    ]);
}

// extended multiplication 32x32 -> 64
#[inline(always)]
fn emul(a: i32, b: i32) -> i64 {
    (a as i64) * (b as i64)
}

impl Add for Fe {
    type Output = Fe;
    fn add(self, rhs: Fe) -> Fe {
        &self + &rhs
    }
}

impl Add for &Fe {
    type Output = Fe;

    /*
    h = f + g
    Can overlap h with f or g.

    Preconditions:
       |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
       |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.

    Postconditions:
       |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
    */
    fn add(self, rhs: &Fe) -> Fe {
        let Fe([f0, f1, f2, f3, f4, f5, f6, f7, f8, f9]) = *self;
        let Fe([g0, g1, g2, g3, g4, g5, g6, g7, g8, g9]) = *rhs;

        let h0 = f0 + g0;
        let h1 = f1 + g1;
        let h2 = f2 + g2;
        let h3 = f3 + g3;
        let h4 = f4 + g4;
        let h5 = f5 + g5;
        let h6 = f6 + g6;
        let h7 = f7 + g7;
        let h8 = f8 + g8;
        let h9 = f9 + g9;
        Fe([h0, h1, h2, h3, h4, h5, h6, h7, h8, h9])
    }
}

impl Sub for Fe {
    type Output = Fe;
    fn sub(self, rhs: Fe) -> Fe {
        &self - &rhs
    }
}

impl Sub for &Fe {
    type Output = Fe;

    /*
    h = f - g
    Can overlap h with f or g.

    Preconditions:
       |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
       |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.

    Postconditions:
       |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
    */
    fn sub(self, rhs: &Fe) -> Fe {
        let Fe([f0, f1, f2, f3, f4, f5, f6, f7, f8, f9]) = *self;
        let Fe([g0, g1, g2, g3, g4, g5, g6, g7, g8, g9]) = *rhs;

        let h0 = f0 - g0;
        let h1 = f1 - g1;
        let h2 = f2 - g2;
        let h3 = f3 - g3;
        let h4 = f4 - g4;
        let h5 = f5 - g5;
        let h6 = f6 - g6;
        let h7 = f7 - g7;
        let h8 = f8 - g8;
        let h9 = f9 - g9;
        Fe([h0, h1, h2, h3, h4, h5, h6, h7, h8, h9])
    }
}

impl Mul for Fe {
    type Output = Fe;
    fn mul(self, rhs: Fe) -> Fe {
        &self * &rhs
    }
}

impl Mul for &Fe {
    type Output = Fe;

    /*
    h = f * g
    Can overlap h with f or g.

    Preconditions:
       |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
       |g| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.

    Postconditions:
       |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
    */

    /*
    Notes on implementation strategy:

    Using schoolbook multiplication.
    Karatsuba would save a little in some cost models.

    Most multiplications by 2 and 19 are 32-bit precomputations;
    cheaper than 64-bit postcomputations.

    There is one remaining multiplication by 19 in the carry chain;
    one *19 precomputation can be merged into this,
    but the resulting data flow is considerably less clean.

    There are 12 carries below.
    10 of them are 2-way parallelizable and vectorizable.
    Can get away with 11 carries, but then data flow is much deeper.

    With tighter constraints on inputs can squeeze carries into int32.
    */
    #[rustfmt::skip]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: &Fe) -> Fe {
        let Fe([f0, f1, f2, f3, f4, f5, f6, f7, f8, f9]) = *self;
        let Fe([g0, g1, g2, g3, g4, g5, g6, g7, g8, g9]) = *rhs;

        let g1_19 = 19 * g1; /* 1.4*2^29 */
        let g2_19 = 19 * g2; /* 1.4*2^30; still ok */
        let g3_19 = 19 * g3;
        let g4_19 = 19 * g4;
        let g5_19 = 19 * g5;
        let g6_19 = 19 * g6;
        let g7_19 = 19 * g7;
        let g8_19 = 19 * g8;
        let g9_19 = 19 * g9;
        let f1_2 = 2 * f1;
        let f3_2 = 2 * f3;
        let f5_2 = 2 * f5;
        let f7_2 = 2 * f7;
        let f9_2 = 2 * f9;
        let f0g0    = emul(f0   , g0);
        let f0g1    = emul(f0   , g1);
        let f0g2    = emul(f0   , g2);
        let f0g3    = emul(f0   , g3);
        let f0g4    = emul(f0   , g4);
        let f0g5    = emul(f0   , g5);
        let f0g6    = emul(f0   , g6);
        let f0g7    = emul(f0   , g7);
        let f0g8    = emul(f0   , g8);
        let f0g9    = emul(f0   , g9);
        let f1g0    = emul(f1   , g0);
        let f1g1_2  = emul(f1_2 , g1);
        let f1g2    = emul(f1   , g2);
        let f1g3_2  = emul(f1_2 , g3);
        let f1g4    = emul(f1   , g4);
        let f1g5_2  = emul(f1_2 , g5);
        let f1g6    = emul(f1   , g6);
        let f1g7_2  = emul(f1_2 , g7);
        let f1g8    = emul(f1   , g8);
        let f1g9_38 = emul(f1_2 , g9_19);
        let f2g0    = emul(f2   , g0);
        let f2g1    = emul(f2   , g1);
        let f2g2    = emul(f2   , g2);
        let f2g3    = emul(f2   , g3);
        let f2g4    = emul(f2   , g4);
        let f2g5    = emul(f2   , g5);
        let f2g6    = emul(f2   , g6);
        let f2g7    = emul(f2   , g7);
        let f2g8_19 = emul(f2   , g8_19);
        let f2g9_19 = emul(f2   , g9_19);
        let f3g0    = emul(f3   , g0);
        let f3g1_2  = emul(f3_2 , g1);
        let f3g2    = emul(f3   , g2);
        let f3g3_2  = emul(f3_2 , g3);
        let f3g4    = emul(f3   , g4);
        let f3g5_2  = emul(f3_2 , g5);
        let f3g6    = emul(f3   , g6);
        let f3g7_38 = emul(f3_2 , g7_19);
        let f3g8_19 = emul(f3   , g8_19);
        let f3g9_38 = emul(f3_2 , g9_19);
        let f4g0    = emul(f4   , g0);
        let f4g1    = emul(f4   , g1);
        let f4g2    = emul(f4   , g2);
        let f4g3    = emul(f4   , g3);
        let f4g4    = emul(f4   , g4);
        let f4g5    = emul(f4   , g5);
        let f4g6_19 = emul(f4   , g6_19);
        let f4g7_19 = emul(f4   , g7_19);
        let f4g8_19 = emul(f4   , g8_19);
        let f4g9_19 = emul(f4   , g9_19);
        let f5g0    = emul(f5   , g0);
        let f5g1_2  = emul(f5_2 , g1);
        let f5g2    = emul(f5   , g2);
        let f5g3_2  = emul(f5_2 , g3);
        let f5g4    = emul(f5   , g4);
        let f5g5_38 = emul(f5_2 , g5_19);
        let f5g6_19 = emul(f5   , g6_19);
        let f5g7_38 = emul(f5_2 , g7_19);
        let f5g8_19 = emul(f5   , g8_19);
        let f5g9_38 = emul(f5_2 , g9_19);
        let f6g0    = emul(f6   , g0);
        let f6g1    = emul(f6   , g1);
        let f6g2    = emul(f6   , g2);
        let f6g3    = emul(f6   , g3);
        let f6g4_19 = emul(f6   , g4_19);
        let f6g5_19 = emul(f6   , g5_19);
        let f6g6_19 = emul(f6   , g6_19);
        let f6g7_19 = emul(f6   , g7_19);
        let f6g8_19 = emul(f6   , g8_19);
        let f6g9_19 = emul(f6   , g9_19);
        let f7g0    = emul(f7   , g0);
        let f7g1_2  = emul(f7_2 , g1);
        let f7g2    = emul(f7   , g2);
        let f7g3_38 = emul(f7_2 , g3_19);
        let f7g4_19 = emul(f7   , g4_19);
        let f7g5_38 = emul(f7_2 , g5_19);
        let f7g6_19 = emul(f7   , g6_19);
        let f7g7_38 = emul(f7_2 , g7_19);
        let f7g8_19 = emul(f7   , g8_19);
        let f7g9_38 = emul(f7_2 , g9_19);
        let f8g0    = emul(f8   , g0);
        let f8g1    = emul(f8   , g1);
        let f8g2_19 = emul(f8   , g2_19);
        let f8g3_19 = emul(f8   , g3_19);
        let f8g4_19 = emul(f8   , g4_19);
        let f8g5_19 = emul(f8   , g5_19);
        let f8g6_19 = emul(f8   , g6_19);
        let f8g7_19 = emul(f8   , g7_19);
        let f8g8_19 = emul(f8   , g8_19);
        let f8g9_19 = emul(f8   , g9_19);
        let f9g0    = emul(f9   , g0);
        let f9g1_38 = emul(f9_2 , g1_19);
        let f9g2_19 = emul(f9   , g2_19);
        let f9g3_38 = emul(f9_2 , g3_19);
        let f9g4_19 = emul(f9   , g4_19);
        let f9g5_38 = emul(f9_2 , g5_19);
        let f9g6_19 = emul(f9   , g6_19);
        let f9g7_38 = emul(f9_2 , g7_19);
        let f9g8_19 = emul(f9   , g8_19);
        let f9g9_38 = emul(f9_2 , g9_19);
        let mut h0 = f0g0+f1g9_38+f2g8_19+f3g7_38+f4g6_19+f5g5_38+f6g4_19+f7g3_38+f8g2_19+f9g1_38;
        let mut h1 = f0g1+f1g0   +f2g9_19+f3g8_19+f4g7_19+f5g6_19+f6g5_19+f7g4_19+f8g3_19+f9g2_19;
        let mut h2 = f0g2+f1g1_2 +f2g0   +f3g9_38+f4g8_19+f5g7_38+f6g6_19+f7g5_38+f8g4_19+f9g3_38;
        let mut h3 = f0g3+f1g2   +f2g1   +f3g0   +f4g9_19+f5g8_19+f6g7_19+f7g6_19+f8g5_19+f9g4_19;
        let mut h4 = f0g4+f1g3_2 +f2g2   +f3g1_2 +f4g0   +f5g9_38+f6g8_19+f7g7_38+f8g6_19+f9g5_38;
        let mut h5 = f0g5+f1g4   +f2g3   +f3g2   +f4g1   +f5g0   +f6g9_19+f7g8_19+f8g7_19+f9g6_19;
        let mut h6 = f0g6+f1g5_2 +f2g4   +f3g3_2 +f4g2   +f5g1_2 +f6g0   +f7g9_38+f8g8_19+f9g7_38;
        let mut h7 = f0g7+f1g6   +f2g5   +f3g4   +f4g3   +f5g2   +f6g1   +f7g0   +f8g9_19+f9g8_19;
        let mut h8 = f0g8+f1g7_2 +f2g6   +f3g5_2 +f4g4   +f5g3_2 +f6g2   +f7g1_2 +f8g0   +f9g9_38;
        let mut h9 = f0g9+f1g8   +f2g7   +f3g6   +f4g5   +f5g4   +f6g3   +f7g2   +f8g1   +f9g0   ;
        let mut carry0;
        let carry1;
        let carry2;
        let carry3;
        let mut carry4;
        let carry5;
        let carry6;
        let carry7;
        let carry8;
        let carry9;

        /*
        |h0| <= (1.1*1.1*2^52*(1+19+19+19+19)+1.1*1.1*2^50*(38+38+38+38+38))
          i.e. |h0| <= 1.2*2^59; narrower ranges for h2, h4, h6, h8
        |h1| <= (1.1*1.1*2^51*(1+1+19+19+19+19+19+19+19+19))
          i.e. |h1| <= 1.5*2^58; narrower ranges for h3, h5, h7, h9
        */

        carry0 = (h0 + (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
        carry4 = (h4 + (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
        /* |h0| <= 2^25 */
        /* |h4| <= 2^25 */
        /* |h1| <= 1.51*2^58 */
        /* |h5| <= 1.51*2^58 */

        carry1 = (h1 + (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
        carry5 = (h5 + (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
        /* |h1| <= 2^24; from now on fits into int32 */
        /* |h5| <= 2^24; from now on fits into int32 */
        /* |h2| <= 1.21*2^59 */
        /* |h6| <= 1.21*2^59 */

        carry2 = (h2 + (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
        carry6 = (h6 + (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
        /* |h2| <= 2^25; from now on fits into int32 unchanged */
        /* |h6| <= 2^25; from now on fits into int32 unchanged */
        /* |h3| <= 1.51*2^58 */
        /* |h7| <= 1.51*2^58 */

        carry3 = (h3 + (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
        carry7 = (h7 + (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
        /* |h3| <= 2^24; from now on fits into int32 unchanged */
        /* |h7| <= 2^24; from now on fits into int32 unchanged */
        /* |h4| <= 1.52*2^33 */
        /* |h8| <= 1.52*2^33 */

        carry4 = (h4 + (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
        carry8 = (h8 + (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
        /* |h4| <= 2^25; from now on fits into int32 unchanged */
        /* |h8| <= 2^25; from now on fits into int32 unchanged */
        /* |h5| <= 1.01*2^24 */
        /* |h9| <= 1.51*2^58 */

        carry9 = (h9 + (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
        /* |h9| <= 2^24; from now on fits into int32 unchanged */
        /* |h0| <= 1.8*2^37 */

        carry0 = (h0 + (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
        /* |h0| <= 2^25; from now on fits into int32 unchanged */
        /* |h1| <= 1.01*2^24 */

        Fe([h0 as i32, h1 as i32, h2 as i32, h3 as i32, h4 as i32,
            h5 as i32, h6 as i32, h7 as i32, h8 as i32, h9 as i32])
    }
}

impl Neg for &Fe {
    type Output = Fe;

    fn neg(self) -> Fe {
        let &Fe(f) = self;
        Fe([
            -f[0], -f[1], -f[2], -f[3], -f[4], -f[5], -f[6], -f[7], -f[8], -f[9],
        ])
    }
}

impl Fe {
    #[rustfmt::skip]
    pub fn from_bytes(s: &[u8; 32]) -> Fe {
        let mut h0 = load_4i(&s[0..4]);
        let mut h1 = load_3i(&s[4..7]) << 6;
        let mut h2 = load_3i(&s[7..10]) << 5;
        let mut h3 = load_3i(&s[10..13]) << 3;
        let mut h4 = load_3i(&s[13..16]) << 2;
        let mut h5 = load_4i(&s[16..20]);
        let mut h6 = load_3i(&s[20..23]) << 7;
        let mut h7 = load_3i(&s[23..26]) << 5;
        let mut h8 = load_3i(&s[26..29]) << 4;
        let mut h9 = (load_3i(&s[29..32]) & 8388607) << 2;

        let carry9 = (h9 + (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
        let carry1 = (h1 + (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
        let carry3 = (h3 + (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
        let carry5 = (h5 + (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
        let carry7 = (h7 + (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

        let carry0 = (h0 + (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
        let carry2 = (h2 + (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
        let carry4 = (h4 + (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
        let carry6 = (h6 + (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
        let carry8 = (h8 + (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

        Fe([h0 as i32, h1 as i32, h2 as i32, h3 as i32, h4 as i32,
            h5 as i32, h6 as i32, h7 as i32, h8 as i32, h9 as i32])
    }

    /*
    Preconditions:
      |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.

    Write p=2^255-19; q=floor(h/p).
    Basic claim: q = floor(2^(-255)(h + 19 2^(-25)h9 + 2^(-1))).

    Proof:
      Have |h|<=p so |q|<=1 so |19^2 2^(-255) q|<1/4.
      Also have |h-2^230 h9|<2^230 so |19 2^(-255)(h-2^230 h9)|<1/4.

      Write y=2^(-1)-19^2 2^(-255)q-19 2^(-255)(h-2^230 h9).
      Then 0<y<1.

      Write r=h-pq.
      Have 0<=r<=p-1=2^255-20.
      Thus 0<=r+19(2^-255)r<r+19(2^-255)2^255<=2^255-1.

      Write x=r+19(2^-255)r+y.
      Then 0<x<2^255 so floor(2^(-255)x) = 0 so floor(q+2^(-255)x) = q.

      Have q+2^(-255)x = 2^(-255)(h + 19 2^(-25) h9 + 2^(-1))
      so floor(2^(-255)(h + 19 2^(-25) h9 + 2^(-1))) = q.
    */

    #[rustfmt::skip]
    pub fn to_bytes(&self) -> [u8; 32] {
        let Fe([mut h0, mut h1, mut h2, mut h3, mut h4, mut h5, mut h6, mut h7, mut h8, mut h9]) = *self;
        let mut q;

        q = (19 * h9 + (1 << 24)) >> 25;
        q = (h0 + q) >> 26;
        q = (h1 + q) >> 25;
        q = (h2 + q) >> 26;
        q = (h3 + q) >> 25;
        q = (h4 + q) >> 26;
        q = (h5 + q) >> 25;
        q = (h6 + q) >> 26;
        q = (h7 + q) >> 25;
        q = (h8 + q) >> 26;
        q = (h9 + q) >> 25;

        /* Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20. */
        h0 += 19 * q;
        /* Goal: Output h-2^255 q, which is between 0 and 2^255-20. */

        let carry0 = h0 >> 26; h1 += carry0; h0 -= carry0 << 26;
        let carry1 = h1 >> 25; h2 += carry1; h1 -= carry1 << 25;
        let carry2 = h2 >> 26; h3 += carry2; h2 -= carry2 << 26;
        let carry3 = h3 >> 25; h4 += carry3; h3 -= carry3 << 25;
        let carry4 = h4 >> 26; h5 += carry4; h4 -= carry4 << 26;
        let carry5 = h5 >> 25; h6 += carry5; h5 -= carry5 << 25;
        let carry6 = h6 >> 26; h7 += carry6; h6 -= carry6 << 26;
        let carry7 = h7 >> 25; h8 += carry7; h7 -= carry7 << 25;
        let carry8 = h8 >> 26; h9 += carry8; h8 -= carry8 << 26;
        let carry9 = h9 >> 25;               h9 -= carry9 << 25;
                            /* h10 = carry9 */

        /*
        Goal: Output h0+...+2^255 h10-2^255 q, which is between 0 and 2^255-20.
        Have h0+...+2^230 h9 between 0 and 2^255-1;
        evidently 2^255 h10-2^255 q = 0.
        Goal: Output h0+...+2^230 h9.
        */
        [
            (h0 >> 0) as u8,
            (h0 >> 8) as u8,
            (h0 >> 16) as u8,
            ((h0 >> 24) | (h1 << 2)) as u8,
            (h1 >> 6) as u8,
            (h1 >> 14) as u8,
            ((h1 >> 22) | (h2 << 3)) as u8,
            (h2 >> 5) as u8,
            (h2 >> 13) as u8,
            ((h2 >> 21) | (h3 << 5)) as u8,
            (h3 >> 3) as u8,
            (h3 >> 11) as u8,
            ((h3 >> 19) | (h4 << 6)) as u8,
            (h4 >> 2) as u8,
            (h4 >> 10) as u8,
            (h4 >> 18) as u8,
            (h5 >> 0) as u8,
            (h5 >> 8) as u8,
            (h5 >> 16) as u8,
            ((h5 >> 24) | (h6 << 1)) as u8,
            (h6 >> 7) as u8,
            (h6 >> 15) as u8,
            ((h6 >> 23) | (h7 << 3)) as u8,
            (h7 >> 5) as u8,
            (h7 >> 13) as u8,
            ((h7 >> 21) | (h8 << 4)) as u8,
            (h8 >> 4) as u8,
            (h8 >> 12) as u8,
            ((h8 >> 20) | (h9 << 6)) as u8,
            (h9 >> 2) as u8,
            (h9 >> 10) as u8,
            (h9 >> 18) as u8,
        ]
    }

    pub(crate) fn maybe_swap_with(&mut self, rhs: &mut Fe, do_swap: Choice) {
        ct_array32_maybe_swap_with(&mut self.0, &mut rhs.0, do_swap);
    }

    pub(crate) fn maybe_set(&mut self, rhs: &Fe, do_swap: Choice) {
        ct_array32_maybe_set(&mut self.0, &rhs.0, do_swap);
    }

    /*
    h = f * S0
    Can overlap h with f.

    Preconditions:
       |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.

    Postconditions:
       |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
    */

    #[rustfmt::skip]
    pub const fn mul_small<const S0: u32>(&self) -> Fe {
        let &Fe(f) = self;

        let mut h0 = (f[0] as i64) * (S0 as i64);
        let mut h1 = (f[1] as i64) * (S0 as i64);
        let mut h2 = (f[2] as i64) * (S0 as i64);
        let mut h3 = (f[3] as i64) * (S0 as i64);
        let mut h4 = (f[4] as i64) * (S0 as i64);
        let mut h5 = (f[5] as i64) * (S0 as i64);
        let mut h6 = (f[6] as i64) * (S0 as i64);
        let mut h7 = (f[7] as i64) * (S0 as i64);
        let mut h8 = (f[8] as i64) * (S0 as i64);
        let mut h9 = (f[9] as i64) * (S0 as i64);

        let carry9 = (h9 + (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
        let carry1 = (h1 + (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
        let carry3 = (h3 + (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
        let carry5 = (h5 + (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
        let carry7 = (h7 + (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

        let carry0 = (h0 + (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
        let carry2 = (h2 + (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
        let carry4 = (h4 + (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
        let carry6 = (h6 + (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
        let carry8 = (h8 + (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

        Fe([h0 as i32, h1 as i32, h2 as i32, h3 as i32, h4 as i32,
            h5 as i32, h6 as i32, h7 as i32, h8 as i32, h9 as i32])
    }

    pub(crate) fn negate_mut(&mut self) {
        self.0[0] = -self.0[0];
        self.0[1] = -self.0[1];
        self.0[2] = -self.0[2];
        self.0[3] = -self.0[3];
        self.0[4] = -self.0[4];
        self.0[5] = -self.0[5];
        self.0[6] = -self.0[6];
        self.0[7] = -self.0[7];
        self.0[8] = -self.0[8];
        self.0[9] = -self.0[9];
    }

    /*
    h = f * f
    Can overlap h with f.

    Preconditions:
       |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.

    Postconditions:
       |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
    */

    /*
    See fe_mul.c for discussion of implementation strategy.
    */
    #[rustfmt::skip]
    pub fn square(&self) -> Fe {
        let Fe([f0, f1, f2, f3, f4, f5, f6, f7, f8, f9]) = *self;

        let f0_2 = 2 * f0;
        let f1_2 = 2 * f1;
        let f2_2 = 2 * f2;
        let f3_2 = 2 * f3;
        let f4_2 = 2 * f4;
        let f5_2 = 2 * f5;
        let f6_2 = 2 * f6;
        let f7_2 = 2 * f7;
        let f5_38 = 38 * f5; /* 1.31*2^30 */
        let f6_19 = 19 * f6; /* 1.31*2^30 */
        let f7_38 = 38 * f7; /* 1.31*2^30 */
        let f8_19 = 19 * f8; /* 1.31*2^30 */
        let f9_38 = 38 * f9; /* 1.31*2^30 */
        let f0f0    = emul(f0  , f0);
        let f0f1_2  = emul(f0_2, f1);
        let f0f2_2  = emul(f0_2, f2);
        let f0f3_2  = emul(f0_2, f3);
        let f0f4_2  = emul(f0_2, f4);
        let f0f5_2  = emul(f0_2, f5);
        let f0f6_2  = emul(f0_2, f6);
        let f0f7_2  = emul(f0_2, f7);
        let f0f8_2  = emul(f0_2, f8);
        let f0f9_2  = emul(f0_2, f9);
        let f1f1_2  = emul(f1_2, f1);
        let f1f2_2  = emul(f1_2, f2);
        let f1f3_4  = emul(f1_2, f3_2);
        let f1f4_2  = emul(f1_2, f4);
        let f1f5_4  = emul(f1_2, f5_2);
        let f1f6_2  = emul(f1_2, f6);
        let f1f7_4  = emul(f1_2, f7_2);
        let f1f8_2  = emul(f1_2, f8);
        let f1f9_76 = emul(f1_2, f9_38);
        let f2f2    = emul(f2  , f2);
        let f2f3_2  = emul(f2_2, f3);
        let f2f4_2  = emul(f2_2, f4);
        let f2f5_2  = emul(f2_2, f5);
        let f2f6_2  = emul(f2_2, f6);
        let f2f7_2  = emul(f2_2, f7);
        let f2f8_38 = emul(f2_2, f8_19);
        let f2f9_38 = emul(f2  , f9_38);
        let f3f3_2  = emul(f3_2, f3);
        let f3f4_2  = emul(f3_2, f4);
        let f3f5_4  = emul(f3_2, f5_2);
        let f3f6_2  = emul(f3_2, f6);
        let f3f7_76 = emul(f3_2, f7_38);
        let f3f8_38 = emul(f3_2, f8_19);
        let f3f9_76 = emul(f3_2, f9_38);
        let f4f4    = emul(f4  , f4);
        let f4f5_2  = emul(f4_2, f5);
        let f4f6_38 = emul(f4_2, f6_19);
        let f4f7_38 = emul(f4  , f7_38);
        let f4f8_38 = emul(f4_2, f8_19);
        let f4f9_38 = emul(f4  , f9_38);
        let f5f5_38 = emul(f5  , f5_38);
        let f5f6_38 = emul(f5_2, f6_19);
        let f5f7_76 = emul(f5_2, f7_38);
        let f5f8_38 = emul(f5_2, f8_19);
        let f5f9_76 = emul(f5_2, f9_38);
        let f6f6_19 = emul(f6  , f6_19);
        let f6f7_38 = emul(f6  , f7_38);
        let f6f8_38 = emul(f6_2, f8_19);
        let f6f9_38 = emul(f6  , f9_38);
        let f7f7_38 = emul(f7  , f7_38);
        let f7f8_38 = emul(f7_2, f8_19);
        let f7f9_76 = emul(f7_2, f9_38);
        let f8f8_19 = emul(f8  , f8_19);
        let f8f9_38 = emul(f8  , f9_38);
        let f9f9_38 = emul(f9  , f9_38);
        let mut h0 = f0f0  +f1f9_76+f2f8_38+f3f7_76+f4f6_38+f5f5_38;
        let mut h1 = f0f1_2+f2f9_38+f3f8_38+f4f7_38+f5f6_38;
        let mut h2 = f0f2_2+f1f1_2 +f3f9_76+f4f8_38+f5f7_76+f6f6_19;
        let mut h3 = f0f3_2+f1f2_2 +f4f9_38+f5f8_38+f6f7_38;
        let mut h4 = f0f4_2+f1f3_4 +f2f2   +f5f9_76+f6f8_38+f7f7_38;
        let mut h5 = f0f5_2+f1f4_2 +f2f3_2 +f6f9_38+f7f8_38;
        let mut h6 = f0f6_2+f1f5_4 +f2f4_2 +f3f3_2 +f7f9_76+f8f8_19;
        let mut h7 = f0f7_2+f1f6_2 +f2f5_2 +f3f4_2 +f8f9_38;
        let mut h8 = f0f8_2+f1f7_4 +f2f6_2 +f3f5_4 +f4f4   +f9f9_38;
        let mut h9 = f0f9_2+f1f8_2 +f2f7_2 +f3f6_2 +f4f5_2;

        let carry0 = (h0 + (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
        let carry4 = (h4 + (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;

        let carry1 = (h1 + (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
        let carry5 = (h5 + (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;

        let carry2 = (h2 + (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
        let carry6 = (h6 + (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;

        let carry3 = (h3 + (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
        let carry7 = (h7 + (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

        let carry4 = (h4 + (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
        let carry8 = (h8 + (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

        let carry9 = (h9 + (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;

        let carrya = (h0 + (1<<25)) >> 26; h1 += carrya; h0 -= carrya << 26;

        Fe([h0 as i32, h1 as i32, h2 as i32, h3 as i32, h4 as i32,
            h5 as i32, h6 as i32, h7 as i32, h8 as i32, h9 as i32])
    }

    pub fn square_repeatdly(&self, n: usize) -> Fe {
        let mut acc = self.square();
        for _ in 1..n {
            acc = acc.square();
        }
        acc
    }


    #[rustfmt::skip]
    pub fn square_and_double(&self) -> Fe {
        let Fe([f0, f1, f2, f3, f4, f5, f6, f7, f8, f9]) = *self;

        let f0_2 = 2 * f0;
        let f1_2 = 2 * f1;
        let f2_2 = 2 * f2;
        let f3_2 = 2 * f3;
        let f4_2 = 2 * f4;
        let f5_2 = 2 * f5;
        let f6_2 = 2 * f6;
        let f7_2 = 2 * f7;
        let f5_38 = 38 * f5; /* 1.959375*2^30 */
        let f6_19 = 19 * f6; /* 1.959375*2^30 */
        let f7_38 = 38 * f7; /* 1.959375*2^30 */
        let f8_19 = 19 * f8; /* 1.959375*2^30 */
        let f9_38 = 38 * f9; /* 1.959375*2^30 */
        let f0f0    = emul(f0   , f0);
        let f0f1_2  = emul(f0_2 , f1);
        let f0f2_2  = emul(f0_2 , f2);
        let f0f3_2  = emul(f0_2 , f3);
        let f0f4_2  = emul(f0_2 , f4);
        let f0f5_2  = emul(f0_2 , f5);
        let f0f6_2  = emul(f0_2 , f6);
        let f0f7_2  = emul(f0_2 , f7);
        let f0f8_2  = emul(f0_2 , f8);
        let f0f9_2  = emul(f0_2 , f9);
        let f1f1_2  = emul(f1_2 , f1);
        let f1f2_2  = emul(f1_2 , f2);
        let f1f3_4  = emul(f1_2 , f3_2);
        let f1f4_2  = emul(f1_2 , f4);
        let f1f5_4  = emul(f1_2 , f5_2);
        let f1f6_2  = emul(f1_2 , f6);
        let f1f7_4  = emul(f1_2 , f7_2);
        let f1f8_2  = emul(f1_2 , f8);
        let f1f9_76 = emul(f1_2 , f9_38);
        let f2f2    = emul(f2   , f2);
        let f2f3_2  = emul(f2_2 , f3);
        let f2f4_2  = emul(f2_2 , f4);
        let f2f5_2  = emul(f2_2 , f5);
        let f2f6_2  = emul(f2_2 , f6);
        let f2f7_2  = emul(f2_2 , f7);
        let f2f8_38 = emul(f2_2 , f8_19);
        let f2f9_38 = emul(f2   , f9_38);
        let f3f3_2  = emul(f3_2 , f3);
        let f3f4_2  = emul(f3_2 , f4);
        let f3f5_4  = emul(f3_2 , f5_2);
        let f3f6_2  = emul(f3_2 , f6);
        let f3f7_76 = emul(f3_2 , f7_38);
        let f3f8_38 = emul(f3_2 , f8_19);
        let f3f9_76 = emul(f3_2 , f9_38);
        let f4f4    = emul(f4   , f4);
        let f4f5_2  = emul(f4_2 , f5);
        let f4f6_38 = emul(f4_2 , f6_19);
        let f4f7_38 = emul(f4   , f7_38);
        let f4f8_38 = emul(f4_2 , f8_19);
        let f4f9_38 = emul(f4   , f9_38);
        let f5f5_38 = emul(f5   , f5_38);
        let f5f6_38 = emul(f5_2 , f6_19);
        let f5f7_76 = emul(f5_2 , f7_38);
        let f5f8_38 = emul(f5_2 , f8_19);
        let f5f9_76 = emul(f5_2 , f9_38);
        let f6f6_19 = emul(f6   , f6_19);
        let f6f7_38 = emul(f6   , f7_38);
        let f6f8_38 = emul(f6_2 , f8_19);
        let f6f9_38 = emul(f6   , f9_38);
        let f7f7_38 = emul(f7   , f7_38);
        let f7f8_38 = emul(f7_2 , f8_19);
        let f7f9_76 = emul(f7_2 , f9_38);
        let f8f8_19 = emul(f8   , f8_19);
        let f8f9_38 = emul(f8   , f9_38);
        let f9f9_38 = emul(f9   , f9_38);
        let mut h0 = f0f0  +f1f9_76+f2f8_38+f3f7_76+f4f6_38+f5f5_38;
        let mut h1 = f0f1_2+f2f9_38+f3f8_38+f4f7_38+f5f6_38;
        let mut h2 = f0f2_2+f1f1_2 +f3f9_76+f4f8_38+f5f7_76+f6f6_19;
        let mut h3 = f0f3_2+f1f2_2 +f4f9_38+f5f8_38+f6f7_38;
        let mut h4 = f0f4_2+f1f3_4 +f2f2   +f5f9_76+f6f8_38+f7f7_38;
        let mut h5 = f0f5_2+f1f4_2 +f2f3_2 +f6f9_38+f7f8_38;
        let mut h6 = f0f6_2+f1f5_4 +f2f4_2 +f3f3_2 +f7f9_76+f8f8_19;
        let mut h7 = f0f7_2+f1f6_2 +f2f5_2 +f3f4_2 +f8f9_38;
        let mut h8 = f0f8_2+f1f7_4 +f2f6_2 +f3f5_4 +f4f4   +f9f9_38;
        let mut h9 = f0f9_2+f1f8_2 +f2f7_2 +f3f6_2 +f4f5_2;
        let mut carry0: i64;
        let carry1: i64;
        let carry2: i64;
        let carry3: i64;
        let mut carry4: i64;
        let carry5: i64;
        let carry6: i64;
        let carry7: i64;
        let carry8: i64;
        let carry9: i64;

        h0 += h0;
        h1 += h1;
        h2 += h2;
        h3 += h3;
        h4 += h4;
        h5 += h5;
        h6 += h6;
        h7 += h7;
        h8 += h8;
        h9 += h9;

        carry0 = (h0 + (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
        carry4 = (h4 + (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;

        carry1 = (h1 + (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
        carry5 = (h5 + (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;

        carry2 = (h2 + (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
        carry6 = (h6 + (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;

        carry3 = (h3 + (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
        carry7 = (h7 + (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

        carry4 = (h4 + (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
        carry8 = (h8 + (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

        carry9 = (h9 + (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;

        carry0 = (h0 + (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;

        Fe([h0 as i32, h1 as i32, h2 as i32, h3 as i32, h4 as i32,
            h5 as i32, h6 as i32, h7 as i32, h8 as i32, h9 as i32])
    }

    pub fn is_nonzero(&self) -> bool {
        CtEqual::ct_ne(&self.to_bytes(), &[0; 32]).into()
    }

    pub fn is_negative(&self) -> bool {
        (self.to_bytes()[0] & 1) != 0
    }
}
