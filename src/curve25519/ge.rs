use core::cmp::Ordering;
use core::ops::{Add, Neg, Sub};

use super::fe::{precomp, Fe};
use super::scalar::Scalar;
use crate::constant_time::{Choice, CtEqual, CtZero};

/// Curve Group Element (Point)
///
/// The group element is using the extended homogeneous coordinates
/// using (x,y,z,t) which maps to coordinates using the following
/// equations:
///    X     = x/z
///    Y     = y/z
///    X * Y = t/z
#[derive(Clone)]
pub struct Ge {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// Curve Group element without t=X*Y
#[derive(Clone)]
pub struct GePartial {
    x: Fe,
    y: Fe,
    z: Fe,
}

#[derive(Clone)]
pub struct GeP1P1 {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

#[derive(Clone)]
pub struct GePrecomp {
    pub(crate) y_plus_x: Fe,
    pub(crate) y_minus_x: Fe,
    pub(crate) xy2d: Fe,
}

#[derive(Clone)]
struct GeAffine {
    x: Fe,
    y: Fe,
}

#[derive(Clone)]
pub struct GeCached {
    y_plus_x: Fe,
    y_minus_x: Fe,
    z: Fe,
    t2d: Fe,
}

impl GeAffine {
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bs = self.y.to_bytes();
        bs[31] ^= (if self.x.is_negative() { 1 } else { 0 }) << 7;
        bs
    }

    pub fn from_bytes(s: &[u8; 32]) -> Option<Self> {
        // See RFC8032 5.3.1 decoding process
        //
        // y (255 bits) | sign(x) (1 bit) = s
        // let u = y^2 - 1
        //     v = d * y^2 + 1
        //     x = u * v^3 * (u * v^7)^((p-5)/8)

        // recover y by clearing the highest bit (side effect of from_bytes)
        let y = Fe::from_bytes(s);

        // recover x
        let y2 = y.square();
        let u = &y2 - &Fe::ONE;
        let v = &(&y2 * &Fe::D) + &Fe::ONE;
        let v3 = &v.square() * &v;
        let v7 = &v3.square() * &v;
        let uv7 = &v7 * &u;

        let mut x = &(&uv7.pow25523() * &v3) * &u;

        let vxx = &x.square() * &v;
        let check = &vxx - &u;
        if check.is_nonzero() {
            let check2 = &vxx + &u;
            if check2.is_nonzero() {
                return None;
            }
            x = &x * &Fe::SQRTM1;
        }

        if x.is_negative() == ((s[31] >> 7) != 0) {
            x.negate_mut();
        }
        Some(Self { x, y })
    }
}

impl GeP1P1 {
    pub fn to_partial(&self) -> GePartial {
        GePartial {
            x: &self.x * &self.t,
            y: &self.y * &self.z,
            z: &self.z * &self.t,
        }
    }

    pub fn to_full(&self) -> Ge {
        Ge {
            x: &self.x * &self.t,
            y: &self.y * &self.z,
            z: &self.z * &self.t,
            t: &self.x * &self.y,
        }
    }
}

impl GePartial {
    pub const ZERO: Self = Self {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
    };

    pub fn to_bytes(&self) -> [u8; 32] {
        let recip = self.z.invert();
        let x = &self.x * &recip;
        let y = &self.y * &recip;
        let mut bs = y.to_bytes();
        bs[31] ^= (if x.is_negative() { 1 } else { 0 }) << 7;
        bs
    }

    pub fn double_p1p1(&self) -> GeP1P1 {
        let xx = self.x.square();
        let yy = self.y.square();
        let b = self.z.square_and_double();
        let a = &self.x + &self.y;
        let aa = a.square();
        let y3 = &yy + &xx;
        let z3 = &yy - &xx;
        let x3 = &aa - &y3;
        let t3 = &b - &z3;

        GeP1P1 {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }

    pub fn double(&self) -> Self {
        self.double_p1p1().to_partial()
    }

    pub fn double_full(&self) -> Ge {
        self.double_p1p1().to_full()
    }

    /// Calculate r = a * A + b * B
    ///
    /// ```ignore
    /// double_scalarmult_vartime(a, A, b) = a * A + b * B
    /// ```
    ///
    /// where
    ///     a is a scalar
    ///     A is an arbitrary point
    ///     b is a scalar
    ///     B the ED25519 base point (not a parameter to the function)
    ///
    /// Note that the
    ///
    pub fn double_scalarmult_vartime(
        a_scalar: &Scalar,
        a_point: Ge,
        b_scalar: &Scalar,
    ) -> GePartial {
        let aslide = a_scalar.slide();
        let bslide = b_scalar.slide();

        let a1 = a_point.to_cached();
        let a2 = a_point.double_p1p1().to_full();
        let a3 = (&a2 + &a1).to_full().to_cached();
        let a5 = (&a2 + &a3).to_full().to_cached();
        let a7 = (&a2 + &a5).to_full().to_cached();
        let a9 = (&a2 + &a7).to_full().to_cached();
        let a11 = (&a2 + &a9).to_full().to_cached();
        let a13 = (&a2 + &a11).to_full().to_cached();
        let a15 = (&a2 + &a13).to_full().to_cached();

        let ai: [GeCached; 8] = [a1, a3, a5, a7, a9, a11, a13, a15];

        let mut r = GePartial::ZERO;

        let mut i: usize = 255;
        loop {
            if aslide[i] != 0 || bslide[i] != 0 {
                break;
            }
            if i == 0 {
                return r;
            }
            i -= 1;
        }

        loop {
            let mut t = r.double_p1p1();
            match aslide[i].cmp(&0) {
                Ordering::Greater => t = &t.to_full() + &ai[(aslide[i] / 2) as usize],
                Ordering::Less => t = &t.to_full() - &ai[(-aslide[i] / 2) as usize],
                Ordering::Equal => {}
            }

            match bslide[i].cmp(&0) {
                Ordering::Greater => t = &t.to_full() + &precomp::BI[(bslide[i] / 2) as usize],
                Ordering::Less => t = &t.to_full() - &precomp::BI[(-bslide[i] / 2) as usize],
                Ordering::Equal => {}
            }

            r = t.to_partial();

            if i == 0 {
                return r;
            }
            i -= 1;
        }
    }
}

impl Ge {
    /// The Identity Element for the group, which represent (X=0, Y=1) and is (x=0, y=1, z=1, t=0*1)
    pub const ZERO: Ge = Ge {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// Create a group element from affine coordinate
    #[inline]
    fn from_affine(affine: GeAffine) -> Ge {
        let t = &affine.x * &affine.y;
        Ge {
            x: affine.x,
            y: affine.y,
            z: Fe::ONE,
            t: t,
        }
    }

    /// Flatten a group element on the affine plane (x,y)
    #[inline]
    fn to_affine(&self) -> GeAffine {
        let recip = self.z.invert();
        let x = &self.x * &recip;
        let y = &self.y * &recip;
        GeAffine { x, y }
    }

    /// Try to construct a group element (Point on the curve)
    /// from its compressed byte representation (32 bytes little endian).
    ///
    /// The compressed bytes representation is the y coordinate (255 bits)
    /// and the sign of the x coordinate (1 bit) as the highest bit.
    pub fn from_bytes(s: &[u8; 32]) -> Option<Ge> {
        GeAffine::from_bytes(s).map(Self::from_affine)
    }

    /// Drop the t coordinate to become a `GePartial`
    pub fn to_partial(self) -> GePartial {
        GePartial {
            x: self.x,
            y: self.y,
            z: self.z,
        }
    }

    pub fn to_cached(&self) -> GeCached {
        GeCached {
            y_plus_x: &self.y + &self.x,
            y_minus_x: &self.y - &self.x,
            z: self.z.clone(),
            t2d: &self.t * &Fe::D2,
        }
    }

    pub fn double_p1p1(&self) -> GeP1P1 {
        let xx = self.x.square();
        let yy = self.y.square();
        let b = self.z.square_and_double();
        let a = &self.x + &self.y;
        let aa = a.square();
        let y3 = &yy + &xx;
        let z3 = &yy - &xx;
        let x3 = &aa - &y3;
        let t3 = &b - &z3;

        GeP1P1 {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }

    /// Double the point
    pub fn double(&self) -> Ge {
        self.double_p1p1().to_full()
    }

    pub fn double_partial(&self) -> GePartial {
        self.double_p1p1().to_partial()
    }

    /// Transform a point into the compressed byte representation
    ///
    /// the compressed bytes representation is the Y coordinate
    /// followed by the 1 bit sign of X coordinate
    pub fn to_bytes(&self) -> [u8; 32] {
        self.to_affine().to_bytes()
    }

    /// Compute `r = a * B`
    ///
    /// where
    ///     `a = a[0]+2^8*a[1]+...+2^248*a[31]` a scalar number represented by 32-bytes in little endian format
    ///         and `a[31] <= 0x80`
    ///     `B` the ED25519 base point (not a parameter to the function)
    pub fn scalarmult_base(a: &Scalar) -> Ge {
        let mut r: GeP1P1;
        let mut t: GePrecomp;

        /* each es[i] is between 0 and 0xf */
        /* es[63] is between 0 and 7 */
        let mut es = a.nibbles();

        let mut carry: i8 = 0;
        for esi in es[0..63].iter_mut() {
            *esi += carry;
            carry = *esi + 8;
            carry >>= 4;
            *esi -= carry << 4;
        }
        es[63] += carry;
        /* each es[i] is between -8 and 8 */

        let mut h = Ge::ZERO;
        for j in 0..32 {
            let i = j * 2 + 1;
            t = GePrecomp::select(j, es[i]);
            r = &h + &t;
            h = r.to_full();
        }

        h = h.double_partial().double().double().double_full();

        for j in 0..32 {
            let i = j * 2;
            t = GePrecomp::select(j, es[i]);
            r = &h + &t;
            h = r.to_full();
        }

        h
    }
}

impl Add<&GeCached> for &Ge {
    type Output = GeP1P1;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, _rhs: &GeCached) -> GeP1P1 {
        let y1_plus_x1 = &self.y + &self.x;
        let y1_minus_x1 = &self.y - &self.x;
        let a = &y1_plus_x1 * &_rhs.y_plus_x;
        let b = &y1_minus_x1 * &_rhs.y_minus_x;
        let c = &_rhs.t2d * &self.t;
        let zz = &self.z * &_rhs.z;
        let d = &zz + &zz;
        let x3 = &a - &b;
        let y3 = &a + &b;
        let z3 = &d + &c;
        let t3 = &d - &c;

        GeP1P1 {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }
}

impl Add<&GePrecomp> for &Ge {
    type Output = GeP1P1;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, _rhs: &GePrecomp) -> GeP1P1 {
        let y1_plus_x1 = &self.y + &self.x;
        let y1_minus_x1 = &self.y - &self.x;
        let a = &y1_plus_x1 * &_rhs.y_plus_x;
        let b = &y1_minus_x1 * &_rhs.y_minus_x;
        let c = &_rhs.xy2d * &self.t;
        let d = &self.z + &self.z;
        let x3 = &a - &b;
        let y3 = &a + &b;
        let z3 = &d + &c;
        let t3 = &d - &c;

        GeP1P1 {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }
}

impl Sub<GeCached> for Ge {
    type Output = GeP1P1;

    fn sub(self, rhs: GeCached) -> GeP1P1 {
        &self - &rhs
    }
}

impl Sub<&GeCached> for &Ge {
    type Output = GeP1P1;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, _rhs: &GeCached) -> GeP1P1 {
        let y1_plus_x1 = &self.y + &self.x;
        let y1_minus_x1 = &self.y - &self.x;
        let a = &y1_plus_x1 * &_rhs.y_minus_x;
        let b = &y1_minus_x1 * &_rhs.y_plus_x;
        let c = &_rhs.t2d * &self.t;
        let zz = &self.z * &_rhs.z;
        let d = &zz + &zz;
        let x3 = &a - &b;
        let y3 = &a + &b;
        let z3 = &d - &c;
        let t3 = &d + &c;

        GeP1P1 {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }
}

impl Sub<GePrecomp> for Ge {
    type Output = GeP1P1;

    fn sub(self, rhs: GePrecomp) -> GeP1P1 {
        &self - &rhs
    }
}

impl Sub<&GePrecomp> for &Ge {
    type Output = GeP1P1;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, _rhs: &GePrecomp) -> GeP1P1 {
        let y1_plus_x1 = &self.y + &self.x;
        let y1_minus_x1 = &self.y - &self.x;
        let a = &y1_plus_x1 * &_rhs.y_minus_x;
        let b = &y1_minus_x1 * &_rhs.y_plus_x;
        let c = &_rhs.xy2d * &self.t;
        let d = &self.z + &self.z;
        let x3 = &a - &b;
        let y3 = &a + &b;
        let z3 = &d - &c;
        let t3 = &d + &c;

        GeP1P1 {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }
}

impl GePrecomp {
    pub const ZERO: Self = Self {
        y_plus_x: Fe::ONE,
        y_minus_x: Fe::ONE,
        xy2d: Fe::ZERO,
    };

    pub(crate) fn maybe_set(&mut self, other: &GePrecomp, do_swap: Choice) {
        self.y_plus_x.maybe_set(&other.y_plus_x, do_swap);
        self.y_minus_x.maybe_set(&other.y_minus_x, do_swap);
        self.xy2d.maybe_set(&other.xy2d, do_swap);
    }

    pub(crate) fn select(pos: usize, b: i8) -> GePrecomp {
        debug_assert!(b >= -8 && b <= 8);

        let bnegative = (b as u8) >> 7;
        let babs: u8 = (b - (((-(bnegative as i8)) & b) << 1)) as u8;
        let mut t = GePrecomp::ZERO;
        t.maybe_set(&precomp::GE_BASE[pos][0], babs.ct_eq(1));
        t.maybe_set(&precomp::GE_BASE[pos][1], babs.ct_eq(2));
        t.maybe_set(&precomp::GE_BASE[pos][2], babs.ct_eq(3));
        t.maybe_set(&precomp::GE_BASE[pos][3], babs.ct_eq(4));
        t.maybe_set(&precomp::GE_BASE[pos][4], babs.ct_eq(5));
        t.maybe_set(&precomp::GE_BASE[pos][5], babs.ct_eq(6));
        t.maybe_set(&precomp::GE_BASE[pos][6], babs.ct_eq(7));
        t.maybe_set(&precomp::GE_BASE[pos][7], babs.ct_eq(8));
        let minus_t = GePrecomp {
            y_plus_x: t.y_minus_x.clone(),
            y_minus_x: t.y_plus_x.clone(),
            xy2d: t.xy2d.neg(),
        };
        t.maybe_set(&minus_t, bnegative.ct_nonzero());
        t
    }
}
