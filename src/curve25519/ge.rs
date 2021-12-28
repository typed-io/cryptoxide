use core::cmp::{min, Ordering};
use core::ops::{Add, Neg, Sub};

use super::fe::{precomp, Fe};

#[derive(Clone)]
pub struct GeP2 {
    x: Fe,
    y: Fe,
    z: Fe,
}

#[derive(Clone)]
pub struct GeP3 {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
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
pub struct GeCached {
    y_plus_x: Fe,
    y_minus_x: Fe,
    z: Fe,
    t2d: Fe,
}

impl GeP1P1 {
    pub(crate) fn to_p2(&self) -> GeP2 {
        GeP2 {
            x: &self.x * &self.t,
            y: &self.y * &self.z,
            z: &self.z * &self.t,
        }
    }

    pub(crate) fn to_p3(&self) -> GeP3 {
        GeP3 {
            x: &self.x * &self.t,
            y: &self.y * &self.z,
            z: &self.z * &self.t,
            t: &self.x * &self.y,
        }
    }
}

impl GeP2 {
    pub const ZERO: GeP2 = GeP2 {
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

    pub fn dbl(&self) -> GeP1P1 {
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

    #[allow(clippy::needless_range_loop)]
    fn slide(a: &[u8]) -> [i8; 256] {
        let mut r = [0i8; 256];
        for i in 0..256 {
            r[i] = (1 & (a[i >> 3] >> (i & 7))) as i8;
        }
        for i in 0..256 {
            if r[i] != 0 {
                for b in 1..min(7, 256 - i) {
                    if r[i + b] != 0 {
                        if r[i] + (r[i + b] << b) <= 15 {
                            r[i] += r[i + b] << b;
                            r[i + b] = 0;
                        } else if r[i] - (r[i + b] << b) >= -15 {
                            r[i] -= r[i + b] << b;
                            for k in i + b..256 {
                                if r[k] == 0 {
                                    r[k] = 1;
                                    break;
                                }
                                r[k] = 0;
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        }

        r
    }

    /*
    r = a * A + b * B
    where a = a[0]+256*a[1]+...+256^31 a[31].
    and b = b[0]+256*b[1]+...+256^31 b[31].
    B is the Ed25519 base point (x,4/5) with x positive.
    */
    pub fn double_scalarmult_vartime(a_scalar: &[u8], a_point: GeP3, b_scalar: &[u8]) -> GeP2 {
        let aslide = GeP2::slide(a_scalar);
        let bslide = GeP2::slide(b_scalar);

        let a1 = a_point.to_cached();
        let a2 = a_point.dbl().to_p3();
        let a3 = (&a2 + &a1).to_p3().to_cached();
        let a5 = (&a2 + &a3).to_p3().to_cached();
        let a7 = (&a2 + &a5).to_p3().to_cached();
        let a9 = (&a2 + &a7).to_p3().to_cached();
        let a11 = (&a2 + &a9).to_p3().to_cached();
        let a13 = (&a2 + &a11).to_p3().to_cached();
        let a15 = (&a2 + &a13).to_p3().to_cached();

        let ai: [GeCached; 8] = [a1, a3, a5, a7, a9, a11, a13, a15];

        let mut r = GeP2::ZERO;

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
            let mut t = r.dbl();
            match aslide[i].cmp(&0) {
                Ordering::Greater => t = &t.to_p3() + &ai[(aslide[i] / 2) as usize],
                Ordering::Less => t = &t.to_p3() - &ai[(-aslide[i] / 2) as usize],
                Ordering::Equal => {}
            }

            match bslide[i].cmp(&0) {
                Ordering::Greater => t = &t.to_p3() + &precomp::BI[(bslide[i] / 2) as usize],
                Ordering::Less => t = &t.to_p3() - &precomp::BI[(-bslide[i] / 2) as usize],
                Ordering::Equal => {}
            }

            r = t.to_p2();

            if i == 0 {
                return r;
            }
            i -= 1;
        }
    }
}

impl GeP3 {
    pub fn from_bytes_negate_vartime(s: &[u8; 32]) -> Option<GeP3> {
        let y = Fe::from_bytes(s);
        let z = Fe::ONE;
        let y_squared = y.square();
        let u = &y_squared - &Fe::ONE;
        let v = &(&y_squared * &Fe::D) + &Fe::ONE;
        let v_raise_3 = &v.square() * &v;
        let v_raise_7 = &v_raise_3.square() * &v;
        let uv7 = &v_raise_7 * &u; // Is this commutative? u comes second in the code, but not in the notation...

        let mut x = &(&uv7.pow25523() * &v_raise_3) * &u;

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
            x = x.neg();
        }

        let t = &x * &y;

        Some(GeP3 {
            x: x,
            y: y,
            z: z,
            t: t,
        })
    }

    pub fn to_p2(&self) -> GeP2 {
        GeP2 {
            x: self.x.clone(),
            y: self.y.clone(),
            z: self.z.clone(),
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

    pub const ZERO: GeP3 = GeP3 {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    pub fn dbl(&self) -> GeP1P1 {
        self.to_p2().dbl()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let recip = self.z.invert();
        let x = &self.x * &recip;
        let y = &self.y * &recip;
        let mut bs = y.to_bytes();
        bs[31] ^= (if x.is_negative() { 1 } else { 0 }) << 7;
        bs
    }
}

impl Add<GeCached> for GeP3 {
    type Output = GeP1P1;
    fn add(self, rhs: GeCached) -> GeP1P1 {
        &self + &rhs
    }
}

impl Add<&GeCached> for &GeP3 {
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

impl Add<GePrecomp> for GeP3 {
    type Output = GeP1P1;

    fn add(self, rhs: GePrecomp) -> GeP1P1 {
        &self + &rhs
    }
}

impl Add<&GePrecomp> for &GeP3 {
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

impl Sub<GeCached> for GeP3 {
    type Output = GeP1P1;

    fn sub(self, rhs: GeCached) -> GeP1P1 {
        &self - &rhs
    }
}

impl Sub<&GeCached> for &GeP3 {
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

impl Sub<GePrecomp> for GeP3 {
    type Output = GeP1P1;

    fn sub(self, rhs: GePrecomp) -> GeP1P1 {
        &self - &rhs
    }
}

impl Sub<&GePrecomp> for &GeP3 {
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

fn equal(b: u8, c: u8) -> i32 {
    let x = b ^ c; /* 0: yes; 1..255: no */
    let mut y = x as u32; /* 0: yes; 1..255: no */
    y = y.wrapping_sub(1); /* 4294967295: yes; 0..254: no */
    y >>= 31; /* 1: yes; 0: no */
    y as i32
}

impl GePrecomp {
    fn zero() -> GePrecomp {
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ZERO,
        }
    }

    pub(crate) fn maybe_set(&mut self, other: &GePrecomp, do_swap: i32) {
        self.y_plus_x.maybe_set(&other.y_plus_x, do_swap);
        self.y_minus_x.maybe_set(&other.y_minus_x, do_swap);
        self.xy2d.maybe_set(&other.xy2d, do_swap);
    }

    pub(crate) fn select(pos: usize, b: i8) -> GePrecomp {
        let bnegative = (b as u8) >> 7;
        let babs: u8 = (b - (((-(bnegative as i8)) & b) << 1)) as u8;
        let mut t = GePrecomp::zero();
        t.maybe_set(&precomp::GE_BASE[pos][0], equal(babs, 1));
        t.maybe_set(&precomp::GE_BASE[pos][1], equal(babs, 2));
        t.maybe_set(&precomp::GE_BASE[pos][2], equal(babs, 3));
        t.maybe_set(&precomp::GE_BASE[pos][3], equal(babs, 4));
        t.maybe_set(&precomp::GE_BASE[pos][4], equal(babs, 5));
        t.maybe_set(&precomp::GE_BASE[pos][5], equal(babs, 6));
        t.maybe_set(&precomp::GE_BASE[pos][6], equal(babs, 7));
        t.maybe_set(&precomp::GE_BASE[pos][7], equal(babs, 8));
        let minus_t = GePrecomp {
            y_plus_x: t.y_minus_x.clone(),
            y_minus_x: t.y_plus_x.clone(),
            xy2d: t.xy2d.neg(),
        };
        t.maybe_set(&minus_t, bnegative as i32);
        t
    }
}
