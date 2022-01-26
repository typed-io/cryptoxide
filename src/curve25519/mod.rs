//! Curve25519 elliptic curve diffie hellman (X25519)
//!
//! Curve25519 elliptic curve from [Specification][1], and extra information also on [Wikipedia][2]
//!
//! # Example
//!
//! Creating a curve25519 point from a secret:
//!
//! ```
//! use cryptoxide::curve25519::curve25519_base;
//!
//! let secret : [u8;32] = [0,1,2,3,4,5,6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
//! let public = curve25519_base(&secret);
//! ```
//!
//! Doing a ECDH on curve25519 using a curve point 'other_point' and a specific secret:
//!
//! ```
//! use cryptoxide::curve25519::{curve25519_base, curve25519};
//!
//! # let other_point = curve25519_base(&[3u8; 32]);
//! let secret : [u8;32] = [0,1,2,3,4,5,6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
//! let public = curve25519(&secret, &other_point);
//! ```
//!
//! [1]: <https://cr.yp.to/ecdh/curve25519-20060209.pdf>
//! [2]: <https://en.wikipedia.org/wiki/Curve25519>

mod fe;
mod ge;
pub mod scalar;

pub use fe::Fe;
pub use ge::{Ge, GeCached, GeP1P1, GePartial, GePrecomp};
pub use scalar::Scalar;

use crate::constant_time::CtZero;

/// Computes a shared secret from the curve25519 private key (n) and public
/// key (p)
pub fn curve25519(n: &[u8; 32], p: &[u8; 32]) -> [u8; 32] {
    let mut e: [u8; 32] = *n;

    // clear the lowest 3 bits, clear the highest bit and set the 2nd highest bit
    e[0] &= 0b1111_1000;
    e[31] &= 0b0111_1111;
    e[31] |= 0b1000000;

    let x1 = Fe::from_bytes(p);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1.clone();
    let mut z3 = Fe::ONE;

    let mut swap = 1u64.ct_zero();
    // pos starts at 254 and goes down to 0
    for pos in (0usize..255).rev() {
        let b = ((e[pos / 8] >> (pos & 7)) & 1).ct_nonzero();
        x2.maybe_swap_with(&mut x3, swap ^ b);
        z2.maybe_swap_with(&mut z3, swap ^ b);
        swap = b;

        let d = &x3 - &z3;
        let b = &x2 - &z2;
        let a = &x2 + &z2;
        let c = &x3 + &z3;
        let da = &d * &a;
        let cb = &c * &b;
        let bb = b.square();
        let aa = a.square();
        let t0 = &da + &cb;
        let t1 = &da - &cb;
        let x4 = &aa * &bb;
        let e = &aa - &bb;
        let t2 = t1.square();
        let t3 = e.mul_small::<121666>();
        let x5 = t0.square();
        let t4 = &bb + &t3;
        let z5 = &x1 * &t2;
        let z4 = &e * &t4;

        z2 = z4;
        z3 = z5;
        x2 = x4;
        x3 = x5;
    }
    x2.maybe_swap_with(&mut x3, swap);
    z2.maybe_swap_with(&mut z3, swap);

    (&z2.invert() * &x2).to_bytes()
}

const BASE: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Derives a public key from a private key
///
/// it's a faster version of `curve25519(x, &BASE)`
/// with `BASE = [9u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]`
pub fn curve25519_base(n: &[u8; 32]) -> [u8; 32] {
    //curve25519(x, &BASE)
    let mut e: [u8; 32] = *n;

    // clear the lowest 3 bits, clear the highest bit and set the 2nd highest bit
    e[0] &= 0b1111_1000;
    e[31] &= 0b0111_1111;
    e[31] |= 0b1000000;

    let x1 = Fe::from_bytes(&BASE);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1.clone();
    let mut z3 = Fe::ONE;

    let mut swap = 1u64.ct_zero();
    // pos starts at 254 and goes down to 0
    for pos in (0usize..255).rev() {
        let b = ((e[pos / 8] >> (pos & 7)) & 1).ct_nonzero();
        x2.maybe_swap_with(&mut x3, swap ^ b);
        z2.maybe_swap_with(&mut z3, swap ^ b);
        swap = b;

        let d = &x3 - &z3;
        let b = &x2 - &z2;
        let a = &x2 + &z2;
        let c = &x3 + &z3;
        let da = &d * &a;
        let cb = &c * &b;
        let bb = b.square();
        let aa = a.square();
        let t0 = &da + &cb;
        let t1 = &da - &cb;
        let x4 = &aa * &bb;
        let e = &aa - &bb;
        let t2 = t1.square();
        let t3 = e.mul_small::<121666>();
        let x5 = t0.square();
        let t4 = &bb + &t3;
        let z5 = t2.mul_small::<9>();
        let z4 = &e * &t4;

        z2 = z4;
        z3 = z5;
        x2 = x4;
        x3 = x5;
    }
    x2.maybe_swap_with(&mut x3, swap);
    z2.maybe_swap_with(&mut z3, swap);

    (&z2.invert() * &x2).to_bytes()
}

#[cfg(test)]
pub(super) mod testrng;

#[cfg(test)]
mod tests {
    use crate::constant_time::CtZero;

    use super::{curve25519_base, Fe};

    #[test]
    fn from_to_bytes_preserves() {
        for i in 0..50 {
            let mut e = [0u8; 32];
            for (idx, v) in e.iter_mut().enumerate() {
                *v = (idx * (1289 + i * 761)) as u8;
            }

            e[0] &= 248;
            e[31] &= 127;
            e[31] |= 64;
            let fe = Fe::from_bytes(&e);
            let e_preserved = fe.to_bytes();
            assert!(e == e_preserved);
        }
    }

    #[test]
    fn swap_test() {
        for (f_initial, g_initial) in CurveGen::new(1).zip(CurveGen::new(2)).take(40) {
            let mut f = f_initial.clone();
            let mut g = g_initial.clone();
            f.maybe_swap_with(&mut g, 0u64.ct_nonzero());
            assert!(f == f_initial);
            assert!(g == g_initial);

            f.maybe_swap_with(&mut g, 1u64.ct_nonzero());
            assert!(f == g_initial);
            assert!(g == f_initial);
        }
    }

    struct CurveGen {
        which: u32,
    }
    impl CurveGen {
        fn new(seed: u32) -> CurveGen {
            CurveGen { which: seed }
        }
    }
    impl Iterator for CurveGen {
        type Item = Fe;

        fn next(&mut self) -> Option<Fe> {
            let mut e = [0u8; 32];
            for (idx, v) in e.iter_mut().enumerate() {
                *v = (idx as u32 * (1289 + self.which * 761)) as u8;
            }

            e[0] &= 248;
            e[31] &= 127;
            e[31] |= 64;
            Some(Fe::from_bytes(&e))
        }
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn mul_commutes() {
        for (x, y) in CurveGen::new(1).zip(CurveGen::new(2)).take(40) {
            assert!(&x * &y == &y * &x);
        }
    }

    #[test]
    fn mul_assoc() {
        for (x, (y, z)) in CurveGen::new(1)
            .zip(CurveGen::new(2).zip(CurveGen::new(3)))
            .take(40)
        {
            assert!(&(&x * &y) * &z == &x * &(&y * &z));
        }
    }

    #[test]
    fn invert_inverts() {
        for x in CurveGen::new(1).take(40) {
            assert!(x.invert().invert() == x);
        }
    }

    #[test]
    fn square_by_mul() {
        for x in CurveGen::new(1).take(40) {
            assert!(&x * &x == x.square());
        }
    }

    #[test]
    fn base_example() {
        let sk: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let pk = curve25519_base(&sk);
        let correct: [u8; 32] = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];
        assert_eq!(pk.to_vec(), correct.to_vec());
    }
}

#[cfg(all(test, feature = "with-bench"))]
mod bench {
    use super::*;
    use test::Bencher;
    #[bench]
    pub fn mul_curve_base(bh: &mut Bencher) {
        bh.iter(|| curve25519_base(&[3u8; 32]));
    }

    #[bench]
    pub fn mul_curve(bh: &mut Bencher) {
        let p = curve25519_base(&[3u8; 32]);
        bh.iter(|| curve25519(&[4u8; 32], &p));
    }
}
