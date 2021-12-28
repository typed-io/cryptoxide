//! Field Element implementation for 64-bits native arch using unsaturated 51-bits limbs.
//!
//! arithmetic calculation helpers:
//!
//! * Sandy2x: New Curve25519 Speed Records

use crate::constant_time::{Choice, CtEqual};
use core::ops::{Add, Mul, Neg, Sub};

pub mod precomp;

/// Field Element in \Z/(2^255-19)
#[derive(Clone)]
pub struct Fe(pub(crate) [u64; 5]);

impl CtEqual for Fe {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
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

    // todo
    pub const SQRTM1: Fe = Fe([1, 1, 1, 1, 1]);
    pub const D: Fe = Fe([1, 1, 1, 1, 1]);
    pub const D2: Fe = Fe([1, 1, 1, 1, 1]);
}

impl Add for &Fe {
    type Output = Fe;

    fn add(self, rhs: &Fe) -> Fe {
        let Fe([f0, f1, f2, f3, f4]) = *self;
        let Fe([g0, g1, g2, g3, g4]) = *rhs;
        let h0 = f0 + g0;
        let h1 = f1 + g1;
        let h2 = f2 + g2;
        let h3 = f3 + g3;
        let h4 = f4 + g4;
        Fe([h0, h1, h2, h3, h4])
    }
}

impl Sub for &Fe {
    type Output = Fe;

    fn sub(self, rhs: &Fe) -> Fe {
        // multiple of P
        const TWO_P0: u64 = 0x0fffffffffffda;
        const TWO_P1234: u64 = 0x0ffffffffffffe;

        let Fe([f0, f1, f2, f3, f4]) = *self;
        let Fe([g0, g1, g2, g3, g4]) = *rhs;

        let h0 = f0 + TWO_P0 - g0;
        let h1 = f1 + TWO_P1234 - g1;
        let h2 = f2 + TWO_P1234 - g2;
        let h3 = f3 + TWO_P1234 - g3;
        let h4 = f4 + TWO_P1234 - g4;
        Fe([h0, h1, h2, h3, h4])
    }
}

impl Neg for &Fe {
    type Output = Fe;

    fn neg(self) -> Fe {
        todo!()
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

impl Fe {
    pub fn from_bytes(bytes: &[u8; 32]) -> Fe {
        todo!()
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        todo!()
    }
    pub fn invert(&self) -> Fe {
        todo!()
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
        todo!()
    }
    pub fn is_nonzero(&self) -> bool {
        CtEqual::ct_ne(&self.to_bytes(), &[0; 32]).into()
    }
    pub fn is_negative(&self) -> bool {
        (self.to_bytes()[0] & 1) != 0
    }
    pub(crate) fn maybe_swap_with(&mut self, other: &mut Fe, do_swap: i32) {
        todo!()
    }
    pub(crate) fn maybe_set(&mut self, other: &Fe, do_swap: i32) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn prop_() {}
}
