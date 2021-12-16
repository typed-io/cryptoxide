//! Constant time operations
//!
//! This module exports traits to do basic checking operation in constant time,
//! those operations are:
//!
//! * CtZero : constant time zero and non-zero checking
//! * CtEqual : constant time equality and non-equality checking
//! * CtLesser : constant time less (<) and opposite greater-equal (>=) checking
//! * CtGreater : constant time greater (>) and opposite lesser-equal (<=) checking
//!
//! And simple types to manipulate those capabilities in a safer way:
//!
//! * Choice : Constant time boolean and safe methods.
//!            this was initially called CtBool but aligned to other implementation.
//! * CtOption : Constant time Option type.
//!
//! Great care has been done to make operation constant so that it's useful in
//! cryptographic context, but we're not protected from implementation bug,
//! compiler optimisations, gamma rays and other Moon-Mars alignments.
//!
//! The general functionality would be a great addition to the rust core library
//! to have those type of things built-in and crucially more eyeballs.

/// Constant time boolean
///
/// This implementation uses a u64 under the hood, but it's never exposed
/// and only used through abstraction that push toward more constant time
/// operations.
///
/// Choice can be combined with simple And operation.
///
/// Choice can be converted back to a boolean operations, although
/// once this is done, the operation will likely be non-constant.
#[derive(Clone, Copy)]
pub struct Choice(pub(crate) u64);

/// Constant time equivalent to Option.
///
/// The T type is always present in the data structure,
/// it's just marked as valid / invalid with a Choice
/// type.
#[derive(Clone)]
pub struct CtOption<T> {
    present: Choice, // if present the value is there and valid
    t: T,
}

impl Choice {
    pub fn is_true(self) -> bool {
        self.0 == 1
    }
    pub fn is_false(self) -> bool {
        self.0 == 0
    }
    pub fn negate(self) -> Self {
        Choice(1 ^ self.0)
    }
}

impl From<Choice> for bool {
    fn from(c: Choice) -> bool {
        c.is_true()
    }
}

impl core::ops::BitAnd for Choice {
    type Output = Choice;
    fn bitand(self, b: Choice) -> Choice {
        Choice(self.0 & b.0)
    }
}

impl<T> From<(Choice, T)> for CtOption<T> {
    fn from(c: (Choice, T)) -> CtOption<T> {
        CtOption {
            present: c.0,
            t: c.1,
        }
    }
}

impl<T> CtOption<T> {
    pub fn into_option(self) -> Option<T> {
        if self.present.is_true() {
            Some(self.t)
        } else {
            None
        }
    }
}

/// Check in constant time if the object is zero or non-zero
///
/// Note that zero means 0 with integer primitive, or for array of integer
/// it means all elements are 0
pub trait CtZero {
    fn ct_zero(&self) -> Choice;
    fn ct_nonzero(&self) -> Choice;
}

/// Check in constant time if the left object is greater than right object
///
/// This equivalent to the > operator found in the core library.
pub trait CtGreater: Sized {
    fn ct_gt(a: Self, b: Self) -> Choice;
    fn ct_le(a: Self, b: Self) -> Choice {
        Self::ct_gt(b, a)
    }
}

/// Check in constant time if the left object is lesser than right object
///
/// This equivalent to the < operator found in the core library.
pub trait CtLesser: Sized {
    fn ct_lt(a: Self, b: Self) -> Choice;
    fn ct_ge(a: Self, b: Self) -> Choice {
        Self::ct_lt(b, a)
    }
}

/// Check in constant time if the left object is equal to the right object
///
/// This equivalent to the == operator found in the core library.
pub trait CtEqual<Rhs: ?Sized = Self> {
    fn ct_eq(&self, b: &Rhs) -> Choice;
    fn ct_ne(&self, b: &Rhs) -> Choice {
        self.ct_eq(b).negate()
    }
}

impl CtZero for u64 {
    fn ct_zero(&self) -> Choice {
        Choice(1 ^ ((self | self.wrapping_neg()) >> 63))
    }
    fn ct_nonzero(&self) -> Choice {
        Choice((self | self.wrapping_neg()) >> 63)
    }
}

impl CtEqual for u64 {
    fn ct_eq(&self, b: &Self) -> Choice {
        Self::ct_zero(&(self ^ b))
    }
    fn ct_ne(&self, b: &Self) -> Choice {
        Self::ct_nonzero(&(self ^ b))
    }
}

impl CtLesser for u64 {
    fn ct_lt(a: Self, b: Self) -> Choice {
        Choice((a ^ ((a ^ b) | ((a - b) ^ b))) >> 63)
    }
}

impl CtGreater for u64 {
    fn ct_gt(a: Self, b: Self) -> Choice {
        Self::ct_lt(b, a)
    }
}

impl<const N: usize> CtZero for [u8; N] {
    fn ct_zero(&self) -> Choice {
        let mut acc = 0u64;
        for b in self.iter() {
            acc |= *b as u64
        }
        acc.ct_zero()
    }
    fn ct_nonzero(&self) -> Choice {
        let mut acc = 0u64;
        for b in self.iter() {
            acc |= *b as u64
        }
        acc.ct_nonzero()
    }
}

impl<const N: usize> CtZero for [u64; N] {
    fn ct_zero(&self) -> Choice {
        let mut acc = 0u64;
        for b in self.iter() {
            acc |= b
        }
        acc.ct_zero()
    }
    fn ct_nonzero(&self) -> Choice {
        let mut acc = 0u64;
        for b in self.iter() {
            acc |= b
        }
        acc.ct_nonzero()
    }
}

impl CtZero for [u64] {
    fn ct_zero(&self) -> Choice {
        let mut acc = 0u64;
        for b in self.iter() {
            acc |= b
        }
        acc.ct_zero()
    }
    fn ct_nonzero(&self) -> Choice {
        let mut acc = 0u64;
        for b in self.iter() {
            acc |= b
        }
        acc.ct_nonzero()
    }
}

impl<const N: usize> CtEqual for [u8; N] {
    fn ct_eq(&self, b: &[u8; N]) -> Choice {
        let mut acc = 0u64;
        for (x, y) in self.iter().zip(b.iter()) {
            acc |= (*x as u64) ^ (*y as u64);
        }
        acc.ct_zero()
    }
}
impl<const N: usize> CtEqual for [u64; N] {
    fn ct_eq(&self, b: &[u64; N]) -> Choice {
        let mut acc = 0u64;
        for (x, y) in self.iter().zip(b.iter()) {
            acc |= x ^ y;
        }
        acc.ct_zero()
    }
}

impl CtEqual for [u8] {
    fn ct_eq(&self, b: &[u8]) -> Choice {
        assert_eq!(self.len(), b.len());
        let mut acc = 0u64;
        for (x, y) in self.iter().zip(b.iter()) {
            acc |= (*x as u64) ^ (*y as u64);
        }
        acc.ct_zero()
    }
}

impl CtEqual for [u64] {
    fn ct_eq(&self, b: &[u64]) -> Choice {
        assert_eq!(self.len(), b.len());
        let mut acc = 0u64;
        for (x, y) in self.iter().zip(b.iter()) {
            acc |= x ^ y;
        }
        acc.ct_zero()
    }
}

// big endian representation of a number, but also leading byte of a array being the MSB.
impl<const N: usize> CtLesser for &[u8; N] {
    fn ct_lt(a: Self, b: Self) -> Choice {
        let mut borrow = 0u8;
        for (x, y) in a.iter().rev().zip(b.iter().rev()) {
            let x1: i16 = ((*x as i16) - (borrow as i16)) - (*y as i16);
            let x2: i8 = (x1 >> 8) as i8;
            borrow = (0x0 - x2) as u8;
        }
        let borrow = borrow as u64;
        Choice((borrow | borrow.wrapping_neg()) >> 63)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_zero() {
        assert_eq!(0u64.ct_zero().is_true(), true);
        assert_eq!(1u64.ct_zero().is_false(), true);
    }

    #[test]
    fn test_ct_less() {
        let a: [u8; 4] = [0u8, 1, 2, 3];
        assert_eq!(<&[u8; 4]>::ct_lt(&a, &[1, 1, 2, 3]).is_true(), true);
    }
}
