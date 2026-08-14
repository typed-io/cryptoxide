//! Portable constant-time GHASH backend.
//!
//! Multiplication in GF(2^128) is done bit by bit with shift-and-conditional-XOR,
//! using branchless masking. No lookup tables are used and no branch depends on
//! secret data.

/// GF(2^128) element represented as a pair of big-endian u64 values.
#[derive(Clone, Copy)]
struct GfElement {
    hi: u64,
    lo: u64,
}

/// Reducing polynomial R for GF(2^128).
///
/// Represents x^128 + x^7 + x^2 + x + 1 per the GCM spec.
/// Only the top 64 bits are needed: 0xe1 << 56.
const R: u64 = 0xe100000000000000u64;

impl GfElement {
    /// The zero element (additive identity) in GF(2^128).
    const ZERO: GfElement = GfElement { hi: 0, lo: 0 };

    /// Construct a GF(2^128) element from a 16-byte big-endian representation.
    fn from_bytes(bytes: &[u8; 16]) -> Self {
        let hi = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let lo = u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        GfElement { hi, lo }
    }

    /// Serialize this element to a 16-byte big-endian representation.
    fn to_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        let hi_bytes = self.hi.to_be_bytes();
        let lo_bytes = self.lo.to_be_bytes();
        out[..8].copy_from_slice(&hi_bytes);
        out[8..].copy_from_slice(&lo_bytes);
        out
    }

    /// XOR two GF(2^128) elements (addition in GF(2^128)).
    fn xor(&self, other: &GfElement) -> GfElement {
        GfElement {
            hi: self.hi ^ other.hi,
            lo: self.lo ^ other.lo,
        }
    }

    /// Multiply two GF(2^128) elements using bit-by-bit constant-time algorithm.
    ///
    /// This processes all 128 bits of `x` (self) against `y` (other) using
    /// shift-and-conditional-XOR with branchless masking. No lookup tables
    /// are used and no branches depend on secret data.
    ///
    /// Algorithm from NIST SP 800-38D, adapted for constant-time execution.
    fn mul(&self, other: &GfElement) -> GfElement {
        let x = *self;
        let mut z = GfElement::ZERO;
        let mut v = *other;

        // Process the high 64 bits of x
        for i in 0..64 {
            // Extract bit i from x.hi (MSB first)
            let bit = (x.hi >> (63 - i)) & 1;
            let mask = 0u64.wrapping_sub(bit);
            // Conditional XOR: z ^= v if bit is set
            z.hi ^= v.hi & mask;
            z.lo ^= v.lo & mask;

            // Right-shift v by 1, with conditional XOR of R
            let lsb_mask = 0u64.wrapping_sub(v.lo & 1);
            v.lo = (v.lo >> 1) | (v.hi << 63);
            v.hi = (v.hi >> 1) ^ (R & lsb_mask);
        }

        // Process the low 64 bits of x
        for i in 0..64 {
            let bit = (x.lo >> (63 - i)) & 1;
            let mask = 0u64.wrapping_sub(bit);
            z.hi ^= v.hi & mask;
            z.lo ^= v.lo & mask;

            let lsb_mask = 0u64.wrapping_sub(v.lo & 1);
            v.lo = (v.lo >> 1) | (v.hi << 63);
            v.hi = (v.hi >> 1) ^ (R & lsb_mask);
        }

        z
    }
}

/// GHASH hash key: the element H the state is multiplied by on every block.
#[derive(Clone)]
pub(super) struct Key {
    h: GfElement,
}

impl Key {
    /// Precompute the multiplication key from the 16-byte hash key H.
    pub(super) fn new(h: &[u8; 16]) -> Self {
        Key {
            h: GfElement::from_bytes(h),
        }
    }
}

/// GHASH accumulator X_i.
#[derive(Clone, Copy)]
pub(super) struct State {
    x: GfElement,
}

impl State {
    /// The initial GHASH state X_0 = 0.
    pub(super) fn zero() -> Self {
        State { x: GfElement::ZERO }
    }

    /// Absorb complete blocks: `state = (state XOR block) * H` for each block.
    ///
    /// `blocks` length must be a multiple of 16.
    pub(super) fn update(&mut self, key: &Key, blocks: &[u8]) {
        debug_assert_eq!(blocks.len() % 16, 0);
        for block in blocks.chunks_exact(16) {
            let block = GfElement::from_bytes(block.try_into().unwrap());
            self.x = self.x.xor(&block).mul(&key.h);
        }
    }

    /// Serialize the accumulator to its 16-byte big-endian representation.
    pub(super) fn to_bytes(&self) -> [u8; 16] {
        self.x.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_multiply_zero() {
        // Multiplying by zero should give zero
        let a = GfElement::ZERO;
        let b = GfElement {
            hi: 0x12345678,
            lo: 0x9abcdef0,
        };
        let result = a.mul(&b);
        assert_eq!(result.hi, 0);
        assert_eq!(result.lo, 0);

        // Also verify commutative: b * 0 == 0
        let a2 = GfElement::from_bytes(&[0x01; 16]);
        let z = GfElement::ZERO;
        let result2 = a2.mul(&z);
        assert_eq!(result2.to_bytes(), [0u8; 16]);
    }

    #[test]
    fn test_gf_xor_self_is_zero() {
        let a = GfElement::from_bytes(&[
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c,
        ]);
        let result = a.xor(&a);
        assert_eq!(result.to_bytes(), [0u8; 16]);
    }

    #[test]
    fn test_gf_from_to_bytes_roundtrip() {
        let bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let elem = GfElement::from_bytes(&bytes);
        assert_eq!(elem.to_bytes(), bytes);
    }
}
