/// GF(2^128) element represented as a pair of big-endian u64 values.
///
/// The element (hi, lo) represents the 128-bit value where `hi` holds the
/// most significant 64 bits (bytes 0..8) and `lo` holds the least significant
/// 64 bits (bytes 8..16).
#[derive(Clone, Copy)]
pub(super) struct GfElement {
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
    pub(super) const ZERO: GfElement = GfElement { hi: 0, lo: 0 };

    /// Construct a GF(2^128) element from a 16-byte big-endian representation.
    pub(super) fn from_bytes(bytes: &[u8; 16]) -> Self {
        let hi = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let lo = u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        GfElement { hi, lo }
    }

    /// Serialize this element to a 16-byte big-endian representation.
    pub(super) fn to_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        let hi_bytes = self.hi.to_be_bytes();
        let lo_bytes = self.lo.to_be_bytes();
        out[..8].copy_from_slice(&hi_bytes);
        out[8..].copy_from_slice(&lo_bytes);
        out
    }

    /// XOR two GF(2^128) elements (addition in GF(2^128)).
    pub(super) fn xor(&self, other: &GfElement) -> GfElement {
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
    pub(super) fn mul(&self, other: &GfElement) -> GfElement {
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

/// Incremental GHASH MAC for AES-GCM.
///
/// GHASH is a universal hash function over GF(2^128) defined in NIST SP 800-38D.
/// It processes 16-byte blocks of data by XORing each block into the running
/// state and multiplying by the hash key H.
pub(super) struct GHash {
    /// Hash key H = AES_K(0^128)
    h: GfElement,
    /// Running GHASH state X_i
    state: GfElement,
    /// Partial block buffer
    buf: [u8; 16],
    /// Number of valid bytes in the partial block buffer
    buf_len: usize,
}

impl GHash {
    /// Create a new GHASH instance with the given hash key.
    ///
    /// The hash key H is typically computed as `AES_K(0^128)`.
    pub(super) fn new(h: &[u8; 16]) -> Self {
        GHash {
            h: GfElement::from_bytes(h),
            state: GfElement::ZERO,
            buf: [0u8; 16],
            buf_len: 0,
        }
    }

    /// Feed data into the GHASH computation.
    ///
    /// Data is buffered internally and processed in 16-byte blocks.
    /// Each complete block updates the state: `state = (state XOR block) * H`.
    pub(super) fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // If there's data in the buffer, try to fill it to a complete block
        if self.buf_len > 0 {
            let remaining = 16 - self.buf_len;
            if data.len() >= remaining {
                self.buf[self.buf_len..16].copy_from_slice(&data[..remaining]);
                let block = GfElement::from_bytes(&self.buf);
                self.state = self.state.xor(&block).mul(&self.h);
                self.buf_len = 0;
                offset = remaining;
            } else {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
        }

        // Process complete 16-byte blocks directly from input
        while offset + 16 <= data.len() {
            let block_bytes: &[u8; 16] = data[offset..offset + 16].try_into().unwrap();
            let block = GfElement::from_bytes(block_bytes);
            self.state = self.state.xor(&block).mul(&self.h);
            offset += 16;
        }

        // Buffer any remaining partial block
        let leftover = data.len() - offset;
        if leftover > 0 {
            self.buf[..leftover].copy_from_slice(&data[offset..]);
            self.buf_len = leftover;
        }
    }

    /// Pad and process any partial block in the buffer.
    ///
    /// If there are buffered bytes, the remaining positions are zero-padded
    /// and the block is processed. This is used between AAD and ciphertext
    /// sections and before finalization.
    pub(super) fn pad(&mut self) {
        if self.buf_len > 0 {
            // Zero-pad the remaining bytes
            for i in self.buf_len..16 {
                self.buf[i] = 0;
            }
            let block = GfElement::from_bytes(&self.buf);
            self.state = self.state.xor(&block).mul(&self.h);
            self.buf_len = 0;
        }
    }

    /// Finalize the GHASH computation with the length block.
    ///
    /// Pads any remaining partial block, then processes the length block
    /// containing `[aad_len_bits]_64be || [ct_len_bits]_64be`.
    ///
    /// The `aad_len` and `ct_len` parameters are byte counts; they are
    /// converted to bit counts internally (multiplied by 8).
    pub(super) fn finalize(mut self, aad_len: u64, ct_len: u64) -> [u8; 16] {
        self.pad();

        // Build length block: bit counts as big-endian u64
        let mut len_block = [0u8; 16];
        let aad_bits = aad_len.wrapping_mul(8);
        let ct_bits = ct_len.wrapping_mul(8);
        len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
        len_block[8..].copy_from_slice(&ct_bits.to_be_bytes());

        let block = GfElement::from_bytes(&len_block);
        self.state = self.state.xor(&block).mul(&self.h);

        self.state.to_bytes()
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

    #[test]
    fn test_ghash_empty_input() {
        // GHASH with H = 66e94bd4ef8a2c3b884cfa59ca342b2e (from NIST Test Case 1), empty input
        // H is AES_K(0^128) where K is all zeros
        // Expected: 00000000000000000000000000000000
        let h = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let ghash = GHash::new(&h);
        let result = ghash.finalize(0, 0);
        assert_eq!(result, [0u8; 16]);
    }

    #[test]
    fn test_ghash_single_block() {
        // GHASH with H = 66e94bd4ef8a2c3b884cfa59ca342b2e
        // C = 0388dace60b6a392f328c2b971b2fe78
        // Expected GHASH(H, C || len): f38cbb1ad69223dcc3457ae5b6b0f885
        //
        // This tests GHASH processing of a single ciphertext block
        // followed by the length block [0_64 || 128_64] (0 bits AAD, 128 bits CT)
        let h = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let c = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78,
        ];

        let mut ghash = GHash::new(&h);
        ghash.update(&c);
        let result = ghash.finalize(0, 16); // 0 bytes AAD, 16 bytes CT

        let expected = [
            0xf3, 0x8c, 0xbb, 0x1a, 0xd6, 0x92, 0x23, 0xdc, 0xc3, 0x45, 0x7a, 0xe5, 0xb6, 0xb0,
            0xf8, 0x85,
        ];
        assert_eq!(&result[..], &expected[..]);
    }
}
