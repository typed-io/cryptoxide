/// Build the initial counter block J0 from a 96-bit nonce.
///
/// For a 96-bit IV, J0 is defined as `IV || 0x00000001` (NIST SP 800-38D Section 7.1).
/// The rightmost 32 bits form a big-endian counter initialized to 1.
pub(super) fn make_j0(nonce: &[u8; 12]) -> [u8; 16] {
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 0x01;
    j0
}

/// Increment the rightmost 32 bits of a 128-bit counter block (big-endian).
///
/// This implements the `inc32` function from NIST SP 800-38D Section 6.2.
/// Only the last 4 bytes are modified; the first 12 bytes (nonce portion)
/// are preserved.
pub(super) fn inc32(counter: &mut [u8; 16]) {
    let c = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]);
    let c = c.wrapping_add(1);
    let bytes = c.to_be_bytes();
    counter[12] = bytes[0];
    counter[13] = bytes[1];
    counter[14] = bytes[2];
    counter[15] = bytes[3];
}

/// AES-CTR counter state for GCM keystream generation.
///
/// Manages the counter block and a buffer of leftover keystream bytes
/// from partial block processing. The counter starts at `inc32(J0)` because
/// J0 itself is reserved for tag encryption.
pub(super) struct Ctr {
    /// Current counter block
    counter: [u8; 16],
    /// Leftover keystream from the last partial block
    buffer: [u8; 16],
    /// Position within the keystream buffer (16 = buffer empty/exhausted)
    buffer_pos: usize,
}

impl Ctr {
    /// Create a new CTR state from the initial counter block J0.
    ///
    /// The CTR encryption starts at `inc32(J0)` per NIST SP 800-38D.
    /// J0 is reserved for encrypting the final GHASH output to produce the tag.
    pub(super) fn new(j0: &[u8; 16]) -> Self {
        let mut counter = *j0;
        inc32(&mut counter);
        Ctr {
            counter,
            buffer: [0u8; 16],
            buffer_pos: 16, // empty
        }
    }

    /// XOR input with AES-CTR keystream, writing to output.
    ///
    /// This handles partial blocks across calls: leftover keystream from a
    /// previous call is consumed first, then full blocks are processed, and
    /// any final partial block's remaining keystream is saved for the next call.
    ///
    /// The `encrypt_block` closure performs `AES_K(counter_block)` to generate
    /// each 16-byte keystream block.
    ///
    /// CTR mode is symmetric: encryption and decryption are the same XOR operation.
    pub(super) fn process<F>(&mut self, encrypt_block: F, input: &[u8], output: &mut [u8])
    where
        F: Fn(&[u8; 16]) -> [u8; 16],
    {
        assert_eq!(input.len(), output.len());
        let mut i = 0;

        // Consume leftover keystream from previous partial block
        while i < input.len() && self.buffer_pos < 16 {
            output[i] = input[i] ^ self.buffer[self.buffer_pos];
            self.buffer_pos += 1;
            i += 1;
        }

        // Process full 16-byte blocks
        while i + 16 <= input.len() {
            let keystream = encrypt_block(&self.counter);
            inc32(&mut self.counter);
            for j in 0..16 {
                output[i + j] = input[i + j] ^ keystream[j];
            }
            i += 16;
        }

        // Handle final partial block
        if i < input.len() {
            let keystream = encrypt_block(&self.counter);
            inc32(&mut self.counter);
            let remaining = input.len() - i;
            for j in 0..remaining {
                output[i + j] = input[i + j] ^ keystream[j];
            }
            // Save remaining keystream for next call
            self.buffer = keystream;
            self.buffer_pos = remaining;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_j0() {
        let nonce = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        ];
        let j0 = make_j0(&nonce);
        assert_eq!(&j0[..12], &nonce);
        assert_eq!(j0[12], 0x00);
        assert_eq!(j0[13], 0x00);
        assert_eq!(j0[14], 0x00);
        assert_eq!(j0[15], 0x01);
    }

    #[test]
    fn test_inc32_basic() {
        let mut counter = [0u8; 16];
        counter[15] = 0x01;
        inc32(&mut counter);
        assert_eq!(counter[15], 0x02);
        assert_eq!(counter[14], 0x00);
    }

    #[test]
    fn test_inc32_wrap() {
        let mut counter = [0u8; 16];
        counter[12] = 0xff;
        counter[13] = 0xff;
        counter[14] = 0xff;
        counter[15] = 0xff;
        inc32(&mut counter);
        // Should wrap to 0x00000000
        assert_eq!(counter[12], 0x00);
        assert_eq!(counter[13], 0x00);
        assert_eq!(counter[14], 0x00);
        assert_eq!(counter[15], 0x00);
        // Nonce portion unchanged
        assert_eq!(&counter[..12], &[0u8; 12]);
    }

    #[test]
    fn test_inc32_carry() {
        let mut counter = [0xaa; 16];
        counter[12] = 0x00;
        counter[13] = 0x00;
        counter[14] = 0x00;
        counter[15] = 0xff;
        inc32(&mut counter);
        assert_eq!(counter[12], 0x00);
        assert_eq!(counter[13], 0x00);
        assert_eq!(counter[14], 0x01);
        assert_eq!(counter[15], 0x00);
        // Nonce portion should be untouched
        assert_eq!(&counter[..12], &[0xaa; 12]);
    }

    #[test]
    fn test_ctr_process_identity_keystream() {
        // Use identity "encryption" (returns input unchanged) to test CTR structure
        let j0 = [0u8; 16];
        let mut ctr = Ctr::new(&j0);
        let input = [0x41u8; 32]; // 2 full blocks
        let mut output = [0u8; 32];
        // Counter starts at inc32(j0) = ...0x02, so keystream blocks are the counter values
        ctr.process(&|block: &[u8; 16]| *block, &input, &mut output);
        // Just verify it completes without panic and output differs from input
        // (XOR with non-zero counter blocks)
        assert_ne!(&output[..], &input[..]);
    }
}
