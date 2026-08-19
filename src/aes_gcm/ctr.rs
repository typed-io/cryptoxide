//! AES-CTR keystream generation for GCM.

use super::BlockEncryptor;
use crate::aes::{BLOCK_BYTES, PARALLEL_BLOCKS};
use crate::cryptoutil::xor_keystream_mut;

/// XOR a block of keystream into `input`, writing to `output`.
#[inline(always)]
fn xor_block(input: &[u8], keystream: &[u8; BLOCK_BYTES], output: &mut [u8]) {
    for ((output, input), keystream) in output.iter_mut().zip(input).zip(keystream) {
        *output = *input ^ *keystream;
    }
}

/// Build the initial counter block J0 from a 96-bit nonce.
///
/// For a 96-bit IV, J0 is defined as `IV || 0x00000001` (NIST SP 800-38D Section 7.1).
/// The rightmost 32 bits form a big-endian counter initialized to 1.
pub(super) fn make_j0(nonce: &[u8; 12]) -> [u8; BLOCK_BYTES] {
    let mut j0 = [0u8; BLOCK_BYTES];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 0x01;
    j0
}

/// Increment the rightmost 32 bits of a 128-bit counter block (big-endian).
///
/// This implements the `inc32` function from NIST SP 800-38D Section 6.2.
/// Only the last 4 bytes are modified; the first 12 bytes (nonce portion)
/// are preserved.
pub(super) fn inc32(counter: &mut [u8; BLOCK_BYTES]) {
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
    counter: [u8; BLOCK_BYTES],
    /// Leftover keystream from the last partial block
    buffer: [u8; BLOCK_BYTES],
    /// Position within the keystream buffer (16 = buffer empty/exhausted)
    buffer_pos: usize,
}

impl Ctr {
    /// Create a new CTR state from the initial counter block J0.
    ///
    /// The CTR encryption starts at `inc32(J0)` per NIST SP 800-38D.
    /// J0 is reserved for encrypting the final GHASH output to produce the tag.
    pub(super) fn new(j0: &[u8; BLOCK_BYTES]) -> Self {
        let mut counter = *j0;
        inc32(&mut counter);
        Ctr {
            counter,
            buffer: [0u8; BLOCK_BYTES],
            buffer_pos: BLOCK_BYTES, // empty
        }
    }

    #[inline]
    fn next_counters(&mut self) -> [[u8; BLOCK_BYTES]; PARALLEL_BLOCKS] {
        core::array::from_fn(|_| {
            let counter = self.counter;
            inc32(&mut self.counter);
            counter
        })
    }

    /// XOR input with AES-CTR keystream, writing to output.
    ///
    /// This handles partial blocks across calls: leftover keystream from a
    /// previous call is consumed first, then full blocks are processed, and
    /// any final partial block's remaining keystream is saved for the next call.
    ///
    /// The bulk of the data is handled PARALLEL_BLOCKS blocks at a time.
    pub(super) fn process<C: BlockEncryptor>(
        &mut self,
        cipher: &C,
        input: &[u8],
        output: &mut [u8],
    ) {
        assert_eq!(input.len(), output.len());

        // Consume the keystream left over by a previous partial block.
        let leftover = core::cmp::min(BLOCK_BYTES - self.buffer_pos, input.len());
        let buffered = &self.buffer[self.buffer_pos..self.buffer_pos + leftover];
        for ((output, input), keystream) in output.iter_mut().zip(input).zip(buffered) {
            *output = *input ^ *keystream;
        }
        self.buffer_pos += leftover;
        let input = &input[leftover..];
        let output = &mut output[leftover..];

        // Bulk: one cipher call per group of blocks.
        let mut inputs = input.chunks_exact(BLOCK_BYTES * PARALLEL_BLOCKS);
        let mut outputs = output.chunks_exact_mut(BLOCK_BYTES * PARALLEL_BLOCKS);
        for (input, output) in inputs.by_ref().zip(outputs.by_ref()) {
            let keystream = cipher.encrypt_blocks(&self.next_counters());
            let blocks = input
                .chunks_exact(BLOCK_BYTES)
                .zip(output.chunks_exact_mut(BLOCK_BYTES));
            for (keystream, (input, output)) in keystream.iter().zip(blocks) {
                xor_block(input, keystream, output);
            }
        }
        let input = inputs.remainder();
        let output = outputs.into_remainder();

        // The 0 to PARALLEL_BLOCKS-1 whole blocks the groups did not cover.
        let mut inputs = input.chunks_exact(BLOCK_BYTES);
        let mut outputs = output.chunks_exact_mut(BLOCK_BYTES);
        for (input, output) in inputs.by_ref().zip(outputs.by_ref()) {
            let keystream = cipher.encrypt_block(&self.counter);
            inc32(&mut self.counter);
            xor_block(input, &keystream, output);
        }
        let input = inputs.remainder();
        let output = outputs.into_remainder();

        // Final partial block: keep the unused keystream for the next call.
        if !input.is_empty() {
            let keystream = cipher.encrypt_block(&self.counter);
            inc32(&mut self.counter);
            xor_block(input, &keystream, output);
            self.buffer = keystream;
            self.buffer_pos = input.len();
        }
    }

    /// XOR the AES-CTR keystream into `data`, in place.
    ///
    /// Same keystream and same handling of partial blocks across calls as
    /// [`Ctr::process`], the only difference being that the data is replaced
    /// instead of written to a separate output.
    pub(super) fn process_mut<C: BlockEncryptor>(&mut self, cipher: &C, data: &mut [u8]) {
        // Consume the keystream left over by a previous partial block.
        let leftover = core::cmp::min(BLOCK_BYTES - self.buffer_pos, data.len());
        let buffered = &self.buffer[self.buffer_pos..self.buffer_pos + leftover];
        for (data, keystream) in data.iter_mut().zip(buffered) {
            *data ^= *keystream;
        }
        self.buffer_pos += leftover;
        let data = &mut data[leftover..];

        // Bulk: one cipher call per group of blocks.
        let mut groups = data.chunks_exact_mut(BLOCK_BYTES * PARALLEL_BLOCKS);
        for group in groups.by_ref() {
            let keystream = cipher.encrypt_blocks(&self.next_counters());
            let blocks = group.chunks_exact_mut(BLOCK_BYTES);
            for (keystream, block) in keystream.iter().zip(blocks) {
                xor_keystream_mut(block, keystream);
            }
        }
        let data = groups.into_remainder();

        // The 0 to PARALLEL_BLOCKS-1 whole blocks the groups did not cover.
        let mut blocks = data.chunks_exact_mut(BLOCK_BYTES);
        for block in blocks.by_ref() {
            let keystream = cipher.encrypt_block(&self.counter);
            inc32(&mut self.counter);
            xor_keystream_mut(block, &keystream);
        }
        let data = blocks.into_remainder();

        // Final partial block: keep the unused keystream for the next call.
        if !data.is_empty() {
            let keystream = cipher.encrypt_block(&self.counter);
            inc32(&mut self.counter);
            xor_keystream_mut(data, &keystream);
            self.buffer = keystream;
            self.buffer_pos = data.len();
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
        let mut counter = [0u8; BLOCK_BYTES];
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
        let mut counter = [0xaa; BLOCK_BYTES];
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

    /// Identity "cipher": the keystream is the counter block itself, which
    /// makes the counter sequence directly observable in the output.
    struct Identity;

    impl BlockEncryptor for Identity {
        fn encrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
            *block
        }
        fn encrypt_blocks(
            &self,
            blocks: &[[u8; BLOCK_BYTES]; PARALLEL_BLOCKS],
        ) -> [[u8; BLOCK_BYTES]; PARALLEL_BLOCKS] {
            *blocks
        }
    }

    #[test]
    fn test_ctr_process_identity_keystream() {
        // Use identity "encryption" (returns input unchanged) to test CTR structure
        let j0 = [0u8; BLOCK_BYTES];
        let mut ctr = Ctr::new(&j0);
        let input = [0x41u8; 32]; // 2 full blocks
        let mut output = [0u8; 32];
        // Counter starts at inc32(j0) = ...0x02, so keystream blocks are the counter values
        ctr.process(&Identity, &input, &mut output);
        // Just verify it completes without panic and output differs from input
        // (XOR with non-zero counter blocks)
        assert_ne!(&output[..], &input[..]);
    }

    /// The keystream must not depend on how the data is split across calls:
    /// the multi-block bulk path, the single-block tail and the buffered
    /// partial block all have to line up on the same counter sequence.
    #[test]
    fn test_ctr_chunking_matches_oneshot() {
        let j0 = [0x5au8; BLOCK_BYTES];
        let input: [u8; 293] = core::array::from_fn(|i| ((i * 11 + 5) & 0xff) as u8);

        let mut expected = [0u8; 293];
        Ctr::new(&j0).process(&Identity, &input, &mut expected);

        for chunk in [1, 3, 15, 16, 17, 31, 33, 63, 64, 65, 127, 292] {
            let mut ctr = Ctr::new(&j0);
            let mut got = [0u8; 293];
            for (input, output) in input.chunks(chunk).zip(got.chunks_mut(chunk)) {
                ctr.process(&Identity, input, output);
            }
            assert_eq!(got, expected, "mismatch with {chunk}-byte chunks");
        }
    }
}
