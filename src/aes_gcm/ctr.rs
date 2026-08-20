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

/// The keystream of one whole group, as produced by [`Ctr::next_keystream`].
pub(super) type Keystream = [[u8; BLOCK_BYTES]; PARALLEL_BLOCKS];

/// XOR a whole stitch unit of keystream into `input`, writing to `output`.
///
/// Panics unless `input` and `output` are exactly one group long.
#[inline]
pub(super) fn xor_group(keystream: &Keystream, input: &[u8], output: &mut [u8]) {
    debug_assert_eq!(input.len(), BLOCK_BYTES * PARALLEL_BLOCKS);
    debug_assert_eq!(output.len(), BLOCK_BYTES * PARALLEL_BLOCKS);
    let blocks = input
        .chunks_exact(BLOCK_BYTES)
        .zip(output.chunks_exact_mut(BLOCK_BYTES));
    for (keystream, (input, output)) in keystream.iter().zip(blocks) {
        xor_block(input, keystream, output);
    }
}

/// XOR a whole stitch unit of keystream into `data`, in place.
///
/// Panics unless `data` is exactly one group long.
#[inline]
pub(super) fn xor_group_mut(keystream: &Keystream, data: &mut [u8]) {
    debug_assert_eq!(data.len(), BLOCK_BYTES * PARALLEL_BLOCKS);
    let blocks = data.chunks_exact_mut(BLOCK_BYTES);
    for (keystream, block) in keystream.iter().zip(blocks) {
        xor_keystream_mut(block, keystream);
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

/// Number of bytes of a counter block held by the nonce, the remaining ones
/// being the `inc32` counter itself.
const PREFIX_BYTES: usize = BLOCK_BYTES - 4;

/// AES-CTR counter state for GCM keystream generation.
///
/// Manages the counter block and a buffer of leftover keystream bytes
/// from partial block processing. The counter starts at `inc32(J0)` because
/// J0 itself is reserved for tag encryption.
pub(super) struct Ctr {
    /// The part of the counter block taken from the nonce, which never changes
    prefix: [u8; PREFIX_BYTES],
    /// Rightmost 32 bits of the current counter block, as a number
    counter: u32,
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
        let (prefix, counter) = j0.split_at(PREFIX_BYTES);
        let counter = u32::from_be_bytes(counter.try_into().expect("4 bytes of counter"));
        Ctr {
            prefix: prefix.try_into().expect("12 bytes of prefix"),
            // `inc32(J0)`: the counter wraps within its 32 bits, per NIST SP 800-38D
            counter: counter.wrapping_add(1),
            buffer: [0u8; BLOCK_BYTES],
            buffer_pos: BLOCK_BYTES, // empty
        }
    }

    /// Assemble the counter block for the given counter value.
    #[inline]
    fn block(&self, counter: u32) -> [u8; BLOCK_BYTES] {
        let mut block = [0u8; BLOCK_BYTES];
        block[..PREFIX_BYTES].copy_from_slice(&self.prefix);
        block[PREFIX_BYTES..].copy_from_slice(&counter.to_be_bytes());
        block
    }

    /// The next counter block, advancing the counter by one.
    #[inline]
    fn next_counter(&mut self) -> [u8; BLOCK_BYTES] {
        let block = self.block(self.counter);
        self.counter = self.counter.wrapping_add(1);
        block
    }

    /// The next PARALLEL_BLOCKS counter blocks, advancing the counter by as much.
    #[inline]
    fn next_counters(&mut self) -> [[u8; BLOCK_BYTES]; PARALLEL_BLOCKS] {
        let counter = self.counter;
        let blocks = core::array::from_fn(|i| self.block(counter.wrapping_add(i as u32)));
        self.counter = counter.wrapping_add(PARALLEL_BLOCKS as u32);
        blocks
    }

    /// Number of bytes of keystream left over from the last partial block.
    ///
    /// Zero when the next block of keystream starts fresh, which is what the
    /// group paths below require.
    #[inline]
    pub(super) fn pending(&self) -> usize {
        BLOCK_BYTES - self.buffer_pos
    }

    /// The keystream for the next whole group of blocks.
    ///
    /// Split out from applying it so that the stitched paths can generate the
    /// keystream of one group while hashing the previous one: the two have no
    /// dependency on each other, so issuing them together lets the AES and
    /// carry-less multiplier pipelines overlap instead of taking turns.
    ///
    /// Panics if a partial block is left over from a previous call, since the
    /// group would then not start on a block boundary.
    #[inline]
    pub(super) fn next_keystream<C: BlockEncryptor>(&mut self, cipher: &C) -> Keystream {
        debug_assert_eq!(self.pending(), 0);
        cipher.encrypt_blocks(&self.next_counters())
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
            let keystream = cipher.encrypt_block(&self.next_counter());
            xor_block(input, &keystream, output);
        }
        let input = inputs.remainder();
        let output = outputs.into_remainder();

        // Final partial block: keep the unused keystream for the next call.
        if !input.is_empty() {
            let keystream = cipher.encrypt_block(&self.next_counter());
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
            let keystream = cipher.encrypt_block(&self.next_counter());
            xor_keystream_mut(block, &keystream);
        }
        let data = blocks.into_remainder();

        // Final partial block: keep the unused keystream for the next call.
        if !data.is_empty() {
            let keystream = cipher.encrypt_block(&self.next_counter());
            xor_keystream_mut(data, &keystream);
            self.buffer = keystream;
            self.buffer_pos = data.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

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

    /// A J0 block with every prefix byte set to `prefix` and the given counter.
    fn j0_with(prefix: u8, counter: u32) -> [u8; BLOCK_BYTES] {
        let mut j0 = [prefix; BLOCK_BYTES];
        j0[PREFIX_BYTES..].copy_from_slice(&counter.to_be_bytes());
        j0
    }

    /// The `nblocks` counter blocks a `Ctr` starting at `j0` produces.
    ///
    /// Against the identity cipher and an all-zero input, the output is the
    /// keystream, which is the counter block sequence itself.
    fn counter_blocks(j0: &[u8; BLOCK_BYTES], nblocks: usize) -> Vec<[u8; BLOCK_BYTES]> {
        let mut out = vec![0u8; nblocks * BLOCK_BYTES];
        Ctr::new(j0).process_mut(&Identity, &mut out);
        out.chunks_exact(BLOCK_BYTES)
            .map(|b| b.try_into().expect("one block"))
            .collect()
    }

    /// The counter starts at `inc32(J0)` and goes up by one per block, the
    /// nonce prefix being carried along untouched.
    #[test]
    fn test_counter_starts_after_j0() {
        let blocks = counter_blocks(&j0_with(0xaa, 1), 3);
        assert_eq!(blocks[0], j0_with(0xaa, 2));
        assert_eq!(blocks[1], j0_with(0xaa, 3));
        assert_eq!(blocks[2], j0_with(0xaa, 4));
    }

    /// A carry out of the last byte moves into the next one, and no further.
    #[test]
    fn test_counter_carry() {
        let blocks = counter_blocks(&j0_with(0xaa, 0x0000_00fe), 2);
        assert_eq!(blocks[0], j0_with(0xaa, 0x0000_00ff));
        assert_eq!(blocks[1], j0_with(0xaa, 0x0000_0100));
    }

    /// The counter wraps within its 32 bits, leaving the nonce alone.
    #[test]
    fn test_counter_wraps_in_32_bits() {
        let blocks = counter_blocks(&j0_with(0xaa, 0xffff_fffe), 2);
        assert_eq!(blocks[0], j0_with(0xaa, 0xffff_ffff));
        assert_eq!(blocks[1], j0_with(0xaa, 0x0000_0000));
    }

    /// The bulk path adds an offset to the counter of the whole group at once,
    /// so the wrap has to be checked at every position within a group too.
    #[test]
    fn test_counter_wraps_within_a_group() {
        for offset in 0..(2 * PARALLEL_BLOCKS as u32) {
            let start = 0u32.wrapping_sub(offset);
            let j0 = j0_with(0x5a, start.wrapping_sub(1));
            let blocks = counter_blocks(&j0, 3 * PARALLEL_BLOCKS);
            for (i, block) in blocks.iter().enumerate() {
                assert_eq!(
                    *block,
                    j0_with(0x5a, start.wrapping_add(i as u32)),
                    "block {i} of the run starting at {start:#x}"
                );
            }
        }
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
