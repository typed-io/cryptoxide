//! GHASH, the universal hash function underlying AES-GCM authentication.
//!
//! GHASH is defined in NIST SP 800-38D over GF(2^128). It processes 16-byte
//! blocks of data by XORing each block into the running state and multiplying
//! by the hash key H.
//!
//! The backend is selected at compile time:
//!
//! * On aarch64 with the `aes` target feature, the ARMv8 Cryptography
//!   Extensions (`pmull` carry-less multiply) are used.
//! * Otherwise, a portable constant-time bit-by-bit implementation is used.

// ARMv8 Cryptography AES Extensions backend.
#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
mod aarch64;
#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
use aarch64 as backend;

// Software backend: portable constant-time implementation. also available for test
#[cfg(any(not(all(target_arch = "aarch64", target_feature = "aes")), test))]
mod reference;
#[cfg(not(all(target_arch = "aarch64", target_feature = "aes")))]
use reference as backend;

/// Incremental GHASH MAC for AES-GCM.
///
/// GHASH is a universal hash function over GF(2^128) defined in NIST SP 800-38D.
/// It processes 16-byte blocks of data by XORing each block into the running
/// state and multiplying by the hash key H.
pub(super) struct GHash {
    /// Precomputed multiplication key, derived from the hash key H = AES_K(0^128)
    key: backend::Key,
    /// Running GHASH state X_i
    state: backend::State,
    /// Partial block buffer
    buf: [u8; 16],
    /// Number of valid bytes in the partial block buffer
    buf_len: usize,
}

impl GHash {
    /// Create a new GHASH instance with the given hash key.
    ///
    /// The hash key H is typically computed as `AES_K([0;16])`.
    pub(super) fn new(h: &[u8; 16]) -> Self {
        GHash {
            key: backend::Key::new(h),
            state: backend::State::zero(),
            buf: [0u8; 16],
            buf_len: 0,
        }
    }

    /// Feed data into the GHASH computation.
    ///
    /// Data is buffered internally and processed in 16-byte blocks.
    /// Each complete block updates the state: `state = (state XOR block) * H`.
    pub(super) fn update(&mut self, mut data: &[u8]) {
        // If there's data in the buffer, try to fill it to a complete block
        if self.buf_len > 0 {
            let remaining = 16 - self.buf_len;
            if data.len() < remaining {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            let (head, tail) = data.split_at(remaining);
            self.buf[self.buf_len..16].copy_from_slice(head);
            self.state.update(&self.key, &self.buf);
            self.buf_len = 0;
            data = tail;
        }

        // Process all the complete blocks in one go, so that backends able to
        // handle several blocks per reduction can do so.
        let (blocks, leftover) = data.split_at(data.len() & !15);
        if !blocks.is_empty() {
            self.state.update(&self.key, blocks);
        }

        // Buffer any remaining partial block
        if !leftover.is_empty() {
            self.buf[..leftover.len()].copy_from_slice(leftover);
            self.buf_len = leftover.len();
        }
    }

    /// Feed complete blocks into the GHASH computation, bypassing the buffer.
    ///
    /// The counterpart of [`GHash::update`] without safety
    ///
    /// Panics unless `blocks` is a whole number of blocks and the buffer is
    /// empty, i.e. all data fed so far ended on a block boundary.
    pub(super) fn update_blocks(&mut self, blocks: &[u8]) {
        debug_assert_eq!(blocks.len() % 16, 0);
        debug_assert_eq!(self.buf_len, 0);
        self.state.update(&self.key, blocks);
    }

    /// Pad and process any partial block in the buffer.
    ///
    /// If there are buffered bytes, the remaining positions are zero-padded
    /// and the block is processed. This is used between AAD and ciphertext
    /// sections and before finalization.
    pub(super) fn pad(&mut self) {
        if self.buf_len > 0 {
            // Zero-pad the remaining bytes
            self.buf[self.buf_len..16].fill(0);
            self.state.update(&self.key, &self.buf);
            self.buf_len = 0;
        }
    }

    /// Finalize the GHASH computation with the length block.
    ///
    /// Pads any remaining partial block, then processes the length block
    /// containing `[aad_len_bits]_64be || [ct_len_bits]_64be`.
    ///
    /// The `aad_len` and `ct_len` parameters are byte counts; they are
    /// converted to bit counts internally
    pub(super) fn finalize(mut self, aad_len: u64, ct_len: u64) -> [u8; 16] {
        self.pad();

        // Build length block: bit counts as big-endian u64
        let mut len_block = [0u8; 16];
        let aad_bits = aad_len.wrapping_mul(8);
        let ct_bits = ct_len.wrapping_mul(8);
        len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
        len_block[8..].copy_from_slice(&ct_bits.to_be_bytes());

        self.state.update(&self.key, &len_block);

        self.state.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// H = AES_0([0; 16]), from NIST SP 800-38D test case 1.
    const H: [u8; 16] = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b,
        0x2e,
    ];

    #[test]
    fn test_ghash_empty_input() {
        // GHASH with H = 66e94bd4ef8a2c3b884cfa59ca342b2e (from NIST Test Case 1), empty input
        // H is AES_K([0;16]) where K is all zeros
        // Expected: 00000000000000000000000000000000
        let ghash = GHash::new(&H);
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
        let c = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78,
        ];

        let mut ghash = GHash::new(&H);
        ghash.update(&c);
        let result = ghash.finalize(0, 16); // 0 bytes AAD, 16 bytes CT

        let expected = [
            0xf3, 0x8c, 0xbb, 0x1a, 0xd6, 0x92, 0x23, 0xdc, 0xc3, 0x45, 0x7a, 0xe5, 0xb6, 0xb0,
            0xf8, 0x85,
        ];
        assert_eq!(&result[..], &expected[..]);
    }

    /// Feeding the same data in arbitrary chunk sizes must give the same result
    /// as feeding it in one call: the partial block buffering has to agree with
    /// the multi-block bulk path of whichever backend is selected.
    #[test]
    fn test_ghash_incremental_matches_oneshot() {
        let data: [u8; 293] = core::array::from_fn(|i| ((i * 7 + 3) & 0xff) as u8);

        let mut oneshot = GHash::new(&H);
        oneshot.update(&data);
        let expected = oneshot.finalize(13, data.len() as u64);

        for chunk in [1, 3, 5, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 291] {
            let mut ghash = GHash::new(&H);
            for part in data.chunks(chunk) {
                ghash.update(part);
            }
            let got = ghash.finalize(13, data.len() as u64);
            assert_eq!(got, expected, "mismatch with {chunk}-byte chunks");
        }
    }
}

#[cfg(all(test, feature = "with-bench"))]
mod bench {
    use super::*;
    use test::Bencher;

    fn bench_update(bh: &mut Bencher, size: usize) {
        let h = [3u8; 16];
        let data = vec![1u8; size];
        let mut ghash = GHash::new(&h);
        bh.iter(|| {
            ghash.update(&data);
        });
        bh.bytes = size as u64;
    }

    #[bench]
    pub fn ghash_16(bh: &mut Bencher) {
        bench_update(bh, 16);
    }

    #[bench]
    pub fn ghash_1k(bh: &mut Bencher) {
        bench_update(bh, 1024);
    }

    #[bench]
    pub fn ghash_64k(bh: &mut Bencher) {
        bench_update(bh, 65536);
    }
}
