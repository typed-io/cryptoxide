use crate::cryptoutil::{read_u64v_be, write_u32_be, write_u64v_be};

pub(super) const STATE_LEN: usize = 8;
pub(super) const BLOCK_LEN: usize = 16;
pub(super) const BLOCK_LEN_BYTES: usize = BLOCK_LEN * core::mem::size_of::<u64>();

pub use super::reference512::*;

// A structure that represents that state of a digest computation for
// the SHA-2 64 bits family of digest functions
#[derive(Clone)]
pub(super) struct Engine {
    h: [u64; STATE_LEN],
}

impl Engine {
    pub(super) fn new(h: &[u64; STATE_LEN]) -> Self {
        Self { h: *h }
    }

    pub(super) fn reset(&mut self, h: &[u64; STATE_LEN]) {
        self.h = *h;
    }

    /// Process a block with the SHA-2 64bits algorithm.
    #[allow(dead_code)]
    pub fn block(&mut self, block: &[u64; BLOCK_LEN]) {
        digest_block_u64(&mut self.h, block);
    }

    /// Process a block in bytes with the SHA-2 64bits algorithm.
    pub fn block_byteslice(&mut self, block: &[u8]) {
        assert_eq!(block.len(), BLOCK_LEN_BYTES);
        let mut block2 = [0u64; BLOCK_LEN];
        read_u64v_be(&mut block2[..], block);
        digest_block_u64(&mut self.h, &block2);
    }

    #[allow(dead_code)]
    pub(super) fn output_224bits(&self, out: &mut [u8; 28]) {
        write_u64v_be(&mut out[0..24], &self.h[0..3]);
        write_u32_be(&mut out[24..28], (self.h[3] >> 32) as u32);
    }

    #[allow(dead_code)]
    pub(super) fn output_256bits(&self, out: &mut [u8; 32]) {
        write_u64v_be(out, &self.h[0..4]);
    }

    #[allow(dead_code)]
    pub(super) fn output_384bits(&self, out: &mut [u8; 48]) {
        write_u64v_be(out, &self.h[0..6])
    }

    #[allow(dead_code)]
    pub(super) fn output_512bits(&self, out: &mut [u8; 64]) {
        write_u64v_be(out, &self.h[0..8])
    }

    pub(super) fn output_224bits_at(&self, out: &mut [u8]) {
        write_u64v_be(&mut out[0..24], &self.h[0..3]);
        write_u32_be(&mut out[24..28], (self.h[3] >> 32) as u32);
    }

    pub(super) fn output_256bits_at(&self, out: &mut [u8]) {
        write_u64v_be(out, &self.h[0..4]);
    }

    pub(super) fn output_384bits_at(&self, out: &mut [u8]) {
        write_u64v_be(out, &self.h[0..6])
    }

    pub(super) fn output_512bits_at(&self, out: &mut [u8]) {
        write_u64v_be(out, &self.h[0..8])
    }
}
