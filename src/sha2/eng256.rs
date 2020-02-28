use crate::cryptoutil::{read_u32v_be, write_u32v_be};

pub(super) const STATE_LEN: usize = 8;
pub(super) const BLOCK_LEN: usize = 16;
pub(super) const BLOCK_LEN_BYTES: usize = BLOCK_LEN * core::mem::size_of::<u32>();

pub use super::reference256::*;

// A structure that represents that state of a digest computation for
// the SHA-2 32 bits family of digest functions
#[derive(Clone)]
pub(super) struct Engine {
    h: [u32; STATE_LEN],
}

impl Engine {
    pub(super) fn new(h: &[u32; STATE_LEN]) -> Self {
        Self { h: *h }
    }

    pub(super) fn reset(&mut self, h: &[u32; STATE_LEN]) {
        self.h = *h;
    }

    /// Process a block with the SHA-2 32bits algorithm.
    #[allow(dead_code)]
    pub fn block(&mut self, block: &[u32; BLOCK_LEN]) {
        digest_block_u32(&mut self.h, block);
    }

    /// Process a block in bytes with the SHA-2 32bits algorithm.
    pub fn block_byteslice(&mut self, block: &[u8]) {
        assert_eq!(block.len(), BLOCK_LEN_BYTES);
        let mut block2 = [0u32; BLOCK_LEN];
        read_u32v_be(&mut block2[..], block);
        digest_block_u32(&mut self.h, &block2);
    }

    #[allow(dead_code)]
    pub(super) fn output_224bits(&self, out: &mut [u8; 28]) {
        write_u32v_be(out, &self.h[0..7]);
    }

    #[allow(dead_code)]
    pub(super) fn output_256bits(&self, out: &mut [u8; 32]) {
        write_u32v_be(out, &self.h);
    }

    pub(super) fn output_224bits_at(&self, out: &mut [u8]) {
        write_u32v_be(&mut out[0..28], &self.h[0..7]);
    }

    pub(super) fn output_256bits_at(&self, out: &mut [u8]) {
        write_u32v_be(&mut out[0..32], &self.h);
    }
}
