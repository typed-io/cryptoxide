use crate::cryptoutil::{write_u32_be, write_u64v_be};

pub(super) const STATE_LEN: usize = 8;
pub(super) const BLOCK_LEN: usize = 16;
pub(super) const BLOCK_LEN_BYTES: usize = BLOCK_LEN * core::mem::size_of::<u64>();

use super::impl512::*;

// A structure that represents that state of a digest computation for
// the SHA-2 64 bits family of digest functions
#[derive(Clone)]
pub(super) struct Engine {
    h: [u64; STATE_LEN],
}

impl Engine {
    pub(super) const fn new(h: &[u64; STATE_LEN]) -> Self {
        Self { h: *h }
    }

    pub(super) fn reset(&mut self, h: &[u64; STATE_LEN]) {
        self.h = *h;
    }

    /// Process a block in bytes with the SHA-2 32bits algorithm.
    pub fn blocks(&mut self, block: &[u8]) {
        assert_eq!(block.len() % BLOCK_LEN_BYTES, 0);
        digest_block(&mut self.h, block);
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
