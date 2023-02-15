//! Blake2 hash function
//!
//! Blake2 [Specification][1].
//!
//! [1]: https://eprint.iacr.org/2013/322.pdf

mod common;
mod reference;

pub use common::LastBlock;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "avx"
))]
mod avx;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "avx2"
))]
mod avx2;

use common::{b, s};

/// Blake2s Context
#[derive(Clone)]
#[repr(align(32))]
pub struct EngineS {
    pub h: [u32; 8],
    pub t: [u32; 2],
}

impl EngineS {
    pub const BLOCK_BYTES: usize = s::BLOCK_BYTES;
    pub const BLOCK_BYTES_NATIVE: u32 = s::BLOCK_BYTES as u32;
    pub const MAX_OUTLEN: usize = s::MAX_OUTLEN;
    pub const MAX_KEYLEN: usize = s::MAX_KEYLEN;

    pub fn new(outlen: usize, keylen: usize) -> Self {
        assert!(outlen > 0 && outlen <= s::MAX_OUTLEN);
        assert!(keylen <= s::MAX_KEYLEN);
        let mut h = s::IV;
        h[0] ^= 0x01010000 ^ ((keylen as u32) << 8) ^ outlen as u32;
        Self { h, t: [0, 0] }
    }

    pub fn reset(&mut self, outlen: usize, keylen: usize) {
        self.h = s::IV;
        self.h[0] ^= 0x01010000 ^ ((keylen as u32) << 8) ^ outlen as u32;
        self.t[0] = 0;
        self.t[1] = 0;
    }
    #[inline]
    pub fn increment_counter(&mut self, inc: u32) {
        self.t[0] += inc;
        self.t[1] += if self.t[0] < inc { 1 } else { 0 };
    }

    pub fn compress(&mut self, buf: &[u8], last: LastBlock) {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            #[cfg(target_feature = "avx")]
            const HAS_AVX: bool = true;
            #[cfg(not(target_feature = "avx"))]
            const HAS_AVX: bool = false;

            #[cfg(target_feature = "avx")]
            {
                if HAS_AVX {
                    return avx::compress_s(&mut self.h, &mut self.t, buf, last);
                }
            }
        }
        reference::compress_s(&mut self.h, &mut self.t, buf, last)
    }
}

/// Blake2b Context
#[derive(Clone)]
#[repr(align(32))]
pub struct EngineB {
    pub h: [u64; 8],
    pub t: [u64; 2],
}

impl EngineB {
    pub const BLOCK_BYTES: usize = b::BLOCK_BYTES;
    pub const BLOCK_BYTES_NATIVE: u64 = b::BLOCK_BYTES as u64;
    pub const MAX_OUTLEN: usize = b::MAX_OUTLEN;
    pub const MAX_KEYLEN: usize = b::MAX_KEYLEN;

    pub fn new(outlen: usize, keylen: usize) -> Self {
        assert!(outlen > 0 && outlen <= b::MAX_OUTLEN);
        assert!(keylen <= b::MAX_KEYLEN);
        let mut h = b::IV;
        h[0] ^= 0x01010000 ^ ((keylen as u64) << 8) ^ outlen as u64;
        Self { h, t: [0, 0] }
    }

    pub fn reset(&mut self, outlen: usize, keylen: usize) {
        self.h = b::IV;
        self.h[0] ^= 0x01010000 ^ ((keylen as u64) << 8) ^ outlen as u64;
        self.t[0] = 0;
        self.t[1] = 0;
    }

    #[inline]
    pub fn increment_counter(&mut self, inc: u64) {
        self.t[0] += inc;
        self.t[1] += if self.t[0] < inc { 1 } else { 0 };
    }

    pub fn compress(&mut self, buf: &[u8], last: LastBlock) {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            #[cfg(target_feature = "avx")]
            const HAS_AVX: bool = true;
            #[cfg(not(target_feature = "avx"))]
            const HAS_AVX: bool = false;

            #[cfg(target_feature = "avx2")]
            const HAS_AVX2: bool = true;
            #[cfg(not(target_feature = "avx2"))]
            const HAS_AVX2: bool = false;

            #[cfg(target_feature = "avx2")]
            {
                if HAS_AVX2 {
                    return avx2::compress_b(&mut self.h, &mut self.t, buf, last);
                }
            }

            #[cfg(target_feature = "avx")]
            {
                if HAS_AVX {
                    return avx::compress_b(&mut self.h, &mut self.t, buf, last);
                }
            }
        }
        reference::compress_b(&mut self.h, &mut self.t, buf, last)
    }
}
