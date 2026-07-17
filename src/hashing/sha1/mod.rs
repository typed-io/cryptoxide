//! An implementation of the SHA-1 cryptographic hash algorithm.
//!
//! it is however discouraged to use this algorithm in any application as is, as this is
//! not considered secured anymore. the algorithm is deprecated since 2011, and chosen prefix
//! attack are practical.
//!
//! However the hash function is still pervasively used in other contextes where security is still
//! ok (e.g. hmac-sha1), so on this basis is available here.
//!
//! # Example
//!
//! ```
//! use cryptoxide::hashing::sha1;
//!
//! let digest = sha1::Context::new().update(b"hello world").finalize();
//! ```

use crate::cryptoutil::{write_u32_be, FixedBuffer};

// portable software implementation, valid for all architectures
mod reference;

const STATE_LEN: usize = 5;

/// Process one or more 64-bytes block with the SHA-1 algorithm.
///
/// `block` length must be a non-zero multiple of 64 bytes. The best
/// implementation available for the target is selected at compile time.
fn digest_block(state: &mut [u32; STATE_LEN], block: &[u8]) {
    reference::digest_block(state, block)
}

fn mk_result(st: &mut Context, rs: &mut [u8; 20]) {
    let st_h = &mut st.h;
    st.buffer
        .standard_padding(8, |d| digest_block(&mut *st_h, d));
    *st.buffer.next::<8>() = (st.processed_bytes << 3).to_be_bytes();
    digest_block(st_h, st.buffer.full_buffer());

    write_u32_be(&mut rs[0..4], st.h[0]);
    write_u32_be(&mut rs[4..8], st.h[1]);
    write_u32_be(&mut rs[8..12], st.h[2]);
    write_u32_be(&mut rs[12..16], st.h[3]);
    write_u32_be(&mut rs[16..20], st.h[4]);
}

/// Sha1 Algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha1;

impl Sha1 {
    /// Output of the hashing algorithm in bits
    pub const OUTPUT_BITS: usize = 160;
    /// The block size in bytes of the algorithm, which is the number of bytes the algorithm typically buffer
    /// before calling its compression function
    pub const BLOCK_BYTES: usize = 64;

    /// Create a new context for this algorithm
    pub const fn new() -> Context {
        Context::new()
    }
}

/// Structure representing the state of a Sha1 computation
#[derive(Clone)]
pub struct Context {
    h: [u32; STATE_LEN],
    processed_bytes: u64,
    buffer: FixedBuffer<64>,
}

const H0: u32 = 0x67452301;
const H1: u32 = 0xEFCDAB89;
const H2: u32 = 0x98BADCFE;
const H3: u32 = 0x10325476;
const H4: u32 = 0xC3D2E1F0;
const H: [u32; STATE_LEN] = [H0, H1, H2, H3, H4];

impl Context {
    /// Construct a new default SHA1 context
    pub const fn new() -> Self {
        Self {
            h: H,
            processed_bytes: 0u64,
            buffer: FixedBuffer::new(),
        }
    }

    /// Update the hashing state by adding the input bytes slice into the state
    pub fn update(mut self, input: &[u8]) -> Self {
        self.update_mut(input);
        self
    }

    /// Update in-place the hashing state by adding the input bytes slice into
    ///
    /// For the immutable version see [`update`]
    pub fn update_mut(&mut self, input: &[u8]) {
        self.processed_bytes += input.len() as u64;
        let h = &mut self.h;
        self.buffer.input(input, |d| {
            digest_block(h, d);
        });
    }

    /// Finalize the context and return an array of bytes
    ///
    /// The context is consumed by this function, to prevent buggy reuse.
    ///
    /// If the context need to be kept before finalizing, the user can clone the Context
    pub fn finalize(mut self) -> [u8; 20] {
        let mut out = [0; 20];
        mk_result(&mut self, &mut out);
        out
    }

    /// Reset the context state, as if a new context had been created
    pub fn reset(&mut self) {
        self.processed_bytes = 0;
        self.h = H;
        self.buffer.reset();
    }

    /// Same as `finalize` but do not consume the context, but instead
    /// reset it in a ready to use state.
    pub fn finalize_reset(&mut self) -> [u8; 20] {
        let mut out = [0; 20];
        mk_result(self, &mut out);
        self.reset();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{test_hashing, Test};
    use super::*;

    #[test]
    fn test() {
        let tests = [
            // Test messages from FIPS 180-1
            Test {
                input: b"abc",
                output: [
                    0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78,
                    0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D,
                ],
            },
            Test {
                input: b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                output: [
                    0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE, 0x4A, 0xA1, 0xF9,
                    0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1,
                ],
            },
            // Examples from wikipedia
            Test {
                input: b"The quick brown fox jumps over the lazy dog",
                output: [
                    0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb,
                    0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy cog",
                output: [
                    0xde, 0x9f, 0x2c, 0x7f, 0xd2, 0x5e, 0x1b, 0x3a, 0xfa, 0xd3, 0xe8, 0x5a, 0x0b,
                    0xd1, 0x7d, 0x9b, 0x10, 0x0d, 0xb4, 0xb3,
                ],
            },
        ];

        test_hashing(
            &tests,
            Sha1,
            |_| Context::new(),
            |ctx, input| ctx.update(input),
            |ctx, input| ctx.update_mut(input),
            |ctx| ctx.finalize(),
            |ctx| ctx.finalize_reset(),
            |ctx| ctx.reset(),
        )
    }

    // Multi-block known-answer test. Exercises the block-iteration loop and,
    // on aarch64, the SHA-1 crypto-extension backend. Reference digests
    // generated with `sha1sum`.
    #[test]
    fn test_multiblock() {
        // 256 bytes = 4 pre-padding SHA-1 blocks
        let msg: [u8; 256] = core::array::from_fn(|i| ((i * 7 + 3) & 0xff) as u8);

        let digest = Context::new().update(&msg).finalize();
        let expected = [
            0x6a, 0xa0, 0xe6, 0x2c, 0xd3, 0x73, 0xdc, 0x2e, 0xb2, 0xbd, 0x8d, 0x9d, 0x9e, 0xd6,
            0xe6, 0xef, 0x19, 0x6c, 0xc9, 0x31,
        ];
        assert_eq!(digest, expected);
    }
}

#[cfg(all(test, feature = "with-bench"))]
mod bench {
    use super::*;
    use test::Bencher;

    #[bench]
    pub fn sha1_block(bh: &mut Bencher) {
        let mut state = H;
        let block = [1u8; 64];
        bh.iter(|| {
            digest_block(&mut state, &block);
        });
        bh.bytes = 64u64;
    }

    #[bench]
    pub fn sha1_10(bh: &mut Bencher) {
        let mut sh = Sha1::new();
        let bytes = [1u8; 10];
        bh.iter(|| {
            sh.update_mut(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha1_1k(bh: &mut Bencher) {
        let mut sh = Sha1::new();
        let bytes = [1u8; 1024];
        bh.iter(|| {
            sh.update_mut(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha1_64k(bh: &mut Bencher) {
        let mut sh = Sha1::new();
        let bytes = [1u8; 65536];
        bh.iter(|| {
            sh.update_mut(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }
}
