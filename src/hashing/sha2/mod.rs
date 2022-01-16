//! An implementation of the SHA-2 cryptographic hash algorithms.
//!
//! There are 6 standard algorithms specified in the SHA-2 standard:
//!
//!  * `Sha224`, which is the 32-bit `Sha256` algorithm with the result truncated to 224 bits.
//!  * `Sha256`, which is the 32-bit `Sha256` algorithm.
//!  * `Sha384`, which is the 64-bit `Sha512` algorithm with the result truncated to 384 bits.
//!  * `Sha512`, which is the 64-bit `Sha512` algorithm.
//!  * `Sha512Trunc224`, which is the 64-bit `Sha512` algorithm with the result truncated to 224 bits.
//!  * `Sha512Trunc256`, which is the 64-bit `Sha512` algorithm with the result truncated to 256 bits.
//!
//! Algorithmically, there are only 2 core algorithms: `Sha256` and `Sha512`.
//! All other algorithms are just applications of these with different initial hash
//! values, and truncated to different digest bit lengths.
//!
//! # Usage
//!
//! An example of using `Sha256` is:
//!
//! ```rust
//! use cryptoxide::hashing::sha2::Sha256;
//!
//! // create a Sha256 object
//! let mut context = Sha256::new();
//!
//! // write input message
//! context.update_mut(b"hello world");
//!
//! // read hash digest
//! let output = context.finalize();
//! ```
//!
//! An example of using `Sha512` is:
//!
//! ```rust
//! use cryptoxide::hashing::sha2::Sha512;
//!
//! // create a Sha512 object
//! let mut context = Sha512::new();
//!
//! // write input message
//! context.update_mut(b"hello world");
//!
//! // read hash digest
//! let output = context.finalize();
//! ```

mod eng256;
mod eng512;
mod impl256;
mod impl512;
mod initials;

use crate::cryptoutil::FixedBuffer;
use initials::*;

macro_rules! digest {
    (256 $name:ident, $ctxname:ident, $output_fn: ident, $output_bits:expr, $state:ident) => {
        digest!(
            @internal
            $name,
            $ctxname,
            Engine256,
            $output_fn,
            $output_bits,
            64,
            $state
        );
    };
    (512 $name:ident, $ctxname:ident, $output_fn:ident, $output_bits:expr, $state:ident) => {
        digest!(
            @internal
            $name,
            $ctxname,
            Engine512,
            $output_fn,
            $output_bits,
            128,
            $state
        );
    };
    (@internal $name:ident, $ctxname:ident, $init:ident, $output_fn:ident, $output_bits:expr, $block_size:literal, $state: ident) => {
        /// Hash Algorithm
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name;

        impl $name {
            pub const OUTPUT_BITS: usize = $output_bits;
            pub const BLOCK_BYTES: usize = $block_size;

            /// Create a new context for this algorithm
            pub fn new() -> $ctxname {
                $ctxname::new()
            }
        }

        /// The hash algorithm context
        #[derive(Clone)]
        pub struct $ctxname {
            engine: $init,
        }

        impl $ctxname {
            /// Create a new hashing algorithm context
            pub const fn new() -> Self {
                Self {
                    engine: $init::new(&$state),
                }
            }

            pub fn update_mut(&mut self, input: &[u8]) {
                self.engine.input(input)
            }

            pub fn update(mut self, input: &[u8]) -> Self {
                self.engine.input(input);
                self
            }

            pub fn finalize(mut self) -> [u8; $output_bits / 8] {
                let mut out = [0; $output_bits / 8];
                self.engine.finish();
                self.engine.state.$output_fn(&mut out);
                out
            }

            pub fn finalize_reset(&mut self) -> [u8; $output_bits / 8] {
                let mut out = [0; $output_bits / 8];
                self.engine.finish();
                self.engine.state.$output_fn(&mut out);
                self.reset();
                out
            }

            pub fn reset(&mut self) {
                self.engine.reset(&$state);
            }
        }
    };
}

// A structure that keeps track of the state of the Sha-512 operation and contains the logic
// necessary to perform the final calculations.
#[derive(Clone)]
struct Engine512 {
    processed_bytes: u128,
    buffer: FixedBuffer<128>,
    state: eng512::Engine,
}

impl Engine512 {
    const fn new(h: &[u64; eng512::STATE_LEN]) -> Engine512 {
        Engine512 {
            processed_bytes: 0,
            buffer: FixedBuffer::new(),
            state: eng512::Engine::new(h),
        }
    }

    fn reset(&mut self, h: &[u64; eng512::STATE_LEN]) {
        self.processed_bytes = 0;
        self.buffer.reset();
        self.state.reset(h);
    }

    fn input(&mut self, input: &[u8]) {
        self.processed_bytes += input.len() as u128;
        let self_state = &mut self.state;
        self.buffer.input(input, |input| self_state.blocks(input));
    }

    fn finish(&mut self) {
        let self_state = &mut self.state;
        self.buffer
            .standard_padding(16, |input| self_state.blocks(input));
        *self.buffer.next::<16>() = (self.processed_bytes << 3).to_be_bytes();
        self.state.blocks(self.buffer.full_buffer());
    }
}

// A structure that keeps track of the state of the Sha-256 operation and contains the logic
// necessary to perform the final calculations.
#[derive(Clone)]
struct Engine256 {
    processed_bytes: u64,
    buffer: FixedBuffer<64>,
    state: eng256::Engine,
    finished: bool,
}

impl Engine256 {
    const fn new(h: &[u32; eng256::STATE_LEN]) -> Engine256 {
        Engine256 {
            processed_bytes: 0,
            buffer: FixedBuffer::new(),
            state: eng256::Engine::new(h),
            finished: false,
        }
    }

    fn reset(&mut self, h: &[u32; eng256::STATE_LEN]) {
        self.processed_bytes = 0;
        self.buffer.reset();
        self.state.reset(h);
        self.finished = false;
    }

    fn input(&mut self, input: &[u8]) {
        assert!(!self.finished);
        self.processed_bytes += input.len() as u64;
        let self_state = &mut self.state;
        self.buffer.input(input, |input| self_state.blocks(input));
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }

        let self_state = &mut self.state;
        self.buffer
            .standard_padding(8, |input| self_state.blocks(input));
        *self.buffer.next::<8>() = (self.processed_bytes << 3).to_be_bytes();
        self.state.blocks(self.buffer.full_buffer());

        self.finished = true;
    }
}

digest!(512 Sha512, Context512, output_512bits_at, 512, H512);
digest!(512 Sha384, Context384, output_384bits_at, 384, H384);
digest!(
    512
    Sha512Trunc256,
    Context512_256,
    output_256bits_at,
    256,
    H512_TRUNC_256
);
digest!(
    512
    Sha512Trunc224,
    Context512_224,
    output_224bits_at,
    224,
    H512_TRUNC_224
);
digest!(256 Sha256, Context256, output_256bits_at, 256, H256);
digest!(256 Sha224, Context224, output_224bits_at, 224, H224);

#[cfg(test)]
mod tests {
    use super::super::tests::{test_hashing, Test};
    use super::*;

    #[test]
    fn test_sha512() {
        // Examples from wikipedia
        let tests = [
            Test {
                input: b"",
                output: [
                    0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6,
                    0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4,
                    0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2,
                    0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd,
                    0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog",
                output: [
                    0x07, 0xe5, 0x47, 0xd9, 0x58, 0x6f, 0x6a, 0x73, 0xf7, 0x3f, 0xba, 0xc0, 0x43,
                    0x5e, 0xd7, 0x69, 0x51, 0x21, 0x8f, 0xb7, 0xd0, 0xc8, 0xd7, 0x88, 0xa3, 0x09,
                    0xd7, 0x85, 0x43, 0x6b, 0xbb, 0x64, 0x2e, 0x93, 0xa2, 0x52, 0xa9, 0x54, 0xf2,
                    0x39, 0x12, 0x54, 0x7d, 0x1e, 0x8a, 0x3b, 0x5e, 0xd6, 0xe1, 0xbf, 0xd7, 0x09,
                    0x78, 0x21, 0x23, 0x3f, 0xa0, 0x53, 0x8f, 0x3d, 0xb8, 0x54, 0xfe, 0xe6,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog.",
                output: [
                    0x91, 0xea, 0x12, 0x45, 0xf2, 0x0d, 0x46, 0xae, 0x9a, 0x03, 0x7a, 0x98, 0x9f,
                    0x54, 0xf1, 0xf7, 0x90, 0xf0, 0xa4, 0x76, 0x07, 0xee, 0xb8, 0xa1, 0x4d, 0x12,
                    0x89, 0x0c, 0xea, 0x77, 0xa1, 0xbb, 0xc6, 0xc7, 0xed, 0x9c, 0xf2, 0x05, 0xe6,
                    0x7b, 0x7f, 0x2b, 0x8f, 0xd4, 0xc7, 0xdf, 0xd3, 0xa7, 0xa8, 0x61, 0x7e, 0x45,
                    0xf3, 0xc4, 0x63, 0xd4, 0x81, 0xc7, 0xe5, 0x86, 0xc3, 0x9a, 0xc1, 0xed,
                ],
            },
        ];
        test_hashing(
            &tests,
            Sha512,
            |_| Context512::new(),
            |ctx, input| ctx.update(input),
            |ctx, input| ctx.update_mut(input),
            |ctx| ctx.finalize(),
            |ctx| ctx.finalize_reset(),
            |ctx| ctx.reset(),
        )
    }

    #[test]
    fn test_sha384() {
        // Examples from wikipedia
        let tests = [
            Test {
                input: b"",
                output: [
                    0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1,
                    0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c,
                    0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65,
                    0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog",
                output: [
                    0xca, 0x73, 0x7f, 0x10, 0x14, 0xa4, 0x8f, 0x4c, 0x0b, 0x6d, 0xd4, 0x3c, 0xb1,
                    0x77, 0xb0, 0xaf, 0xd9, 0xe5, 0x16, 0x93, 0x67, 0x54, 0x4c, 0x49, 0x40, 0x11,
                    0xe3, 0x31, 0x7d, 0xbf, 0x9a, 0x50, 0x9c, 0xb1, 0xe5, 0xdc, 0x1e, 0x85, 0xa9,
                    0x41, 0xbb, 0xee, 0x3d, 0x7f, 0x2a, 0xfb, 0xc9, 0xb1,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog.",
                output: [
                    0xed, 0x89, 0x24, 0x81, 0xd8, 0x27, 0x2c, 0xa6, 0xdf, 0x37, 0x0b, 0xf7, 0x06,
                    0xe4, 0xd7, 0xbc, 0x1b, 0x57, 0x39, 0xfa, 0x21, 0x77, 0xaa, 0xe6, 0xc5, 0x0e,
                    0x94, 0x66, 0x78, 0x71, 0x8f, 0xc6, 0x7a, 0x7a, 0xf2, 0x81, 0x9a, 0x02, 0x1c,
                    0x2f, 0xc3, 0x4e, 0x91, 0xbd, 0xb6, 0x34, 0x09, 0xd7,
                ],
            },
        ];
        test_hashing(
            &tests,
            Sha384,
            |_| Context384::new(),
            |ctx, input| ctx.update(input),
            |ctx, input| ctx.update_mut(input),
            |ctx| ctx.finalize(),
            |ctx| ctx.finalize_reset(),
            |ctx| ctx.reset(),
        )
    }

    #[test]
    fn test_sha512_256() {
        // Examples from wikipedia
        let tests = [
            Test {
                input: b"",
                output: [
                    0xc6, 0x72, 0xb8, 0xd1, 0xef, 0x56, 0xed, 0x28, 0xab, 0x87, 0xc3, 0x62, 0x2c,
                    0x51, 0x14, 0x06, 0x9b, 0xdd, 0x3a, 0xd7, 0xb8, 0xf9, 0x73, 0x74, 0x98, 0xd0,
                    0xc0, 0x1e, 0xce, 0xf0, 0x96, 0x7a,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog",
                output: [
                    0xdd, 0x9d, 0x67, 0xb3, 0x71, 0x51, 0x9c, 0x33, 0x9e, 0xd8, 0xdb, 0xd2, 0x5a,
                    0xf9, 0x0e, 0x97, 0x6a, 0x1e, 0xee, 0xfd, 0x4a, 0xd3, 0xd8, 0x89, 0x00, 0x5e,
                    0x53, 0x2f, 0xc5, 0xbe, 0xf0, 0x4d,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog.",
                output: [
                    0x15, 0x46, 0x74, 0x18, 0x40, 0xf8, 0xa4, 0x92, 0xb9, 0x59, 0xd9, 0xb8, 0xb2,
                    0x34, 0x4b, 0x9b, 0x0e, 0xb5, 0x1b, 0x00, 0x4b, 0xba, 0x35, 0xc0, 0xae, 0xba,
                    0xac, 0x86, 0xd4, 0x52, 0x64, 0xc3,
                ],
            },
        ];
        test_hashing(
            &tests,
            Sha512Trunc256,
            |_| Context512_256::new(),
            |ctx, input| ctx.update(input),
            |ctx, input| ctx.update_mut(input),
            |ctx| ctx.finalize(),
            |ctx| ctx.finalize_reset(),
            |ctx| ctx.reset(),
        )
    }

    #[test]
    fn test_sha512_224() {
        // Examples from wikipedia
        let tests = [
            Test {
                input: b"",
                output: [
                    0x6e, 0xd0, 0xdd, 0x02, 0x80, 0x6f, 0xa8, 0x9e, 0x25, 0xde, 0x06, 0x0c, 0x19,
                    0xd3, 0xac, 0x86, 0xca, 0xbb, 0x87, 0xd6, 0xa0, 0xdd, 0xd0, 0x5c, 0x33, 0x3b,
                    0x84, 0xf4,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog",
                output: [
                    0x94, 0x4c, 0xd2, 0x84, 0x7f, 0xb5, 0x45, 0x58, 0xd4, 0x77, 0x5d, 0xb0, 0x48,
                    0x5a, 0x50, 0x00, 0x31, 0x11, 0xc8, 0xe5, 0xda, 0xa6, 0x3f, 0xe7, 0x22, 0xc6,
                    0xaa, 0x37,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog.",
                output: [
                    0x6d, 0x6a, 0x92, 0x79, 0x49, 0x5e, 0xc4, 0x06, 0x17, 0x69, 0x75, 0x2e, 0x7f,
                    0xf9, 0xc6, 0x8b, 0x6b, 0x0b, 0x3c, 0x5a, 0x28, 0x1b, 0x79, 0x17, 0xce, 0x05,
                    0x72, 0xde,
                ],
            },
        ];
        test_hashing(
            &tests,
            Sha512Trunc224,
            |_| Context512_224::new(),
            |ctx, input| ctx.update(input),
            |ctx, input| ctx.update_mut(input),
            |ctx| ctx.finalize(),
            |ctx| ctx.finalize_reset(),
            |ctx| ctx.reset(),
        )
    }

    #[test]
    fn test_sha256() {
        // Examples from wikipedia
        let tests = [
            Test {
                input: b"",
                output: [
                    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99,
                    0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95,
                    0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog",
                output: [
                    0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0,
                    0x08, 0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02,
                    0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog.",
                output: [
                    0xef, 0x53, 0x7f, 0x25, 0xc8, 0x95, 0xbf, 0xa7, 0x82, 0x52, 0x65, 0x29, 0xa9,
                    0xb6, 0x3d, 0x97, 0xaa, 0x63, 0x15, 0x64, 0xd5, 0xd7, 0x89, 0xc2, 0xb7, 0x65,
                    0x44, 0x8c, 0x86, 0x35, 0xfb, 0x6c,
                ],
            },
        ];
        test_hashing(
            &tests,
            Sha256,
            |_| Context256::new(),
            |ctx, input| ctx.update(input),
            |ctx, input| ctx.update_mut(input),
            |ctx| ctx.finalize(),
            |ctx| ctx.finalize_reset(),
            |ctx| ctx.reset(),
        )
    }

    #[test]
    fn test_sha224() {
        // Examples from wikipedia
        let tests = [
            Test {
                input: b"",
                output: [
                    0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9, 0x47, 0x61, 0x02, 0xbb, 0x28,
                    0x82, 0x34, 0xc4, 0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a, 0xc5, 0xb3,
                    0xe4, 0x2f,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog",
                output: [
                    0x73, 0x0e, 0x10, 0x9b, 0xd7, 0xa8, 0xa3, 0x2b, 0x1c, 0xb9, 0xd9, 0xa0, 0x9a,
                    0xa2, 0x32, 0x5d, 0x24, 0x30, 0x58, 0x7d, 0xdb, 0xc0, 0xc3, 0x8b, 0xad, 0x91,
                    0x15, 0x25,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog.",
                output: [
                    0x61, 0x9c, 0xba, 0x8e, 0x8e, 0x05, 0x82, 0x6e, 0x9b, 0x8c, 0x51, 0x9c, 0x0a,
                    0x5c, 0x68, 0xf4, 0xfb, 0x65, 0x3e, 0x8a, 0x3d, 0x8a, 0xa0, 0x4b, 0xb2, 0xc8,
                    0xcd, 0x4c,
                ],
            },
        ];
        test_hashing(
            &tests,
            Sha224,
            |_| Context224::new(),
            |ctx, input| ctx.update(input),
            |ctx, input| ctx.update_mut(input),
            |ctx| ctx.finalize(),
            |ctx| ctx.finalize_reset(),
            |ctx| ctx.reset(),
        )
    }
}

#[cfg(all(test, feature = "with-bench"))]
mod bench {
    use super::eng256;
    use super::eng512;
    use super::{Sha256, Sha512};
    use test::Bencher;

    #[bench]
    pub fn sha256_block(bh: &mut Bencher) {
        let mut state = eng256::Engine::new(&[0u32; eng256::STATE_LEN]);
        let block = [1u8; 64];
        bh.iter(|| {
            state.blocks(&block);
        });
        bh.bytes = 64u64;
    }

    #[bench]
    pub fn sha512_block(bh: &mut Bencher) {
        let mut state = eng512::Engine::new(&[0u64; eng512::STATE_LEN]);
        let block = [1u8; 128];
        bh.iter(|| {
            state.blocks(&block);
        });
        bh.bytes = 128u64;
    }

    #[bench]
    pub fn sha256_10(bh: &mut Bencher) {
        let mut sh = Sha256::new();
        let bytes = [1u8; 10];
        bh.iter(|| {
            sh.update_mut(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha256_1k(bh: &mut Bencher) {
        let mut sh = Sha256::new();
        let bytes = [1u8; 1000];
        bh.iter(|| {
            sh.update_mut(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha256_64k(bh: &mut Bencher) {
        let mut sh = Sha256::new();
        let bytes = [1u8; 65536];
        bh.iter(|| {
            sh.update_mut(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha512_10(bh: &mut Bencher) {
        let mut sh = Sha512::new();
        let bytes = [1u8; 10];
        bh.iter(|| {
            sh.update_mut(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha512_1k(bh: &mut Bencher) {
        let mut sh = Sha512::new();
        let bytes = [1u8; 1024];
        bh.iter(|| {
            sh.update_mut(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha512_64k(bh: &mut Bencher) {
        let mut sh = Sha512::new();
        let bytes = [1u8; 65536];
        bh.iter(|| {
            sh.update_mut(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }
}
