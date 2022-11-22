//! Blake2S hash function
//!
//! Blake2 [Specification][1].
//!
//! # Example
//!
//! Hashing using Blake2s-256:
//!
//! ```
//! use cryptoxide::hashing::blake2s::Blake2s;
//!
//! let mut context = Blake2s::<256>::new();
//! context.update_mut(b"hello world");
//! let digest = context.finalize();
//! ```
//!
//! MAC using Blake2s-224 with 16-bytes key :
//!
//! ```
//! use cryptoxide::hashing::blake2s::Blake2s;
//!
//! let key : [u8; 16] = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
//! let mut context = Blake2s::<224>::new_keyed(&key);
//! context.update_mut(b"hello world");
//! let mac = context.finalize();
//! ```
//!
//!
//! [1]: <https://eprint.iacr.org/2013/322.pdf>

use super::blake2::{EngineS as Engine, LastBlock};
use crate::cryptoutil::{write_u32v_le, zero};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Blake2s<const BITS: usize>;

impl<const BITS: usize> Blake2s<BITS> {
    pub const OUTPUT_BITS: usize = BITS;
    pub const BLOCK_BYTES: usize = Engine::BLOCK_BYTES;

    /// Create a new context for this algorithm
    pub fn new() -> Context<BITS> {
        Context::new()
    }
    /// Create a new context with a key for this algorithm
    pub fn new_keyed(key: &[u8]) -> Context<BITS> {
        Context::new_keyed(key)
    }
}

/// Blake2s Context
#[derive(Clone)]
pub struct Context<const BITS: usize> {
    eng: Engine,
    buf: [u8; Engine::BLOCK_BYTES],
    buflen: usize,
}

/// Blake2s Context with dynamic output size determined by initial parameter
#[derive(Clone)]
pub struct ContextDyn {
    eng: Engine,
    buf: [u8; Engine::BLOCK_BYTES],
    buflen: usize,
    outlen: usize,
}

impl<const BITS: usize> Context<BITS> {
    /// Create a new Blake2s context with a specific output size in bytes
    ///
    /// the size in bytes need to be between 0 (non included) and 32 bytes (included),
    /// which means BITS need to be between 1 and 256.
    pub fn new() -> Self {
        assert!(BITS > 0 && ((BITS + 7) / 8) <= Engine::MAX_OUTLEN);
        Self::new_keyed(&[])
    }

    /// Similar to `new` but also takes a variable size key
    /// to tweak the context initialization
    pub fn new_keyed(key: &[u8]) -> Self {
        assert!(BITS > 0 && ((BITS + 7) / 8) <= Engine::MAX_OUTLEN);
        assert!(key.len() <= Engine::MAX_KEYLEN);

        let mut buf = [0u8; Engine::BLOCK_BYTES];

        let eng = Engine::new((BITS + 7) / 8, key.len());
        let buflen = if !key.is_empty() {
            buf[0..key.len()].copy_from_slice(key);
            Engine::BLOCK_BYTES
        } else {
            0
        };

        Self { eng, buf, buflen }
    }

    pub fn update(mut self, input: &[u8]) -> Self {
        self.update_mut(input);
        self
    }

    pub fn update_mut(&mut self, mut input: &[u8]) {
        if input.is_empty() {
            return;
        }
        let fill = Engine::BLOCK_BYTES - self.buflen;

        if input.len() > fill {
            self.buf[self.buflen..self.buflen + fill].copy_from_slice(&input[0..fill]);
            self.buflen = 0;
            self.eng.increment_counter(Engine::BLOCK_BYTES_NATIVE);
            self.eng
                .compress(&self.buf[0..Engine::BLOCK_BYTES], LastBlock::No);

            input = &input[fill..];

            while input.len() > Engine::BLOCK_BYTES {
                self.eng.increment_counter(Engine::BLOCK_BYTES_NATIVE);
                self.eng
                    .compress(&input[0..Engine::BLOCK_BYTES], LastBlock::No);
                input = &input[Engine::BLOCK_BYTES..];
            }
        }
        self.buf[self.buflen..self.buflen + input.len()].copy_from_slice(input);
        self.buflen += input.len();
    }

    fn internal_final(&mut self) {
        self.eng.increment_counter(self.buflen as u32);
        zero(&mut self.buf[self.buflen..]);
        self.eng
            .compress(&self.buf[0..Engine::BLOCK_BYTES], LastBlock::Yes);

        write_u32v_le(&mut self.buf[0..32], &self.eng.h);
    }

    pub fn finalize_at(mut self, out: &mut [u8]) {
        assert!(out.len() == ((BITS + 7) / 8));
        self.internal_final();
        out.copy_from_slice(&self.buf[0..out.len()]);
    }

    pub fn finalize_reset_at(&mut self, out: &mut [u8]) {
        assert!(out.len() == ((BITS + 7) / 8));
        self.internal_final();
        out.copy_from_slice(&self.buf[0..out.len()]);
        self.reset();
    }

    pub fn finalize_reset_with_key_at(&mut self, key: &[u8], out: &mut [u8]) {
        assert!(out.len() == ((BITS + 7) / 8));
        self.internal_final();
        out.copy_from_slice(&self.buf[0..out.len()]);
        self.reset_with_key(key);
    }

    /// Reset the context to the state after calling `new`
    pub fn reset(&mut self) {
        self.eng.reset((BITS + 7) / 8, 0);
        self.buflen = 0;
        zero(&mut self.buf[..]);
    }

    pub fn reset_with_key(&mut self, key: &[u8]) {
        assert!(key.len() <= Engine::MAX_KEYLEN);

        self.eng.reset((BITS + 7) / 8, key.len());
        zero(&mut self.buf[..]);

        if !key.is_empty() {
            self.buf[0..key.len()].copy_from_slice(key);
            self.buflen = Engine::BLOCK_BYTES;
        } else {
            self.buf = [0; Engine::BLOCK_BYTES];
            self.buflen = 0;
        }
    }
}

impl ContextDyn {
    /// Create a new Blake2s context with a specific output size in bytes
    ///
    /// the size in bytes need to be between 0 (non included) and 32 bytes (included),
    /// which means BITS need to be between 1 and 256.
    pub fn new(output_bytes: usize) -> Self {
        assert!(output_bytes > 0 && output_bytes <= Engine::MAX_OUTLEN);
        Self::new_keyed(output_bytes, &[])
    }

    /// Similar to `new` but also takes a variable size key
    /// to tweak the context initialization
    pub fn new_keyed(output_bytes: usize, key: &[u8]) -> Self {
        assert!(output_bytes > 0 && output_bytes <= Engine::MAX_OUTLEN);
        assert!(key.len() <= Engine::MAX_KEYLEN);

        let mut buf = [0u8; Engine::BLOCK_BYTES];

        let eng = Engine::new(output_bytes, key.len());
        let buflen = if !key.is_empty() {
            buf[0..key.len()].copy_from_slice(key);
            Engine::BLOCK_BYTES
        } else {
            0
        };

        Self {
            eng,
            buf,
            buflen,
            outlen: output_bytes,
        }
    }

    pub fn update(mut self, input: &[u8]) -> Self {
        self.update_mut(input);
        self
    }

    pub fn update_mut(&mut self, mut input: &[u8]) {
        if input.is_empty() {
            return;
        }
        let fill = Engine::BLOCK_BYTES - self.buflen;

        if input.len() > fill {
            self.buf[self.buflen..self.buflen + fill].copy_from_slice(&input[0..fill]);
            self.buflen = 0;
            self.eng.increment_counter(Engine::BLOCK_BYTES_NATIVE);
            self.eng
                .compress(&self.buf[0..Engine::BLOCK_BYTES], LastBlock::No);

            input = &input[fill..];

            while input.len() > Engine::BLOCK_BYTES {
                self.eng.increment_counter(Engine::BLOCK_BYTES_NATIVE);
                self.eng
                    .compress(&input[0..Engine::BLOCK_BYTES], LastBlock::No);
                input = &input[Engine::BLOCK_BYTES..];
            }
        }
        self.buf[self.buflen..self.buflen + input.len()].copy_from_slice(input);
        self.buflen += input.len();
    }

    fn internal_final(&mut self) {
        self.eng.increment_counter(self.buflen as u32);
        zero(&mut self.buf[self.buflen..]);
        self.eng
            .compress(&self.buf[0..Engine::BLOCK_BYTES], LastBlock::Yes);

        write_u32v_le(&mut self.buf[0..32], &self.eng.h);
    }

    pub fn finalize_at(mut self, out: &mut [u8]) {
        assert!(out.len() == self.outlen);
        self.internal_final();
        out.copy_from_slice(&self.buf[0..out.len()]);
    }

    pub fn finalize_reset_at(&mut self, out: &mut [u8]) {
        assert!(out.len() == self.outlen);
        self.internal_final();
        out.copy_from_slice(&self.buf[0..out.len()]);
        self.reset();
    }

    pub fn finalize_reset_with_key_at(&mut self, key: &[u8], out: &mut [u8]) {
        assert!(out.len() == self.outlen);
        self.internal_final();
        out.copy_from_slice(&self.buf[0..out.len()]);
        self.reset_with_key(key);
    }

    /// Reset the context to the state after calling `new`
    pub fn reset(&mut self) {
        self.eng.reset(self.outlen, 0);
        self.buflen = 0;
        zero(&mut self.buf[..]);
    }

    pub fn reset_with_key(&mut self, key: &[u8]) {
        assert!(key.len() <= Engine::MAX_KEYLEN);

        self.eng.reset(self.outlen, key.len());
        zero(&mut self.buf[..]);

        if !key.is_empty() {
            self.buf[0..key.len()].copy_from_slice(key);
            self.buflen = Engine::BLOCK_BYTES;
        } else {
            self.buf = [0; Engine::BLOCK_BYTES];
            self.buflen = 0;
        }
    }

    pub fn output_bits(&self) -> usize {
        self.outlen * 8
    }
}

// Due to limitation of const generic, we can't define finalize in the generic context, so instead
// define support for specific known size, until the limitation is lifted
macro_rules! context_finalize {
    ($size:literal) => {
        impl Context<$size> {
            pub fn finalize(self) -> [u8; $size / 8] {
                let mut out = [0; $size / 8];
                self.finalize_at(&mut out);
                out
            }
            pub fn finalize_reset(&mut self) -> [u8; $size / 8] {
                let mut out = [0; $size / 8];
                self.finalize_reset_at(&mut out);
                out
            }
            pub fn finalize_reset_with_key(&mut self, key: &[u8]) -> [u8; $size / 8] {
                let mut out = [0; $size / 8];
                self.finalize_reset_with_key_at(key, &mut out);
                out
            }
        }
    };
}
context_finalize!(224);
context_finalize!(256);

#[cfg(test)]
mod digest_tests {
    use super::super::tests::{test_hashing, Test};
    use super::{Blake2s, Context};

    #[test]
    fn test_vector() {
        let tests = [Test {
            input: b"abc",
            output: [
                80, 140, 94, 140, 50, 124, 20, 226, 225, 167, 43, 163, 78, 235, 69, 47, 55, 69,
                139, 32, 158, 214, 58, 41, 77, 153, 155, 76, 134, 103, 89, 130,
            ],
        }];

        test_hashing(
            &tests,
            Blake2s::<256>,
            |_| Context::<256>::new(),
            |ctx, input| ctx.update(input),
            |ctx, input| ctx.update_mut(input),
            |ctx| ctx.finalize(),
            |ctx| ctx.finalize_reset(),
            |ctx| ctx.reset(),
        )
    }
}

#[cfg(test)]
mod mac_tests {
    use super::super::tests::{test_hashing_keyed, TestKey};
    use super::{Blake2s, Context};

    #[test]
    fn test_mac() {
        let tests = [
            TestKey {
                input: &[1, 2, 4, 8],
                key: &[
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ],
                output: [
                    0x0e, 0x88, 0xf6, 0x8a, 0xaa, 0x5c, 0x4e, 0xd8, 0xf7, 0xed, 0x28, 0xf8, 0x04,
                    0x45, 0x01, 0x9c, 0x7e, 0xf9, 0x76, 0x2b, 0x4f, 0xf1, 0xad, 0x7e, 0x05, 0x5b,
                    0xa8, 0xc8, 0x82, 0x9e, 0xe2, 0x49,
                ],
            },
            TestKey {
                input: &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
                key: &[
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ],
                output: [
                    0xfd, 0xd8, 0x99, 0x3d, 0xcd, 0x43, 0xf6, 0x96, 0xd4, 0x4f, 0x3c, 0xea, 0x0f,
                    0xf3, 0x53, 0x45, 0x23, 0x4e, 0xc8, 0xee, 0x08, 0x3e, 0xb3, 0xca, 0xda, 0x01,
                    0x7c, 0x7f, 0x78, 0xc1, 0x71, 0x43,
                ],
            },
        ];

        test_hashing_keyed(
            &tests,
            Blake2s::<256>,
            |_, k| Context::<256>::new_keyed(k),
            |ctx, input| ctx.update(input),
            |ctx, input| ctx.update_mut(input),
            |ctx| ctx.finalize(),
            |ctx, key| ctx.finalize_reset_with_key(key),
            |ctx, key| ctx.reset_with_key(key),
        )
    }
}

#[cfg(all(test, feature = "with-bench"))]
mod bench {
    use test::Bencher;

    use super::Blake2s;

    #[bench]
    pub fn blake2s_10(bh: &mut Bencher) {
        let mut sh = Blake2s::<256>::new();
        let bytes = [1u8; 10];
        bh.iter(|| {
            sh.update_mut(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn blake2s_1k(bh: &mut Bencher) {
        let mut sh = Blake2s::<256>::new();
        let bytes = [1u8; 1024];
        bh.iter(|| {
            sh.update_mut(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn blake2s_64k(bh: &mut Bencher) {
        let mut sh = Blake2s::<256>::new();
        let bytes = [1u8; 65536];
        bh.iter(|| {
            sh.update_mut(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }
}
