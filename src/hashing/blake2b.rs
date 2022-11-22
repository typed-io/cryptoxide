//! Blake2B hash function
//!
//! Blake2 [Specification][1].
//!
//! # Example
//!
//! Hashing using Blake2b-256:
//!
//! ```
//! use cryptoxide::hashing::blake2b::Blake2b;
//!
//! let mut context = Blake2b::<256>::new();
//! context.update_mut(b"hello world");
//! let digest = context.finalize();
//! ```
//!
//! MAC using Blake2b-224 with 16-bytes key :
//!
//! ```
//! use cryptoxide::hashing::blake2b::Blake2b;
//!
//! let key : [u8; 16] = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
//! let mut context = Blake2b::<224>::new_keyed(&key);
//! context.update_mut(b"hello world");
//! let mac = context.finalize();
//! ```
//!
//!
//! [1]: <https://eprint.iacr.org/2013/322.pdf>

use super::blake2::{EngineB as Engine, LastBlock};
use crate::cryptoutil::{write_u64v_le, zero};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Blake2b<const BITS: usize>;

impl<const BITS: usize> Blake2b<BITS> {
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

/// Blake2b Context
#[derive(Clone)]
pub struct Context<const BITS: usize> {
    eng: Engine,
    buf: [u8; Engine::BLOCK_BYTES],
    buflen: usize,
}

/// Blake2b Context with dynamic output size determined by initial parameter
#[derive(Clone)]
pub struct ContextDyn {
    eng: Engine,
    buf: [u8; Engine::BLOCK_BYTES],
    buflen: usize,
    outlen: usize,
}

impl<const BITS: usize> Context<BITS> {
    /// Create a new Blake2b context with a specific output size in bytes
    ///
    /// the size in bytes need to be between 0 (non included) and 64 bytes (included),
    /// which means BITS need to be between 1 and 512.
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
        self.eng.increment_counter(self.buflen as u64);
        zero(&mut self.buf[self.buflen..]);
        self.eng
            .compress(&self.buf[0..Engine::BLOCK_BYTES], LastBlock::Yes);

        write_u64v_le(&mut self.buf[0..64], &self.eng.h);
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
    /// Create a new Blake2b context with a specific output size in bytes defined by parameter
    ///
    /// the size need to be between 0 (non included) and 64 bytes (included)
    pub fn new(output_bytes: usize) -> Self {
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
        self.eng.increment_counter(self.buflen as u64);
        zero(&mut self.buf[self.buflen..]);
        self.eng
            .compress(&self.buf[0..Engine::BLOCK_BYTES], LastBlock::Yes);

        write_u64v_le(&mut self.buf[0..64], &self.eng.h);
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
context_finalize!(384);
context_finalize!(512);

#[cfg(test)]
mod digest_tests {
    use super::super::tests::{test_hashing, Test};
    use super::{Blake2b, Context};

    #[test]
    fn test_vector() {
        let tests = [Test {
            input: b"abc",
            output: [
                0xBA, 0x80, 0xA5, 0x3F, 0x98, 0x1C, 0x4D, 0x0D, 0x6A, 0x27, 0x97, 0xB6, 0x9F, 0x12,
                0xF6, 0xE9, 0x4C, 0x21, 0x2F, 0x14, 0x68, 0x5A, 0xC4, 0xB7, 0x4B, 0x12, 0xBB, 0x6F,
                0xDB, 0xFF, 0xA2, 0xD1, 0x7D, 0x87, 0xC5, 0x39, 0x2A, 0xAB, 0x79, 0x2D, 0xC2, 0x52,
                0xD5, 0xDE, 0x45, 0x33, 0xCC, 0x95, 0x18, 0xD3, 0x8A, 0xA8, 0xDB, 0xF1, 0x92, 0x5A,
                0xB9, 0x23, 0x86, 0xED, 0xD4, 0x00, 0x99, 0x23,
            ],
        }];

        test_hashing(
            &tests,
            Blake2b::<512>,
            |_| Context::<512>::new(),
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
    use super::{Blake2b, Context};

    #[test]
    fn test_blake2b_mac() {
        let tests = [TestKey {
            input: &[1, 2, 4, 8],
            key: &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
                44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
            ],
            output: [
                0x8e, 0xc6, 0xcb, 0x71, 0xc4, 0x5c, 0x3c, 0x90, 0x91, 0xd0, 0x8a, 0x37, 0x1e, 0xa8,
                0x5d, 0xc1, 0x22, 0xb5, 0xc8, 0xe2, 0xd9, 0xe5, 0x71, 0x42, 0xbf, 0xef, 0xce, 0x42,
                0xd7, 0xbc, 0xf8, 0x8b, 0xb0, 0x31, 0x27, 0x88, 0x2e, 0x51, 0xa9, 0x21, 0x44, 0x62,
                0x08, 0xf6, 0xa3, 0x58, 0xa9, 0xe0, 0x7d, 0x35, 0x3b, 0xd3, 0x1c, 0x41, 0x70, 0x15,
                0x62, 0xac, 0xd5, 0x39, 0x4e, 0xee, 0x73, 0xae,
            ],
        }];

        test_hashing_keyed(
            &tests,
            Blake2b::<512>,
            |_, k| Context::<512>::new_keyed(k),
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

    use super::Blake2b;

    #[bench]
    pub fn blake2b_10(bh: &mut Bencher) {
        let mut sh = Blake2b::<512>::new();
        let bytes = [1u8; 10];
        bh.iter(|| {
            sh.update_mut(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn blake2b_1k(bh: &mut Bencher) {
        let mut sh = Blake2b::<512>::new();
        let bytes = [1u8; 1024];
        bh.iter(|| {
            sh.update_mut(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn blake2b_64k(bh: &mut Bencher) {
        let mut sh = Blake2b::<512>::new();
        let bytes = [1u8; 65536];
        bh.iter(|| {
            sh.update_mut(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }
}
