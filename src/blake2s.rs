//! Blake2S hash function
//!
//! Blake2 [Specification][1].
//!
//! # Example
//!
//! Hashing using Blake2s-256:
//!
//! ```
//! use cryptoxide::{digest::Digest, blake2s::Blake2s};
//!
//! let mut digest = [0u8; 32];
//! let mut context = Blake2s::new(32);
//! context.input(b"hello world");
//! context.result(&mut digest);
//! ```
//!
//! MAC using Blake2s-224 with 16-bytes key :
//!
//! ```
//! use cryptoxide::{mac::Mac, blake2s::Blake2s};
//!
//! let key : [u8; 16] = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
//! let mut context = Blake2s::new_keyed(28, &key);
//! context.input(b"hello world");
//! let mac = context.result();
//! ```
//!
//!
//! [1]: <https://eprint.iacr.org/2013/322.pdf>

use crate::blake2::{EngineS as Engine, LastBlock};
use crate::cryptoutil::{write_u32v_le, zero};
use crate::digest::Digest;
use crate::mac::{Mac, MacResult};
use alloc::vec::Vec;
use core::iter::repeat;

/// Blake2s Context
#[derive(Clone)]
pub struct Blake2s<const BITS: usize> {
    eng: Engine,
    buf: [u8; Engine::BLOCK_BYTES],
    buflen: usize,
    computed: bool, // whether the final digest has been computed
}

impl<const BITS: usize> Blake2s<BITS> {
    /// Create a new Blake2s context with a specific output size in bytes
    ///
    /// the size need to be between 0 (non included) and 32 bytes (included)
    pub fn new() -> Self {
        assert!(BITS > 0 && (BITS / 8) <= Engine::MAX_OUTLEN);
        Self::new_keyed(&[])
    }

    /// Similar to `new` but also takes a variable size key
    /// to tweak the context initialization
    pub fn new_keyed(key: &[u8]) -> Self {
        assert!(BITS > 0 && (BITS / 8) <= Engine::MAX_OUTLEN);
        assert!(key.len() <= Engine::MAX_KEYLEN);

        let mut buf = [0u8; Engine::BLOCK_BYTES];

        let eng = Engine::new(BITS / 8, key.len());
        let buflen = if !key.is_empty() {
            buf[0..key.len()].copy_from_slice(key);
            Engine::BLOCK_BYTES
        } else {
            0
        };

        Blake2s {
            eng,
            buf,
            buflen,
            computed: false,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
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

    fn finalize(&mut self, out: &mut [u8]) {
        assert!(out.len() == ((BITS + 7) / 8));
        if !self.computed {
            self.eng.increment_counter(self.buflen as u32);
            zero(&mut self.buf[self.buflen..]);
            self.eng
                .compress(&self.buf[0..Engine::BLOCK_BYTES], LastBlock::Yes);

            write_u32v_le(&mut self.buf[0..32], &self.eng.h);
            self.computed = true;
        }
        out.copy_from_slice(&self.buf[0..out.len()]);
    }

    /// Reset the context to the state after calling `new`
    pub fn reset(&mut self) {
        self.eng.reset((BITS + 7) / 8, 0);
        self.computed = false;
        self.buflen = 0;
        zero(&mut self.buf[..]);
    }

    pub fn reset_with_key(&mut self, key: &[u8]) {
        assert!(key.len() <= Engine::MAX_KEYLEN);

        self.eng.reset((BITS + 7) / 8, key.len());
        self.computed = false;
        zero(&mut self.buf[..]);

        if !key.is_empty() {
            self.buf[0..key.len()].copy_from_slice(key);
            self.buflen = Engine::BLOCK_BYTES;
        } else {
            self.buf = [0; Engine::BLOCK_BYTES];
            self.buflen = 0;
        }
    }

    pub fn blake2s(out: &mut [u8], input: &[u8], key: &[u8]) {
        let mut hasher: Self = if !key.is_empty() {
            Blake2s::new_keyed(key)
        } else {
            Blake2s::new()
        };

        hasher.update(input);
        hasher.finalize(out);
    }
}

impl<const BITS: usize> Digest for Blake2s<BITS> {
    const OUTPUT_BITS: usize = BITS;

    fn input(&mut self, msg: &[u8]) {
        self.update(msg);
    }
    fn reset(&mut self) {
        Blake2s::reset(self);
    }
    fn result(&mut self, out: &mut [u8]) {
        self.finalize(out);
    }
    fn block_size(&self) -> usize {
        Engine::BLOCK_BYTES
    }
}

impl<const BITS: usize> Mac for Blake2s<BITS> {
    fn input(&mut self, data: &[u8]) {
        self.update(data);
    }

    fn reset(&mut self) {
        Blake2s::reset(self);
    }

    fn result(&mut self) -> MacResult {
        let mut mac: Vec<u8> = repeat(0).take((BITS + 7) / 8).collect();
        self.raw_result(&mut mac);
        MacResult::new_from_owned(mac)
    }

    fn raw_result(&mut self, output: &mut [u8]) {
        self.finalize(output);
    }

    fn output_bytes(&self) -> usize {
        (BITS + 7) / 8
    }
}

#[cfg(test)]
mod digest_tests {
    use super::Blake2s;
    use crate::digest::Digest;
    use alloc::vec::Vec;

    struct Test {
        input: Vec<u8>,
        output: Vec<u8>,
        key: Option<Vec<u8>>,
    }

    fn test_hash(tests: &[Test]) {
        for t in tests {
            let mut sh = match t.key {
                Some(ref key) => Blake2s::<256>::new_keyed(&key),
                None => Blake2s::new(),
            };

            // Test that it works when accepting the message all at once
            sh.input(&t.input[..]);

            let mut out = [0u8; 32];
            sh.result(&mut out);
            assert_eq!(&out[..], &t.output[..]);

            match t.key {
                Some(ref key) => sh.reset_with_key(&key),
                None => sh.reset(),
            };

            // Test that it works when accepting the message in pieces
            let len = t.input.len();
            let mut left = len;
            while left > 0 {
                let take = (left + 1) / 2;
                sh.input(&t.input[len - left..take + len - left]);
                left -= take;
            }

            let mut out = [0u8; 32];
            sh.result(&mut out);
            assert_eq!(&out[..], &t.output[..]);

            match t.key {
                Some(ref key) => sh.reset_with_key(&key),
                None => sh.reset(),
            };
        }
    }

    #[test]
    fn test_blake2s_digest() {
        let tests = vec![
            // from: https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2s-test.txt
            Test {
                input: vec![
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                    0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
                    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
                    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
                    0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
                    0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                    0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
                    0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81,
                    0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
                    0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
                    0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
                    0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
                    0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2,
                    0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
                    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc,
                    0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
                    0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6,
                    0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
                ],
                output: vec![
                    0x3f, 0xb7, 0x35, 0x06, 0x1a, 0xbc, 0x51, 0x9d, 0xfe, 0x97, 0x9e, 0x54, 0xc1,
                    0xee, 0x5b, 0xfa, 0xd0, 0xa9, 0xd8, 0x58, 0xb3, 0x31, 0x5b, 0xad, 0x34, 0xbd,
                    0xe9, 0x99, 0xef, 0xd7, 0x24, 0xdd,
                ],
                key: Some(vec![
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                ]),
            },
        ];

        test_hash(&tests[..]);
    }
}

#[cfg(test)]
mod mac_tests {
    use super::Blake2s;
    use crate::mac::Mac;

    #[test]
    fn test_blake2s_mac() {
        let key: [u8; 32] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let mut m = Blake2s::<256>::new_keyed(&key[..]);
        m.input(&[1, 2, 4, 8]);
        let expected = [
            0x0e, 0x88, 0xf6, 0x8a, 0xaa, 0x5c, 0x4e, 0xd8, 0xf7, 0xed, 0x28, 0xf8, 0x04, 0x45,
            0x01, 0x9c, 0x7e, 0xf9, 0x76, 0x2b, 0x4f, 0xf1, 0xad, 0x7e, 0x05, 0x5b, 0xa8, 0xc8,
            0x82, 0x9e, 0xe2, 0x49,
        ];
        assert_eq!(m.result().code().to_vec(), expected.to_vec());
    }
}

#[cfg(all(test, feature = "with-bench"))]
mod bench {
    use test::Bencher;

    use super::Blake2s;
    use crate::digest::Digest;

    #[bench]
    pub fn blake2s_10(bh: &mut Bencher) {
        let mut sh = Blake2s::new(32);
        let bytes = [1u8; 10];
        bh.iter(|| {
            sh.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn blake2s_1k(bh: &mut Bencher) {
        let mut sh = Blake2s::new(32);
        let bytes = [1u8; 1024];
        bh.iter(|| {
            sh.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn blake2s_64k(bh: &mut Bencher) {
        let mut sh = Blake2s::new(32);
        let bytes = [1u8; 65536];
        bh.iter(|| {
            sh.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }
}
