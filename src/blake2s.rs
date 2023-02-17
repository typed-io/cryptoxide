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

use crate::digest::Digest;
use crate::hashing::blake2s;
use crate::mac::{Mac, MacResult};
use alloc::vec::Vec;
use core::iter::repeat;

pub type Context = blake2s::ContextDyn;

/// Blake2s Context
#[derive(Clone)]
pub struct Blake2s {
    ctx: blake2s::ContextDyn,
    computed: bool, // whether the final digest has been computed
}

impl Blake2s {
    /// Create a new Blake2s context with a specific output size in bytes
    ///
    /// the size need to be between 0 (non included) and 32 bytes (included)
    pub fn new(outlen: usize) -> Self {
        let ctx = blake2s::ContextDyn::new(outlen);
        Self {
            ctx,
            computed: false,
        }
    }

    /// Similar to `new` but also takes a variable size key
    /// to tweak the context initialization
    pub fn new_keyed(outlen: usize, key: &[u8]) -> Self {
        assert!(key.len() <= 64);
        let ctx = blake2s::ContextDyn::new_keyed(outlen, key);
        Self {
            ctx,
            computed: false,
        }
    }

    fn update(&mut self, input: &[u8]) {
        assert!(!self.computed, "context is already finalized, needs reset");
        self.ctx.update_mut(input);
    }

    fn finalize(&mut self, slice: &mut [u8]) {
        assert!(!self.computed, "context is already finalized, needs reset");
        self.ctx.finalize_reset_at(slice);
        self.computed = true;
    }

    /// Reset the context to the state after calling `new`
    pub fn reset(&mut self) {
        self.ctx.reset();
        self.computed = false;
    }

    pub fn reset_with_key(&mut self, key: &[u8]) {
        self.ctx.reset_with_key(key);
        self.computed = false;
    }

    pub fn blake2s(out: &mut [u8], input: &[u8], key: &[u8]) {
        let mut hasher: Blake2s = if !key.is_empty() {
            Blake2s::new_keyed(out.len(), key)
        } else {
            Blake2s::new(out.len())
        };

        hasher.update(input);
        hasher.finalize(out);
    }
}

impl Digest for Blake2s {
    fn input(&mut self, msg: &[u8]) {
        self.update(msg);
    }
    fn reset(&mut self) {
        Blake2s::reset(self);
    }
    fn result(&mut self, out: &mut [u8]) {
        self.finalize(out);
    }
    fn output_bits(&self) -> usize {
        self.ctx.output_bits()
    }
    fn block_size(&self) -> usize {
        // hack : this is a constant, not related to the number of bit
        blake2s::Blake2s::<0>::BLOCK_BYTES
    }
}

impl Mac for Blake2s {
    fn input(&mut self, data: &[u8]) {
        self.update(data);
    }

    fn reset(&mut self) {
        Blake2s::reset(self);
    }

    fn result(&mut self) -> MacResult {
        let mut mac: Vec<u8> = repeat(0).take(self.ctx.output_bits() / 8).collect();
        self.raw_result(&mut mac);
        MacResult::new_from_owned(mac)
    }

    fn raw_result(&mut self, output: &mut [u8]) {
        self.finalize(output);
    }

    fn output_bytes(&self) -> usize {
        self.ctx.output_bits() / 8
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
        let mut m = Blake2s::new_keyed(32, &key[..]);
        m.input(&[1, 2, 4, 8]);
        let expected = [
            0x0e, 0x88, 0xf6, 0x8a, 0xaa, 0x5c, 0x4e, 0xd8, 0xf7, 0xed, 0x28, 0xf8, 0x04, 0x45,
            0x01, 0x9c, 0x7e, 0xf9, 0x76, 0x2b, 0x4f, 0xf1, 0xad, 0x7e, 0x05, 0x5b, 0xa8, 0xc8,
            0x82, 0x9e, 0xe2, 0x49,
        ];
        assert_eq!(m.result().code().to_vec(), expected.to_vec());
    }
}
