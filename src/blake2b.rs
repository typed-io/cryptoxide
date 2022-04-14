//! Blake2B hash function
//!
//! Blake2 [Specification][1].
//!
//! # Example
//!
//! Hashing using Blake2b-256:
//!
//! ```
//! use cryptoxide::{digest::Digest, blake2b::Blake2b};
//!
//! let mut digest = [0u8; 32];
//! let mut context = Blake2b::new(32);
//! context.input(b"hello world");
//! context.result(&mut digest);
//! ```
//!
//! MAC using Blake2b-224 with 16-bytes key :
//!
//! ```
//! use cryptoxide::{mac::Mac, blake2b::Blake2b};
//!
//! let key : [u8; 16] = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
//! let mut context = Blake2b::new_keyed(28, &key);
//! context.input(b"hello world");
//! let mac = context.result();
//! ```
//!
//!
//! [1]: <https://eprint.iacr.org/2013/322.pdf>

use crate::digest::Digest;
use crate::hashing::blake2b;
use crate::mac::{Mac, MacResult};
use alloc::vec::Vec;
use core::iter::repeat;

#[derive(Clone)]
pub enum Context {
    Context8(blake2b::Context<8>),
    Context16(blake2b::Context<16>),
    Context32(blake2b::Context<32>),
    Context64(blake2b::Context<64>),
    Context128(blake2b::Context<128>),
    Context160(blake2b::Context<160>),
    Context192(blake2b::Context<128>),
    Context224(blake2b::Context<224>),
    Context256(blake2b::Context<256>),
    Context264(blake2b::Context<264>),
    Context288(blake2b::Context<288>),
    Context320(blake2b::Context<320>),
    Context352(blake2b::Context<352>),
    Context384(blake2b::Context<384>),
    Context512(blake2b::Context<512>),
}

macro_rules! ctx_pass {
    ($self:ident, $name:ident ($($input:expr)*)) => {
        match $self {
            Context::Context8(ctx) => ctx.$name ($($input)*),
            Context::Context16(ctx) => ctx.$name ($($input)*),
            Context::Context32(ctx) => ctx.$name ($($input)*),
            Context::Context64(ctx) => ctx.$name ($($input)*),
            Context::Context128(ctx) => ctx.$name ($($input)*),
            Context::Context160(ctx) => ctx.$name ($($input)*),
            Context::Context192(ctx) => ctx.$name ($($input)*),
            Context::Context224(ctx) => ctx.$name ($($input)*),
            Context::Context256(ctx) => ctx.$name ($($input)*),
            Context::Context264(ctx) => ctx.$name ($($input)*),
            Context::Context288(ctx) => ctx.$name ($($input)*),
            Context::Context320(ctx) => ctx.$name ($($input)*),
            Context::Context352(ctx) => ctx.$name ($($input)*),
            Context::Context384(ctx) => ctx.$name ($($input)*),
            Context::Context512(ctx) => ctx.$name ($($input)*),
        }
    };
}

impl Context {
    fn digest_length(&self) -> usize {
        match self {
            Context::Context8(_) => 1,
            Context::Context16(_) => 2,
            Context::Context32(_) => 4,
            Context::Context64(_) => 8,
            Context::Context128(_) => 16,
            Context::Context160(_) => 20,
            Context::Context192(_) => 24,
            Context::Context224(_) => 28,
            Context::Context256(_) => 32,
            Context::Context264(_) => 33,
            Context::Context288(_) => 36,
            Context::Context320(_) => 40,
            Context::Context352(_) => 44,
            Context::Context384(_) => 48,
            Context::Context512(_) => 64,
        }
    }

    fn update_mut(&mut self, input: &[u8]) {
        ctx_pass!(self, update_mut(input))
    }

    fn reset(&mut self) {
        ctx_pass!(self, reset())
    }

    fn reset_with_key(&mut self, key: &[u8]) {
        ctx_pass!(self, reset_with_key(key))
    }

    fn finalize_reset_at(&mut self, out: &mut [u8]) {
        ctx_pass!(self, finalize_reset_at(out))
    }
}

/// Blake2b Context
#[derive(Clone)]
pub struct Blake2b {
    ctx: Context,
    computed: bool, // whether the final digest has been computed
}

impl Blake2b {
    /// Create a new Blake2b context with a specific output size in bytes
    ///
    /// the size need to be between 0 (non included) and 64 bytes (included)
    pub fn new(outlen: usize) -> Self {
        let ctx = match outlen {
            1 => Context::Context8(blake2b::Context::new()),
            2 => Context::Context16(blake2b::Context::new()),
            4 => Context::Context32(blake2b::Context::new()),
            8 => Context::Context64(blake2b::Context::new()),
            16 => Context::Context128(blake2b::Context::new()),
            20 => Context::Context160(blake2b::Context::new()),
            24 => Context::Context192(blake2b::Context::new()),
            28 => Context::Context224(blake2b::Context::new()),
            32 => Context::Context256(blake2b::Context::new()),
            33 => Context::Context264(blake2b::Context::new()),
            36 => Context::Context288(blake2b::Context::new()),
            40 => Context::Context320(blake2b::Context::new()),
            44 => Context::Context352(blake2b::Context::new()),
            48 => Context::Context384(blake2b::Context::new()),
            64 => Context::Context512(blake2b::Context::new()),
            _ => panic!("outlen > 0 && outlen <= 64"),
        };
        Self {
            ctx,
            computed: false,
        }
    }

    /// Similar to `new` but also takes a variable size key
    /// to tweak the context initialization
    pub fn new_keyed(outlen: usize, key: &[u8]) -> Self {
        assert!(key.len() <= 64);
        let ctx = match outlen {
            1 => Context::Context8(blake2b::Context::new_keyed(key)),
            2 => Context::Context16(blake2b::Context::new_keyed(key)),
            4 => Context::Context32(blake2b::Context::new_keyed(key)),
            8 => Context::Context64(blake2b::Context::new_keyed(key)),
            16 => Context::Context128(blake2b::Context::new_keyed(key)),
            20 => Context::Context160(blake2b::Context::new_keyed(key)),
            24 => Context::Context192(blake2b::Context::new_keyed(key)),
            28 => Context::Context224(blake2b::Context::new_keyed(key)),
            32 => Context::Context256(blake2b::Context::new_keyed(key)),
            33 => Context::Context264(blake2b::Context::new_keyed(key)),
            36 => Context::Context288(blake2b::Context::new_keyed(key)),
            40 => Context::Context320(blake2b::Context::new_keyed(key)),
            44 => Context::Context352(blake2b::Context::new_keyed(key)),
            48 => Context::Context384(blake2b::Context::new_keyed(key)),
            64 => Context::Context512(blake2b::Context::new_keyed(key)),
            _ => panic!("outlen > 0 && outlen <= 64"),
        };
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

    pub fn blake2b(out: &mut [u8], input: &[u8], key: &[u8]) {
        let mut hasher: Blake2b = if !key.is_empty() {
            Blake2b::new_keyed(out.len(), key)
        } else {
            Blake2b::new(out.len())
        };

        hasher.update(input);
        hasher.finalize(out);
    }
}

impl Digest for Blake2b {
    fn input(&mut self, msg: &[u8]) {
        self.update(msg);
    }
    fn reset(&mut self) {
        Blake2b::reset(self);
    }
    fn result(&mut self, out: &mut [u8]) {
        self.finalize(out);
    }
    fn output_bits(&self) -> usize {
        8 * (self.ctx.digest_length())
    }
    fn block_size(&self) -> usize {
        // hack : this is a constant, not related to the number of bit
        blake2b::Blake2b::<0>::BLOCK_BYTES
    }
}

impl Mac for Blake2b {
    fn input(&mut self, data: &[u8]) {
        self.update(data);
    }

    fn reset(&mut self) {
        Blake2b::reset(self);
    }

    fn result(&mut self) -> MacResult {
        let mut mac: Vec<u8> = repeat(0).take(self.ctx.digest_length()).collect();
        self.raw_result(&mut mac);
        MacResult::new_from_owned(mac)
    }

    fn raw_result(&mut self, output: &mut [u8]) {
        self.finalize(output);
    }

    fn output_bytes(&self) -> usize {
        self.ctx.digest_length()
    }
}

#[cfg(test)]
mod mac_tests {
    use super::Blake2b;
    use crate::mac::Mac;

    #[test]
    fn test_reset_with_key_same_as_new_keyed_if_empty() {
        const KEY: &[u8] = &[];
        const INPUT: &[u8] = &[];
        let mut m = Blake2b::new_keyed(32, &KEY);
        m.input(&INPUT);

        let mac1 = m.result();

        m.reset_with_key(&KEY);
        m.input(&INPUT);

        let mac2 = m.result();

        assert_eq!(mac1.code(), mac2.code());
    }

    #[test]
    fn test_blake2b_mac() {
        let key: [u8; 64] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ];
        let mut m = Blake2b::new_keyed(64, &key[..]);
        m.input(&[1, 2, 4, 8]);
        let expected = [
            0x8e, 0xc6, 0xcb, 0x71, 0xc4, 0x5c, 0x3c, 0x90, 0x91, 0xd0, 0x8a, 0x37, 0x1e, 0xa8,
            0x5d, 0xc1, 0x22, 0xb5, 0xc8, 0xe2, 0xd9, 0xe5, 0x71, 0x42, 0xbf, 0xef, 0xce, 0x42,
            0xd7, 0xbc, 0xf8, 0x8b, 0xb0, 0x31, 0x27, 0x88, 0x2e, 0x51, 0xa9, 0x21, 0x44, 0x62,
            0x08, 0xf6, 0xa3, 0x58, 0xa9, 0xe0, 0x7d, 0x35, 0x3b, 0xd3, 0x1c, 0x41, 0x70, 0x15,
            0x62, 0xac, 0xd5, 0x39, 0x4e, 0xee, 0x73, 0xae,
        ];
        assert_eq!(m.result().code().to_vec(), expected.to_vec());
    }
}
