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

/// Blake2b Context (Dynamic output size)
pub type Context = blake2b::ContextDyn;

/// Blake2b Context
#[derive(Clone)]
pub struct Blake2b {
    ctx: blake2b::ContextDyn,
    computed: bool, // whether the final digest has been computed
}

impl Blake2b {
    /// Create a new Blake2b context with a specific output size in bytes
    ///
    /// the size need to be between 0 (non included) and 64 bytes (included)
    pub fn new(outlen: usize) -> Self {
        let ctx = blake2b::ContextDyn::new(outlen);
        Self {
            ctx,
            computed: false,
        }
    }

    /// Similar to `new` but also takes a variable size key
    /// to tweak the context initialization
    pub fn new_keyed(outlen: usize, key: &[u8]) -> Self {
        assert!(key.len() <= 64);
        let ctx = blake2b::ContextDyn::new_keyed(outlen, key);
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

    /// Reset the blake2 context with a key
    pub fn reset_with_key(&mut self, key: &[u8]) {
        self.ctx.reset_with_key(key);
        self.computed = false;
    }

    /// Compute the blake2 function as one call
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
        self.ctx.output_bits()
    }
    fn block_size(&self) -> usize {
        // hack : this is a constant, not related to the number of bit
        blake2b::Blake2b::<0>::BLOCK_BYTES
    }
}
