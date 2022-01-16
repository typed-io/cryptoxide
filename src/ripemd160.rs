//! An implementation of the RIPEMD-160 cryptographic hash.
//!
//! RIPEMD (RIPE Message Digest) is a family of cryptographic hash functions
//! developed in 1992 (the original RIPEMD) and 1996 (other variants). There are
//! five functions in the family: RIPEMD, RIPEMD-128, RIPEMD-160, RIPEMD-256,
//! and RIPEMD-320, of which RIPEMD-160 is the most common.
//!
//!
//! ```
//! use cryptoxide::{ripemd160::Ripemd160, digest::Digest};
//!
//! let mut digest = [0u8; 20];
//! let mut context = Ripemd160::new();
//!
//! context.input(b"hello world");
//! context.result(&mut digest);
//! ```

use crate::digest::Digest;
use crate::hashing::ripemd160;

/// Structure representing the state of a Ripemd160 computation
#[derive(Clone)]
pub struct Ripemd160 {
    ctx: ripemd160::Context,
    computed: bool,
}

impl Ripemd160 {
    /// Construct a `sha` object
    pub const fn new() -> Ripemd160 {
        Ripemd160 {
            ctx: ripemd160::Ripemd160::new(),
            computed: false,
        }
    }
}

impl Digest for Ripemd160 {
    fn reset(&mut self) {
        self.ctx.reset();
        self.computed = false;
    }
    fn input(&mut self, msg: &[u8]) {
        assert!(!self.computed, "context is already finalized, needs reset");
        self.ctx.update_mut(msg);
    }
    fn result(&mut self, slice: &mut [u8]) {
        assert!(!self.computed, "context is already finalized, needs reset");
        self.computed = true;
        slice.copy_from_slice(&self.ctx.finalize_reset());
    }
    fn output_bits(&self) -> usize {
        ripemd160::Ripemd160::OUTPUT_BITS
    }
    fn block_size(&self) -> usize {
        ripemd160::Ripemd160::BLOCK_BYTES
    }
}
