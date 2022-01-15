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
//! use cryptoxide::{sha1::Sha1, digest::Digest};
//!
//! let mut digest = [0u8; 20];
//! let mut context = Sha1::new();
//! context.input(b"hello world");
//! context.result(&mut digest);
//! ```

use crate::digest::Digest;
use crate::hashing::sha1;

/// Structure representing the state of a Sha1 computation
#[derive(Clone)]
pub struct Sha1 {
    ctx: sha1::Context,
    computed: bool,
}

impl Sha1 {
    /// Construct a `sha` object
    pub const fn new() -> Sha1 {
        Sha1 {
            ctx: sha1::Sha1::new(),
            computed: false,
        }
    }
}

impl Digest for Sha1 {
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
        sha1::Sha1::OUTPUT_BITS
    }
    fn block_size(&self) -> usize {
        sha1::Sha1::BLOCK_BYTES
    }
}
