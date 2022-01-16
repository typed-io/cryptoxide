//! An implementation of the SHA-3 cryptographic hash algorithms.
//!
//! There are 6 standard algorithms specified in the SHA-3 standard:
//!
//!  * `SHA3-224`
//!  * `SHA3-256`
//!  * `SHA3-384`
//!  * `SHA3-512`
//!  * `Keccak224`, `Keccak256`, `Keccak384`, `Keccak512` (NIST submission without padding changes)
//!
//! Based on an [implementation by Sébastien Martini](https://github.com/seb-m/crypto.rs/blob/master/src/sha3.rs)
//!
//! # Examples
//!
//! An example of using `SHA3-256` is:
//!
//! ```rust
//! use cryptoxide::{digest::Digest, sha3::Sha3_256};
//!
//! // create a SHA3-256 context
//! let mut context = Sha3_256::new();
//!
//! // write input message
//! context.input(b"abc");
//!
//! // get hash digest
//! let mut out = [0u8; 32];
//! context.result(&mut out);
//! ```

use crate::digest::Digest;
use crate::hashing::keccak;
use crate::hashing::sha3;

macro_rules! digest {
    ($name: ident, $m:ident, $ctx: ident) => {
        /// The hash algorithm context
        #[derive(Clone)]
        pub struct $name {
            ctx: $m::$ctx,
            computed: bool,
        }

        impl $name {
            /// Create a new hashing algorithm context
            pub const fn new() -> Self {
                Self {
                    ctx: $m::$ctx::new(),
                    computed: false,
                }
            }
        }

        impl Digest for $name {
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
                $m::$name::OUTPUT_BITS
            }
            fn block_size(&self) -> usize {
                $m::$name::BLOCK_BYTES
            }
        }
    };
}

digest!(Sha3_512, sha3, Context512);
digest!(Sha3_384, sha3, Context384);
digest!(Sha3_256, sha3, Context256);
digest!(Sha3_224, sha3, Context224);

digest!(Keccak512, keccak, Context512);
digest!(Keccak384, keccak, Context384);
digest!(Keccak256, keccak, Context256);
digest!(Keccak224, keccak, Context224);
