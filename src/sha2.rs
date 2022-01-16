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
//! use self::cryptoxide::digest::Digest;
//! use self::cryptoxide::sha2::Sha256;
//!
//! // create a Sha256 object
//! let mut hasher = Sha256::new();
//!
//! // write input message
//! hasher.input_str("hello world");
//!
//! // read hash digest
//! let hex = hasher.result_str();
//!
//! assert_eq!(hex,
//!            concat!("b94d27b9934d3e08a52e52d7da7dabfa",
//!                    "c484efe37a5380ee9088f7ace2efcde9"));
//! ```
//!
//! An example of using `Sha512` is:
//!
//! ```rust
//! use self::cryptoxide::digest::Digest;
//! use self::cryptoxide::sha2::Sha512;
//!
//! // create a Sha512 object
//! let mut hasher = Sha512::new();
//!
//! // write input message
//! hasher.input_str("hello world");
//!
//! // read hash digest
//! let hex = hasher.result_str();
//!
//! assert_eq!(hex,
//!            concat!("309ecc489c12d6eb4cc40f50c902f2b4",
//!                    "d0ed77ee511a7c7a9bcd3ca86d4cd86f",
//!                    "989dd35bc5ff499670da34255b45b0cf",
//!                    "d830e81f605dcf7dc5542e93ae9cd76f"));
//! ```

use crate::digest::Digest;
use crate::hashing::sha2;

macro_rules! digest {
    ($name: ident, $ctx: ident) => {
        /// The hash algorithm context
        #[derive(Clone)]
        pub struct $name {
            ctx: sha2::$ctx,
            computed: bool,
        }

        impl $name {
            /// Create a new hashing algorithm context
            pub const fn new() -> Self {
                Self {
                    ctx: sha2::$ctx::new(),
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
                sha2::$name::OUTPUT_BITS
            }
            fn block_size(&self) -> usize {
                sha2::$name::BLOCK_BYTES
            }
        }
    };
}

digest!(Sha512, Context512);
digest!(Sha384, Context384);
digest!(Sha512Trunc256, Context512_256);
digest!(Sha512Trunc224, Context512_224);
digest!(Sha256, Context256);
digest!(Sha224, Context224);
