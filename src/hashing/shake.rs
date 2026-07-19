//! An implementation of the SHAKE extendable-output functions (XOFs).
//!
//! SHAKE128 and SHAKE256 are the two extendable-output functions defined
//! alongside SHA-3 in [FIPS 202]. Unlike the fixed-length SHA-3 hashes they
//! produce a digest of arbitrary length: the caller decides how many bytes to
//! squeeze out of the sponge.
//!
//! The number in the name is the security strength in bits (against collision
//! and preimage-style attacks); it also determines the sponge capacity, and
//! therefore the rate at which input is absorbed and output squeezed.
//!
//! [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
//!
//! # Examples
//!
//! Squeeze a fixed number of bytes in a single call:
//!
//! ```rust
//! use cryptoxide::hashing::shake::Shake128;
//!
//! // squeeze 32 bytes of SHAKE128 output
//! let out: [u8; 32] = Shake128::new().update(b"abc").finalize();
//! ```
//!
//! Or stream an arbitrary amount of output through a reader:
//!
//! ```rust
//! use cryptoxide::hashing::shake::Shake256;
//!
//! let mut reader = Shake256::new().update(b"abc").finalize_xof();
//!
//! let mut chunk1 = [0u8; 16];
//! let mut chunk2 = [0u8; 48];
//! reader.fill(&mut chunk1);
//! reader.fill(&mut chunk2);
//! // chunk1 ++ chunk2 is the same as squeezing 64 bytes at once
//! ```

use super::sha3::{Engine, B};

macro_rules! shake_impl {
    ($C:ident, $context:ident, $reader:ident, $capacity2:literal, $security:literal, $doc:expr) => {
        #[doc=$doc]
        #[doc = " extendable-output function"]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $C;

        impl $C {
            /// The security strength of the XOF in bits
            pub const SECURITY_BITS: usize = $security;
            /// The rate in bytes: the number of bytes the algorithm absorbs (and
            /// squeezes) before applying the Keccak permutation
            pub const BLOCK_BYTES: usize = B - ($capacity2 * 2);

            /// Create a new context for this algorithm
            pub fn new() -> $context {
                $context::new()
            }
        }

        #[doc=$doc]
        #[doc = " Context"]
        ///
        /// Absorbs input incrementally through [`update`](Self::update) /
        /// [`update_mut`](Self::update_mut), then produces output either as a
        /// fixed-size array via [`finalize`](Self::finalize) or as an
        /// arbitrary-length stream via [`finalize_xof`](Self::finalize_xof).
        #[derive(Clone)]
        pub struct $context(Engine<$capacity2, 4>);

        impl $context {
            /// Create a new SHAKE Context
            pub const fn new() -> Self {
                Self(Engine::new())
            }

            /// Update in-place the hashing state by adding the input bytes slice into the state
            ///
            /// For the immutable version see [`update`](Self::update)
            pub fn update_mut(&mut self, data: &[u8]) {
                self.0.process(data)
            }

            /// Update the hashing state by adding the input bytes slice into the state
            pub fn update(mut self, data: &[u8]) -> Self {
                self.0.process(data);
                self
            }

            /// Reset the context state, as if a new context had been created
            pub fn reset(&mut self) {
                self.0.reset()
            }

            /// Finalize the absorb phase and return a reader for the
            /// arbitrary-length XOF output.
            ///
            /// The context is consumed by this function, to prevent buggy reuse.
            /// If the context needs to be kept before finalizing, the user can
            /// clone the Context.
            pub fn finalize_xof(self) -> $reader {
                $reader(self.0)
            }

            /// Finalize the context and squeeze the output into the mutable slice `out`
            ///
            /// The context is consumed by this function, to prevent buggy reuse.
            /// If the context needs to be kept before finalizing, the user can
            /// clone the Context.
            pub fn finalize_at(mut self, out: &mut [u8]) {
                self.0.output(out)
            }

            /// Finalize the context and return a fixed-size array of `OUT` bytes
            ///
            /// The context is consumed by this function, to prevent buggy reuse.
            /// If the context needs to be kept before finalizing, the user can
            /// clone the Context.
            pub fn finalize<const OUT: usize>(mut self) -> [u8; OUT] {
                let mut out = [0u8; OUT];
                self.0.output(&mut out);
                out
            }

            /// Same as [`finalize_at`](Self::finalize_at) but do not consume the
            /// context, instead resetting it into a ready to use state.
            pub fn finalize_reset_at(&mut self, out: &mut [u8]) {
                self.0.output(out);
                self.0.reset();
            }

            /// Same as [`finalize`](Self::finalize) but do not consume the
            /// context, instead resetting it into a ready to use state.
            pub fn finalize_reset<const OUT: usize>(&mut self) -> [u8; OUT] {
                let mut out = [0u8; OUT];
                self.0.output(&mut out);
                self.0.reset();
                out
            }
        }

        #[doc=$doc]
        #[doc = " extendable-output reader"]
        ///
        /// Returned by [`Context::finalize_xof`](struct.Context128.html#method.finalize_xof).
        /// Produces arbitrary-length output; each call to [`fill`](Self::fill)
        /// continues the output stream where the previous call left off.
        #[derive(Clone)]
        pub struct $reader(Engine<$capacity2, 4>);

        impl $reader {
            /// Fill the provided buffer with the next XOF output bytes
            ///
            /// This method can be called repeatedly to extract an arbitrary
            /// amount of output. Successive calls continue the output stream
            /// where the previous call left off, so filling two 16-byte buffers
            /// is equivalent to filling one 32-byte buffer.
            pub fn fill(&mut self, out: &mut [u8]) {
                self.0.output(out)
            }
        }
    };
}

shake_impl!(Shake128, Context128, Reader128, 16, 128, "SHAKE128");
shake_impl!(Shake256, Context256, Reader256, 32, 256, "SHAKE256");

#[cfg(test)]
mod tests {
    use super::super::tests::{test_hashing, Test};
    use super::*;
    use alloc::vec;

    // Drive the fixed-length test harness at a fixed 32-byte output. The
    // harness exercises one-shot, byte-by-byte and chunked updates, plus reset
    // and finalize_reset.
    #[test]
    fn test_shake128_32() {
        let tests = [
            Test {
                input: b"",
                output: [
                    0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76,
                    0x05, 0x85, 0x3e, 0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88, 0xeb, 0x1a,
                    0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog",
                output: [
                    0xf4, 0x20, 0x2e, 0x3c, 0x58, 0x52, 0xf9, 0x18, 0x2a, 0x04, 0x30, 0xfd, 0x81,
                    0x44, 0xf0, 0xa7, 0x4b, 0x95, 0xe7, 0x41, 0x7e, 0xca, 0xe1, 0x7d, 0xb0, 0xf8,
                    0xcf, 0xee, 0xd0, 0xe3, 0xe6, 0x6e,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog.",
                output: [
                    0x63, 0x40, 0x69, 0xe6, 0xb1, 0x3c, 0x3a, 0xf6, 0x4c, 0x57, 0xf0, 0x5b, 0xab,
                    0xf5, 0x91, 0x1b, 0x6a, 0xcf, 0x1d, 0x30, 0x9b, 0x96, 0x24, 0xfc, 0x92, 0xb0,
                    0xc0, 0xbd, 0x9f, 0x27, 0xf5, 0x38,
                ],
            },
        ];
        test_hashing(
            &tests,
            Shake128,
            |_| Context128::new(),
            |ctx, input| ctx.update(input),
            |ctx, input| ctx.update_mut(input),
            |ctx| ctx.finalize::<32>(),
            |ctx| ctx.finalize_reset::<32>(),
            |ctx| ctx.reset(),
        )
    }

    #[test]
    fn test_shake256_32() {
        let tests = [
            Test {
                input: b"",
                output: [
                    0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74,
                    0x3e, 0xeb, 0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c,
                    0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog",
                output: [
                    0x2f, 0x67, 0x13, 0x43, 0xd9, 0xb2, 0xe1, 0x60, 0x4d, 0xc9, 0xdc, 0xf0, 0x75,
                    0x3e, 0x5f, 0xe1, 0x5c, 0x7c, 0x64, 0xa0, 0xd2, 0x83, 0xcb, 0xbf, 0x72, 0x2d,
                    0x41, 0x1a, 0x0e, 0x36, 0xf6, 0xca,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog.",
                output: [
                    0xbd, 0x22, 0x5b, 0xfc, 0x8b, 0x25, 0x5f, 0x30, 0x36, 0xf0, 0xc8, 0x86, 0x60,
                    0x10, 0xed, 0x00, 0x53, 0xb5, 0x16, 0x3a, 0x3c, 0xae, 0x11, 0x1e, 0x72, 0x3c,
                    0x0c, 0x8e, 0x70, 0x4e, 0xca, 0x4e,
                ],
            },
        ];
        test_hashing(
            &tests,
            Shake256,
            |_| Context256::new(),
            |ctx, input| ctx.update(input),
            |ctx, input| ctx.update_mut(input),
            |ctx| ctx.finalize::<32>(),
            |ctx| ctx.finalize_reset::<32>(),
            |ctx| ctx.reset(),
        )
    }

    // A single large squeeze must equal the concatenation of many small
    // squeezes from the reader, and both must match the reference stream.
    // SHAKE128 has a 168-byte rate, so 200 bytes spans two squeeze blocks and
    // exercises the permutation call in the squeeze loop.
    #[test]
    fn test_shake128_streaming() {
        let expected200: [u8; 200] = [
            0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05,
            0x85, 0x3e, 0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88, 0xeb, 0x1a, 0x6e, 0xac,
            0xfa, 0x66, 0xef, 0x26, 0x3c, 0xb1, 0xee, 0xa9, 0x88, 0x00, 0x4b, 0x93, 0x10, 0x3c,
            0xfb, 0x0a, 0xee, 0xfd, 0x2a, 0x68, 0x6e, 0x01, 0xfa, 0x4a, 0x58, 0xe8, 0xa3, 0x63,
            0x9c, 0xa8, 0xa1, 0xe3, 0xf9, 0xae, 0x57, 0xe2, 0x35, 0xb8, 0xcc, 0x87, 0x3c, 0x23,
            0xdc, 0x62, 0xb8, 0xd2, 0x60, 0x16, 0x9a, 0xfa, 0x2f, 0x75, 0xab, 0x91, 0x6a, 0x58,
            0xd9, 0x74, 0x91, 0x88, 0x35, 0xd2, 0x5e, 0x6a, 0x43, 0x50, 0x85, 0xb2, 0xba, 0xdf,
            0xd6, 0xdf, 0xaa, 0xc3, 0x59, 0xa5, 0xef, 0xbb, 0x7b, 0xcc, 0x4b, 0x59, 0xd5, 0x38,
            0xdf, 0x9a, 0x04, 0x30, 0x2e, 0x10, 0xc8, 0xbc, 0x1c, 0xbf, 0x1a, 0x0b, 0x3a, 0x51,
            0x20, 0xea, 0x17, 0xcd, 0xa7, 0xcf, 0xad, 0x76, 0x5f, 0x56, 0x23, 0x47, 0x4d, 0x36,
            0x8c, 0xcc, 0xa8, 0xaf, 0x00, 0x07, 0xcd, 0x9f, 0x5e, 0x4c, 0x84, 0x9f, 0x16, 0x7a,
            0x58, 0x0b, 0x14, 0xaa, 0xbd, 0xef, 0xae, 0xe7, 0xee, 0xf4, 0x7c, 0xb0, 0xfc, 0xa9,
            0x76, 0x7b, 0xe1, 0xfd, 0xa6, 0x94, 0x19, 0xdf, 0xb9, 0x27, 0xe9, 0xdf, 0x07, 0x34,
            0x8b, 0x19, 0x66, 0x91, 0xab, 0xae, 0xb5, 0x80, 0xb3, 0x2d, 0xef, 0x58, 0x53, 0x8b,
            0x8d, 0x23, 0xf8, 0x77,
        ];

        // one-shot squeeze of all 200 bytes
        let one_shot: [u8; 200] = Shake128::new().update(b"").finalize();
        assert_eq!(one_shot, expected200);

        // streaming: fill in irregular chunk sizes that straddle the block boundary
        let mut reader = Shake128::new().update(b"").finalize_xof();
        let mut streamed = [0u8; 200];
        let mut pos = 0;
        for chunk in [1usize, 50, 100, 17, 32] {
            reader.fill(&mut streamed[pos..pos + chunk]);
            pos += chunk;
        }
        assert_eq!(pos, 200);
        assert_eq!(streamed, expected200);
    }

    #[test]
    fn test_shake256_streaming() {
        let expected200 = [
            0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e,
            0xeb, 0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64,
            0x6e, 0xd5, 0x76, 0x2f, 0xd7, 0x5d, 0xc4, 0xdd, 0xd8, 0xc0, 0xf2, 0x00, 0xcb, 0x05,
            0x01, 0x9d, 0x67, 0xb5, 0x92, 0xf6, 0xfc, 0x82, 0x1c, 0x49, 0x47, 0x9a, 0xb4, 0x86,
            0x40, 0x29, 0x2e, 0xac, 0xb3, 0xb7, 0xc4, 0xbe, 0x14, 0x1e, 0x96, 0x61, 0x6f, 0xb1,
            0x39, 0x57, 0x69, 0x2c, 0xc7, 0xed, 0xd0, 0xb4, 0x5a, 0xe3, 0xdc, 0x07, 0x22, 0x3c,
            0x8e, 0x92, 0x93, 0x7b, 0xef, 0x84, 0xbc, 0x0e, 0xab, 0x86, 0x28, 0x53, 0x34, 0x9e,
            0xc7, 0x55, 0x46, 0xf5, 0x8f, 0xb7, 0xc2, 0x77, 0x5c, 0x38, 0x46, 0x2c, 0x50, 0x10,
            0xd8, 0x46, 0xc1, 0x85, 0xc1, 0x51, 0x11, 0xe5, 0x95, 0x52, 0x2a, 0x6b, 0xcd, 0x16,
            0xcf, 0x86, 0xf3, 0xd1, 0x22, 0x10, 0x9e, 0x3b, 0x1f, 0xdd, 0x94, 0x3b, 0x6a, 0xec,
            0x46, 0x8a, 0x2d, 0x62, 0x1a, 0x7c, 0x06, 0xc6, 0xa9, 0x57, 0xc6, 0x2b, 0x54, 0xda,
            0xfc, 0x3b, 0xe8, 0x75, 0x67, 0xd6, 0x77, 0x23, 0x13, 0x95, 0xf6, 0x14, 0x72, 0x93,
            0xb6, 0x8c, 0xea, 0xb7, 0xa9, 0xe0, 0xc5, 0x8d, 0x86, 0x4e, 0x8e, 0xfd, 0xe4, 0xe1,
            0xb9, 0xa4, 0x6c, 0xbe, 0x85, 0x47, 0x13, 0x67, 0x2f, 0x5c, 0xaa, 0xae, 0x31, 0x4e,
            0xd9, 0x08, 0x3d, 0xab,
        ];

        let one_shot: [u8; 200] = Shake256::new().update(b"").finalize();
        assert_eq!(one_shot, expected200);

        let mut reader = Shake256::new().update(b"").finalize_xof();
        let mut streamed = [0u8; 200];
        let mut pos = 0;
        // 136-byte rate: these chunk sizes cross the boundary too
        for chunk in [136usize, 1, 63] {
            reader.fill(&mut streamed[pos..pos + chunk]);
            pos += chunk;
        }
        assert_eq!(pos, 200);
        assert_eq!(streamed, expected200);
    }
}
