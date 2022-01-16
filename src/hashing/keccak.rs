//! An implementation of the Keccak cryptographic hash algorithms.
//!
//! Keccak is the NIST submission for SHA-3 without padding changes
//!
//! The following variants are defined:
//!
//! * `Keccak224`
//! * `Keccak256`
//! * `Keccak384`
//! * `Keccak512`
use super::sha3::{Engine, B};

macro_rules! keccak_impl {
    ($C: ident, $context:ident, $digestlength:literal, $doc:expr) => {
        #[doc=$doc]
        #[doc = " Algorithm"]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $C;

        impl $C {
            pub const OUTPUT_BITS: usize = $digestlength * 8;
            pub const BLOCK_BYTES: usize = B - ($digestlength * 2);

            /// Create a new context for this algorithm
            pub fn new() -> $context {
                $context::new()
            }
        }

        #[doc=$doc]
        #[doc = " Context"]
        #[derive(Clone)]
        pub struct $context(Engine<$digestlength, 0>);

        impl $context {
            pub const fn new() -> Self {
                Self(Engine::new())
            }

            pub fn update_mut(&mut self, data: &[u8]) {
                self.0.process(data)
            }

            pub fn update(mut self, data: &[u8]) -> Self {
                self.0.process(data);
                self
            }

            pub fn finalize_reset(&mut self) -> [u8; $digestlength] {
                let mut out = [0; $digestlength];
                self.0.output(&mut out);
                self.0.reset();
                out
            }

            pub fn finalize(mut self) -> [u8; $digestlength] {
                let mut out = [0; $digestlength];
                self.0.output(&mut out);
                out
            }

            pub fn reset(&mut self) {
                self.0.reset()
            }
        }
    };
}

keccak_impl!(Keccak224, Context224, 28, "Keccak224");
keccak_impl!(Keccak256, Context256, 32, "Keccak256");
keccak_impl!(Keccak384, Context384, 48, "Keccak384");
keccak_impl!(Keccak512, Context512, 64, "Keccak512");

#[cfg(test)]
mod tests {
    use super::super::tests::{test_hashing, Test};
    use super::*;

    #[test]
    fn test_keccak_512() {
        let tests = [
            Test {
                input: b"",
                output: [
                    0x0e, 0xab, 0x42, 0xde, 0x4c, 0x3c, 0xeb, 0x92, 0x35, 0xfc, 0x91, 0xac, 0xff,
                    0xe7, 0x46, 0xb2, 0x9c, 0x29, 0xa8, 0xc3, 0x66, 0xb7, 0xc6, 0x0e, 0x4e, 0x67,
                    0xc4, 0x66, 0xf3, 0x6a, 0x43, 0x04, 0xc0, 0x0f, 0xa9, 0xca, 0xf9, 0xd8, 0x79,
                    0x76, 0xba, 0x46, 0x9b, 0xcb, 0xe0, 0x67, 0x13, 0xb4, 0x35, 0xf0, 0x91, 0xef,
                    0x27, 0x69, 0xfb, 0x16, 0x0c, 0xda, 0xb3, 0x3d, 0x36, 0x70, 0x68, 0x0e,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog",
                output: [
                    0xd1, 0x35, 0xbb, 0x84, 0xd0, 0x43, 0x9d, 0xba, 0xc4, 0x32, 0x24, 0x7e, 0xe5,
                    0x73, 0xa2, 0x3e, 0xa7, 0xd3, 0xc9, 0xde, 0xb2, 0xa9, 0x68, 0xeb, 0x31, 0xd4,
                    0x7c, 0x4f, 0xb4, 0x5f, 0x1e, 0xf4, 0x42, 0x2d, 0x6c, 0x53, 0x1b, 0x5b, 0x9b,
                    0xd6, 0xf4, 0x49, 0xeb, 0xcc, 0x44, 0x9e, 0xa9, 0x4d, 0x0a, 0x8f, 0x05, 0xf6,
                    0x21, 0x30, 0xfd, 0xa6, 0x12, 0xda, 0x53, 0xc7, 0x96, 0x59, 0xf6, 0x09,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog.",
                output: [
                    0xab, 0x71, 0x92, 0xd2, 0xb1, 0x1f, 0x51, 0xc7, 0xdd, 0x74, 0x4e, 0x7b, 0x34,
                    0x41, 0xfe, 0xbf, 0x39, 0x7c, 0xa0, 0x7b, 0xf8, 0x12, 0xcc, 0xea, 0xe1, 0x22,
                    0xca, 0x4d, 0xed, 0x63, 0x87, 0x88, 0x90, 0x64, 0xf8, 0xdb, 0x92, 0x30, 0xf1,
                    0x73, 0xf6, 0xd1, 0xab, 0x6e, 0x24, 0xb6, 0xe5, 0x0f, 0x06, 0x5b, 0x03, 0x9f,
                    0x79, 0x9f, 0x55, 0x92, 0x36, 0x0a, 0x65, 0x58, 0xeb, 0x52, 0xd7, 0x60,
                ],
            },
        ];
        test_hashing(
            &tests,
            Keccak512,
            |_| Context512::new(),
            |ctx, input| ctx.update(input),
            |ctx, input| ctx.update_mut(input),
            |ctx| ctx.finalize(),
            |ctx| ctx.finalize_reset(),
            |ctx| ctx.reset(),
        )
    }
}
