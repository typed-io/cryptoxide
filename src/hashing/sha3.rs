//! An implementation of the SHA-3 cryptographic hash algorithms.
//!
//! There are 6 standard algorithms specified in the SHA-3 standard:
//!
//!  * `SHA3-224`
//!  * `SHA3-256`
//!  * `SHA3-384`
//!  * `SHA3-512`
//!
//! Based on an [implementation by Sébastien Martini](https://github.com/seb-m/crypto.rs/blob/master/src/sha3.rs)
//!
//! # Examples
//!
//! An example of using `SHA3-256` is:
//!
//! ```rust
//! use cryptoxide::hashing::sha3;
//!
//! // create a SHA3-256 context
//! let mut context = sha3::Sha3_256::new();
//!
//! // append input and get output digest
//! let out : [u8; 32] = context.update(b"abc").finalize();
//!
//! ```

use alloc::vec;
use core::cmp;

use crate::cryptoutil::{read_u64v_le, write_u64v_le, zero};

pub(super) const B: usize = 200;
const NROUNDS: usize = 24;
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];
const ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
const PIL: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];
const M5: [usize; 10] = [0, 1, 2, 3, 4, 0, 1, 2, 3, 4];

// Code based on Keccak-compact64.c from ref implementation.
#[allow(clippy::needless_range_loop)]
fn keccak_f(state: &mut [u8; B]) {
    let mut s: [u64; 25] = [0; 25];
    let mut t: [u64; 1] = [0; 1];
    let mut c: [u64; 5] = [0; 5];

    read_u64v_le(&mut s, state);

    for round in 0..NROUNDS {
        // Theta
        for x in 0..5 {
            c[x] = s[x] ^ s[5 + x] ^ s[10 + x] ^ s[15 + x] ^ s[20 + x];
        }
        for x in 0..5 {
            t[0] = c[M5[x + 4]] ^ c[M5[x + 1]].rotate_left(1);
            for y in 0..5 {
                s[y * 5 + x] ^= t[0];
            }
        }

        // Rho Pi
        t[0] = s[1];
        for x in 0..24 {
            c[0] = s[PIL[x]];
            s[PIL[x]] = t[0].rotate_left(ROTC[x]);
            t[0] = c[0];
        }

        // Chi
        for y in 0..5 {
            for x in 0..5 {
                c[x] = s[y * 5 + x];
            }
            for x in 0..5 {
                s[y * 5 + x] = c[x] ^ (!c[M5[x + 1]] & c[M5[x + 2]]);
            }
        }

        // Iota
        s[0] ^= RC[round];
    }

    write_u64v_le(state, &s);
}

/// Engine for Keccak implementation where
/// DSLEN = 0 (Keccak), 2 (SHA-3), 4 (Shake)
/// DIGESTLEN = size in bytes of the digest (28, 32, 48, 64)
#[derive(Clone)]
pub(super) struct Engine<const DIGESTLEN: usize, const DSLEN: usize> {
    state: [u8; B],    // B bytes
    can_absorb: bool,  // Can absorb
    can_squeeze: bool, // Can squeeze
    offset: usize,     // Enqueued bytes in state for absorb phase
                       // Squeeze offset for squeeze phase
}

impl<const DIGESTLEN: usize, const DSLEN: usize> Engine<DIGESTLEN, DSLEN> {
    //pub const CAPACITY: usize = DIGESTLEN * 2;

    fn rate(&self) -> usize {
        B - (DIGESTLEN * 2)
    }

    /// New SHA-3 instanciated from specified SHA-3 `mode`.
    pub const fn new() -> Self {
        Self {
            state: [0; B],
            can_absorb: true,
            can_squeeze: true,
            offset: 0,
        }
    }

    pub(super) fn finalize(&mut self) {
        assert!(self.can_absorb);

        fn set_domain_sep(out_len: usize, buf: &mut [u8]) {
            assert!(!buf.is_empty());
            if out_len != 0 {
                // 01...
                buf[0] &= 0xfe;
                buf[0] |= 0x2;
            } else {
                // 1111...
                buf[0] |= 0xf;
            }
        }

        // All parameters are expected to be in bits.
        fn pad_len<const DSLEN: usize>(offset: usize, rate: usize) -> usize {
            assert!(rate % 8 == 0 && offset % 8 == 0);
            let r: i64 = rate as i64;
            let m: i64 = (offset + DSLEN) as i64;
            let zeros = (((-m - 2) + 2 * r) % r) as usize;
            assert!((m as usize + zeros + 2) % 8 == 0);
            (DSLEN + zeros + 2) / 8
        }

        fn set_pad<const DSLEN: usize>(buf: &mut [u8]) {
            //assert!(buf.len() as f32 >= ((offset + 2) as f32 / 8.0).ceil());
            let offset = DSLEN;
            let s = offset / 8;
            let buflen = buf.len();
            buf[s] |= 1 << (offset % 8);
            for i in (offset % 8) + 1..8 {
                buf[s] &= !(1 << i);
            }
            for b in buf[s + 1..].iter_mut() {
                *b = 0;
            }
            buf[buflen - 1] |= 0x80;
        }

        let p_len = pad_len::<DSLEN>(self.offset * 8, self.rate() * 8);

        let mut p = vec::from_elem(0, p_len);

        if DSLEN != 0 {
            set_domain_sep(DIGESTLEN * 8, &mut p);
        }

        set_pad::<DSLEN>(&mut p);

        self.process(&p);
        self.can_absorb = false;
    }

    pub(super) fn process(&mut self, data: &[u8]) {
        if !self.can_absorb {
            panic!("Invalid state, absorb phase already finalized.");
        }

        let r = self.rate();
        assert!(self.offset < r);

        let in_len = data.len();
        let mut in_pos: usize = 0;

        // Absorb
        while in_pos < in_len {
            let offset = self.offset;
            let nread = cmp::min(r - offset, in_len - in_pos);
            for i in 0..nread {
                self.state[offset + i] ^= data[in_pos + i];
            }
            in_pos += nread;

            if offset + nread != r {
                self.offset += nread;
                break;
            }

            self.offset = 0;
            keccak_f(&mut self.state);
        }
    }

    pub(super) fn reset(&mut self) {
        self.can_absorb = true;
        self.can_squeeze = true;
        self.offset = 0;
        zero(&mut self.state);
    }

    pub(super) fn output(&mut self, out: &mut [u8]) {
        if !self.can_squeeze {
            panic!("Nothing left to squeeze.");
        }

        if self.can_absorb {
            self.finalize();
        }

        let r = self.rate();
        if DIGESTLEN != 0 {
            assert!(self.offset < DIGESTLEN);
        } else {
            // FIXME: only for SHAKE
            assert!(self.offset < r);
        }

        let in_len = out.len();
        let mut in_pos: usize = 0;

        // Squeeze
        while in_pos < in_len {
            let offset = self.offset % r;
            let mut nread = cmp::min(r - offset, in_len - in_pos);
            if DIGESTLEN != 0 {
                nread = cmp::min(nread, DIGESTLEN - self.offset);
            }

            out[in_pos..(nread + in_pos)].copy_from_slice(&self.state[offset..(nread + offset)]);
            in_pos += nread;

            if offset + nread != r {
                self.offset += nread;
                break;
            }

            if DIGESTLEN == 0 {
                self.offset = 0;
            } else {
                self.offset += nread;
            }

            keccak_f(&mut self.state);
        }

        if DIGESTLEN != 0 && DIGESTLEN == self.offset {
            self.can_squeeze = false;
        }
    }
}

/*
/// New SHAKE-128 instance.
pub fn shake_128() -> Sha3 {
    Sha3::new(Sha3Mode::Shake128)
}

/// New SHAKE-256 instance.
pub fn shake_256() -> Sha3 {
    Sha3::new(Sha3Mode::Shake256)
}
*/
macro_rules! sha3_impl {
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
        pub struct $context(Engine<$digestlength, 2>);

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

sha3_impl!(Sha3_224, Context224, 28, "SHA3 224");
sha3_impl!(Sha3_256, Context256, 32, "SHA3 256");
sha3_impl!(Sha3_384, Context384, 48, "SHA3 384");
sha3_impl!(Sha3_512, Context512, 64, "SHA3 512");

#[cfg(test)]
mod tests {
    use super::super::tests::{test_hashing, Test};
    use super::*;

    #[test]
    fn test_sha3_224() {
        let tests = [
            Test {
                input: b"",
                output: [
                    0x6b, 0x4e, 0x03, 0x42, 0x36, 0x67, 0xdb, 0xb7, 0x3b, 0x6e, 0x15, 0x45, 0x4f,
                    0x0e, 0xb1, 0xab, 0xd4, 0x59, 0x7f, 0x9a, 0x1b, 0x07, 0x8e, 0x3f, 0x5b, 0x5a,
                    0x6b, 0xc7,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog",
                output: [
                    0xd1, 0x5d, 0xad, 0xce, 0xaa, 0x4d, 0x5d, 0x7b, 0xb3, 0xb4, 0x8f, 0x44, 0x64,
                    0x21, 0xd5, 0x42, 0xe0, 0x8a, 0xd8, 0x88, 0x73, 0x05, 0xe2, 0x8d, 0x58, 0x33,
                    0x57, 0x95,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog.",
                output: [
                    0x2d, 0x07, 0x08, 0x90, 0x38, 0x33, 0xaf, 0xab, 0xdd, 0x23, 0x2a, 0x20, 0x20,
                    0x11, 0x76, 0xe8, 0xb5, 0x8c, 0x5b, 0xe8, 0xa6, 0xfe, 0x74, 0x26, 0x5a, 0xc5,
                    0x4d, 0xb0,
                ],
            },
        ];
        test_hashing(
            &tests,
            Sha3_224,
            |_| Context224::new(),
            |ctx, input| ctx.update(input),
            |ctx, input| ctx.update_mut(input),
            |ctx| ctx.finalize(),
            |ctx| ctx.finalize_reset(),
            |ctx| ctx.reset(),
        )
    }

    #[test]
    fn test_sha3_256() {
        let tests = [
            Test {
                input: b"",
                output: [
                    0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0,
                    0x61, 0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8,
                    0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog",
                output: [
                    0x69, 0x07, 0x0d, 0xda, 0x01, 0x97, 0x5c, 0x8c, 0x12, 0x0c, 0x3a, 0xad, 0xa1,
                    0xb2, 0x82, 0x39, 0x4e, 0x7f, 0x03, 0x2f, 0xa9, 0xcf, 0x32, 0xf4, 0xcb, 0x22,
                    0x59, 0xa0, 0x89, 0x7d, 0xfc, 0x04,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog.",
                output: [
                    0xa8, 0x0f, 0x83, 0x9c, 0xd4, 0xf8, 0x3f, 0x6c, 0x3d, 0xaf, 0xc8, 0x7f, 0xea,
                    0xe4, 0x70, 0x04, 0x5e, 0x4e, 0xb0, 0xd3, 0x66, 0x39, 0x7d, 0x5c, 0x6c, 0xe3,
                    0x4b, 0xa1, 0x73, 0x9f, 0x73, 0x4d,
                ],
            },
        ];
        test_hashing(
            &tests,
            Sha3_256,
            |_| Context256::new(),
            |ctx, input| ctx.update(input),
            |ctx, input| ctx.update_mut(input),
            |ctx| ctx.finalize(),
            |ctx| ctx.finalize_reset(),
            |ctx| ctx.reset(),
        )
    }

    #[test]
    fn test_sha3_384() {
        let tests = [
            Test {
                input: b"",
                output: [
                    0x0c, 0x63, 0xa7, 0x5b, 0x84, 0x5e, 0x4f, 0x7d, 0x01, 0x10, 0x7d, 0x85, 0x2e,
                    0x4c, 0x24, 0x85, 0xc5, 0x1a, 0x50, 0xaa, 0xaa, 0x94, 0xfc, 0x61, 0x99, 0x5e,
                    0x71, 0xbb, 0xee, 0x98, 0x3a, 0x2a, 0xc3, 0x71, 0x38, 0x31, 0x26, 0x4a, 0xdb,
                    0x47, 0xfb, 0x6b, 0xd1, 0xe0, 0x58, 0xd5, 0xf0, 0x04,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog",
                output: [
                    0x70, 0x63, 0x46, 0x5e, 0x08, 0xa9, 0x3b, 0xce, 0x31, 0xcd, 0x89, 0xd2, 0xe3,
                    0xca, 0x8f, 0x60, 0x24, 0x98, 0x69, 0x6e, 0x25, 0x35, 0x92, 0xed, 0x26, 0xf0,
                    0x7b, 0xf7, 0xe7, 0x03, 0xcf, 0x32, 0x85, 0x81, 0xe1, 0x47, 0x1a, 0x7b, 0xa7,
                    0xab, 0x11, 0x9b, 0x1a, 0x9e, 0xbd, 0xf8, 0xbe, 0x41,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog.",
                output: [
                    0x1a, 0x34, 0xd8, 0x16, 0x95, 0xb6, 0x22, 0xdf, 0x17, 0x8b, 0xc7, 0x4d, 0xf7,
                    0x12, 0x4f, 0xe1, 0x2f, 0xac, 0x0f, 0x64, 0xba, 0x52, 0x50, 0xb7, 0x8b, 0x99,
                    0xc1, 0x27, 0x3d, 0x4b, 0x08, 0x01, 0x68, 0xe1, 0x06, 0x52, 0x89, 0x4e, 0xca,
                    0xd5, 0xf1, 0xf4, 0xd5, 0xb9, 0x65, 0x43, 0x7f, 0xb9,
                ],
            },
        ];
        test_hashing(
            &tests,
            Sha3_384,
            |_| Context384::new(),
            |ctx, input| ctx.update(input),
            |ctx, input| ctx.update_mut(input),
            |ctx| ctx.finalize(),
            |ctx| ctx.finalize_reset(),
            |ctx| ctx.reset(),
        )
    }

    #[test]
    fn test_sha3_512() {
        let tests = [
            Test {
                input: b"",
                output: [
                    0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5, 0xc8, 0xb5, 0x67, 0xdc, 0x18,
                    0x5a, 0x75, 0x6e, 0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59, 0xe0, 0xd1,
                    0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6, 0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9,
                    0x4c, 0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58, 0xf5, 0x00, 0x19, 0x9d,
                    0x95, 0xb6, 0xd3, 0xe3, 0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog",
                output: [
                    0x01, 0xde, 0xdd, 0x5d, 0xe4, 0xef, 0x14, 0x64, 0x24, 0x45, 0xba, 0x5f, 0x5b,
                    0x97, 0xc1, 0x5e, 0x47, 0xb9, 0xad, 0x93, 0x13, 0x26, 0xe4, 0xb0, 0x72, 0x7c,
                    0xd9, 0x4c, 0xef, 0xc4, 0x4f, 0xff, 0x23, 0xf0, 0x7b, 0xf5, 0x43, 0x13, 0x99,
                    0x39, 0xb4, 0x91, 0x28, 0xca, 0xf4, 0x36, 0xdc, 0x1b, 0xde, 0xe5, 0x4f, 0xcb,
                    0x24, 0x02, 0x3a, 0x08, 0xd9, 0x40, 0x3f, 0x9b, 0x4b, 0xf0, 0xd4, 0x50,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy dog.",
                output: [
                    0x18, 0xf4, 0xf4, 0xbd, 0x41, 0x96, 0x03, 0xf9, 0x55, 0x38, 0x83, 0x70, 0x03,
                    0xd9, 0xd2, 0x54, 0xc2, 0x6c, 0x23, 0x76, 0x55, 0x65, 0x16, 0x22, 0x47, 0x48,
                    0x3f, 0x65, 0xc5, 0x03, 0x03, 0x59, 0x7b, 0xc9, 0xce, 0x4d, 0x28, 0x9f, 0x21,
                    0xd1, 0xc2, 0xf1, 0xf4, 0x58, 0x82, 0x8e, 0x33, 0xdc, 0x44, 0x21, 0x00, 0x33,
                    0x1b, 0x35, 0xe7, 0xeb, 0x03, 0x1b, 0x5d, 0x38, 0xba, 0x64, 0x60, 0xf8,
                ],
            },
        ];
        test_hashing(
            &tests,
            Sha3_512,
            |_| Context512::new(),
            |ctx, input| ctx.update(input),
            |ctx, input| ctx.update_mut(input),
            |ctx| ctx.finalize(),
            |ctx| ctx.finalize_reset(),
            |ctx| ctx.reset(),
        )
    }
}
