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

use alloc::vec;
use core::cmp;

use crate::cryptoutil::{read_u64v_le, write_u64v_le, zero};
use crate::digest::Digest;

const B: usize = 200;
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
const ROTC: [usize; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
const PIL: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];
const M5: [usize; 10] = [0, 1, 2, 3, 4, 0, 1, 2, 3, 4];

#[inline]
fn rotl64(v: u64, n: usize) -> u64 {
    ((v << (n % 64)) & 0xffffffffffffffff) ^ (v >> (64 - (n % 64)))
}

// Code based on Keccak-compact64.c from ref implementation.
#[allow(clippy::needless_range_loop)]
fn keccak_f(state: &mut [u8]) {
    assert!(state.len() == B);

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
            t[0] = c[M5[x + 4]] ^ rotl64(c[M5[x + 1]], 1);
            for y in 0..5 {
                s[y * 5 + x] ^= t[0];
            }
        }

        // Rho Pi
        t[0] = s[1];
        for x in 0..24 {
            c[0] = s[PIL[x]];
            s[PIL[x]] = rotl64(t[0], ROTC[x]);
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

mod constants {
    pub trait Const {
        const DIGEST_LENGTH: usize;
        const IS_KECCAK: bool;
        const CAPACITY: usize;
        const BLOCK_SIZE: usize;
    }

    macro_rules! sha3_const {
        ($C: ident, $DIGEST_LENGTH: expr, $IS_KECCAK: expr) => {
            #[allow(non_camel_case_types)]
            pub(super) struct $C;
            impl Const for $C {
                const DIGEST_LENGTH: usize = $DIGEST_LENGTH;
                const IS_KECCAK: bool = $IS_KECCAK;
                const CAPACITY: usize = $DIGEST_LENGTH * 2;
                const BLOCK_SIZE: usize = super::B - ($DIGEST_LENGTH * 2);
            }
        };
    }

    /*
    macro_rules! shake_const {
        ($C: ident, $CAPACITY: expr) => {
            #[allow(non_camel_case_types)]
            pub(super) struct $C;
            impl Const for $C {
                const DIGEST_LENGTH: usize = 0;
                const IS_KECCAK: bool = false;
                const CAPACITY: usize = $CAPACITY;
                const BLOCK_SIZE: usize = 0xfffff; // hum
            }
        };
    }
    */

    sha3_const!(Sha3_224, 28, false);
    sha3_const!(Sha3_256, 32, false);
    sha3_const!(Sha3_384, 48, false);
    sha3_const!(Sha3_512, 64, false);
    sha3_const!(Keccak224, 28, true);
    sha3_const!(Keccak256, 32, true);
    sha3_const!(Keccak384, 48, true);
    sha3_const!(Keccak512, 64, true);

    //shake_const!(Shake128, 32);
    //shake_const!(Shake256, 64);
}

use core::marker::PhantomData;

struct Engine<E> {
    state: [u8; B], // B bytes
    mode: PhantomData<E>,
    can_absorb: bool,  // Can absorb
    can_squeeze: bool, // Can squeeze
    offset: usize,     // Enqueued bytes in state for absorb phase
                       // Squeeze offset for squeeze phase
}

impl<E> Clone for Engine<E> {
    fn clone(&self) -> Self {
        Self {
            state: self.state,
            mode: self.mode,
            can_absorb: self.can_absorb,
            can_squeeze: self.can_squeeze,
            offset: self.offset,
        }
    }
}

impl<E: constants::Const> Engine<E> {
    fn rate(&self) -> usize {
        B - E::CAPACITY
    }

    /// New SHA-3 instanciated from specified SHA-3 `mode`.
    pub fn new() -> Self {
        Self {
            state: [0; B],
            mode: PhantomData,
            can_absorb: true,
            can_squeeze: true,
            offset: 0,
        }
    }

    fn finalize(&mut self) {
        assert!(self.can_absorb);

        let output_bits = E::DIGEST_LENGTH * 8;

        let ds_len = if E::IS_KECCAK {
            0
        } else if output_bits != 0 {
            2
        } else {
            // TODO: for SHAKE
            4
        };

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
        fn pad_len(ds_len: usize, offset: usize, rate: usize) -> usize {
            assert!(rate % 8 == 0 && offset % 8 == 0);
            let r: i64 = rate as i64;
            let m: i64 = (offset + ds_len) as i64;
            let zeros = (((-m - 2) + 2 * r) % r) as usize;
            assert!((m as usize + zeros + 2) % 8 == 0);
            (ds_len as usize + zeros + 2) / 8
        }

        fn set_pad(offset: usize, buf: &mut [u8]) {
            //assert!(buf.len() as f32 >= ((offset + 2) as f32 / 8.0).ceil());
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

        let p_len = pad_len(ds_len, self.offset * 8, self.rate() * 8);

        let mut p = vec::from_elem(0, p_len);

        if ds_len != 0 {
            set_domain_sep(E::DIGEST_LENGTH * 8, &mut p);
        }

        set_pad(ds_len, &mut p);

        self.process(&p);
        self.can_absorb = false;
    }

    fn process(&mut self, data: &[u8]) {
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

    fn reset(&mut self) {
        self.can_absorb = true;
        self.can_squeeze = true;
        self.offset = 0;
        zero(&mut self.state);
    }

    fn output(&mut self, out: &mut [u8]) {
        if !self.can_squeeze {
            panic!("Nothing left to squeeze.");
        }

        if self.can_absorb {
            self.finalize();
        }

        let r = self.rate();
        let out_len = E::DIGEST_LENGTH;
        if out_len != 0 {
            assert!(self.offset < out_len);
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
            if out_len != 0 {
                nread = cmp::min(nread, out_len - self.offset);
            }

            out[in_pos..(nread + in_pos)].copy_from_slice(&self.state[offset..(nread + offset)]);
            in_pos += nread;

            if offset + nread != r {
                self.offset += nread;
                break;
            }

            if out_len == 0 {
                self.offset = 0;
            } else {
                self.offset += nread;
            }

            keccak_f(&mut self.state);
        }

        if out_len != 0 && out_len == self.offset {
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
use self::constants::Const;

macro_rules! sha3_impl {
    ($C: ident, $doc:expr) => {
        #[doc=$doc]
        #[derive(Clone)]
        pub struct $C(Engine<constants::$C>);

        impl $C {
            pub fn new() -> Self {
                Self(Engine::new())
            }
        }

        impl Digest for $C {
            const OUTPUT_BITS: usize = constants::$C::DIGEST_LENGTH * 8;

            fn input(&mut self, data: &[u8]) {
                self.0.process(data)
            }

            fn result(&mut self, out: &mut [u8]) {
                self.0.output(out)
            }

            fn reset(&mut self) {
                self.0.reset()
            }

            fn block_size(&self) -> usize {
                self.0.rate()
            }
        }
    };
}

sha3_impl!(Sha3_224, "A SHA3 224 context");
sha3_impl!(Sha3_256, "A SHA3 256 context");
sha3_impl!(Sha3_384, "A SHA3 384 context");
sha3_impl!(Sha3_512, "A SHA3 512 context");

sha3_impl!(Keccak224, "A Keccak224 context");
sha3_impl!(Keccak256, "A Keccak256 context");
sha3_impl!(Keccak384, "A Keccak384 context");
sha3_impl!(Keccak512, "A Keccak512 context");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::Digest;

    struct Test {
        input: &'static str,
        output_str: &'static str,
    }

    fn test_hash<D: Digest>(mut sh: D, tests: &[Test]) {
        // Test that it works when accepting the message all at once
        for t in tests.iter() {
            sh.input_str(t.input);

            let out_str = sh.result_str();
            assert_eq!(&out_str[..], t.output_str);

            sh.reset();
        }

        // Test that it works when accepting the message in pieces
        for t in tests.iter() {
            let len = t.input.len();
            let mut left = len;
            while left > 0 {
                let take = (left + 1) / 2;
                sh.input_str(&t.input[len - left..take + len - left]);
                left -= take;
            }

            let out_str = sh.result_str();
            assert_eq!(&out_str[..], t.output_str);

            sh.reset();
        }
    }

    #[test]
    fn test_sha3_224() {
        let wikipedia_tests = [
            Test {
                input: "",
                output_str: "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog",
                output_str: "d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog.",
                output_str: "2d0708903833afabdd232a20201176e8b58c5be8a6fe74265ac54db0",
            },
        ];
        test_hash(Sha3_224::new(), &wikipedia_tests[..]);
    }

    #[test]
    fn test_sha3_256() {
        let wikipedia_tests = [
            Test {
                input: "",
                output_str: "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog",
                output_str: "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog.",
                output_str: "a80f839cd4f83f6c3dafc87feae470045e4eb0d366397d5c6ce34ba1739f734d",
            },
        ];
        test_hash(Sha3_256::new(), &wikipedia_tests[..]);
    }

    #[test]
    fn test_sha3_384() {
        let wikipedia_tests = [
            Test {
                input: "",
                output_str: "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog",
                output_str: "7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog.",
                output_str: "1a34d81695b622df178bc74df7124fe12fac0f64ba5250b78b99c1273d4b080168e10652894ecad5f1f4d5b965437fb9",
            },
        ];
        test_hash(Sha3_384::new(), &wikipedia_tests[..]);
    }

    #[test]
    fn test_sha3_512() {
        let wikipedia_tests = [
            Test {
                input: "",
                output_str: "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog",
                output_str: "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog.",
                output_str: "18f4f4bd419603f95538837003d9d254c26c23765565162247483f65c50303597bc9ce4d289f21d1c2f1f458828e33dc442100331b35e7eb031b5d38ba6460f8"
            },
        ];
        test_hash(Sha3_512::new(), &wikipedia_tests[..]);
    }

    #[test]
    fn test_keccak_512() {
        let wikipedia_tests = [
            Test {
                input: "",
                output_str: "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog",
                output_str: "d135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog.",
                output_str: "ab7192d2b11f51c7dd744e7b3441febf397ca07bf812cceae122ca4ded6387889064f8db9230f173f6d1ab6e24b6e50f065b039f799f5592360a6558eb52d760"
            },
        ];
        test_hash(Keccak512::new(), &wikipedia_tests[..]);
    }
}
