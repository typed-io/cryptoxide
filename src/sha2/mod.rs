// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/*!
An implementation of the SHA-2 cryptographic hash algorithms.

There are 6 standard algorithms specified in the SHA-2 standard:

 * `Sha224`, which is the 32-bit `Sha256` algorithm with the result truncated to 224 bits.
 * `Sha256`, which is the 32-bit `Sha256` algorithm.
 * `Sha384`, which is the 64-bit `Sha512` algorithm with the result truncated to 384 bits.
 * `Sha512`, which is the 64-bit `Sha512` algorithm.
 * `Sha512Trunc224`, which is the 64-bit `Sha512` algorithm with the result truncated to 224 bits.
 * `Sha512Trunc256`, which is the 64-bit `Sha512` algorithm with the result truncated to 256 bits.

Algorithmically, there are only 2 core algorithms: `Sha256` and `Sha512`.
All other algorithms are just applications of these with different initial hash
values, and truncated to different digest bit lengths.

# Usage

An example of using `Sha256` is:

```rust
use self::cryptoxide::digest::Digest;
use self::cryptoxide::sha2::Sha256;

// create a Sha256 object
let mut hasher = Sha256::new();

// write input message
hasher.input_str("hello world");

// read hash digest
let hex = hasher.result_str();

assert_eq!(hex,
           concat!("b94d27b9934d3e08a52e52d7da7dabfa",
                   "c484efe37a5380ee9088f7ace2efcde9"));
```

An example of using `Sha512` is:

```rust
use self::cryptoxide::digest::Digest;
use self::cryptoxide::sha2::Sha512;

// create a Sha512 object
let mut hasher = Sha512::new();

// write input message
hasher.input_str("hello world");

// read hash digest
let hex = hasher.result_str();

assert_eq!(hex,
           concat!("309ecc489c12d6eb4cc40f50c902f2b4",
                   "d0ed77ee511a7c7a9bcd3ca86d4cd86f",
                   "989dd35bc5ff499670da34255b45b0cf",
                   "d830e81f605dcf7dc5542e93ae9cd76f"));
```

 */

mod eng256;
mod eng512;
mod impl256;
mod impl512;
mod initials;

use crate::cryptoutil::{write_u128_be, write_u64_be, FixedBuffer};
use crate::digest::Digest;
use initials::*;

macro_rules! digest {
    ($name: ident, $init: ident, $output_fn: ident, $output_bits: expr, $block_size: expr, $state: ident) => {
        /// The hash algorithm context
        #[derive(Clone)]
        pub struct $name {
            engine: $init,
        }

        impl $name {
            /// Create a new hashing algorithm context
            pub fn new() -> Self {
                Self {
                    engine: $init::new(&$state),
                }
            }
        }

        impl Digest for $name {
            fn input(&mut self, d: &[u8]) {
                self.engine.input(d)
            }

            fn result(&mut self, out: &mut [u8]) {
                self.engine.finish();
                self.engine.state.$output_fn(&mut out[0..$output_bits / 8]);
            }

            fn reset(&mut self) {
                self.engine.reset(&$state);
            }

            fn output_bits(&self) -> usize {
                $output_bits
            }

            fn block_size(&self) -> usize {
                $block_size
            }
        }
    };
}

macro_rules! digest512 {
    ($name: ident, $output_fn: ident, $output_bits: expr, $state: ident) => {
        digest!($name, Engine512, $output_fn, $output_bits, 128, $state);
    };
}

macro_rules! digest256 {
    ($name: ident, $output_fn: ident, $output_bits: expr, $state: ident) => {
        digest!($name, Engine256, $output_fn, $output_bits, 64, $state);
    };
}

// A structure that keeps track of the state of the Sha-512 operation and contains the logic
// necessary to perform the final calculations.
#[derive(Clone)]
struct Engine512 {
    length_bits: u128,
    buffer: FixedBuffer<128>,
    state: eng512::Engine,
    finished: bool,
}

impl Engine512 {
    fn new(h: &[u64; eng512::STATE_LEN]) -> Engine512 {
        Engine512 {
            length_bits: 0,
            buffer: FixedBuffer::new(),
            state: eng512::Engine::new(h),
            finished: false,
        }
    }

    fn reset(&mut self, h: &[u64; eng512::STATE_LEN]) {
        self.length_bits = 0;
        self.buffer.reset();
        self.state.reset(h);
        self.finished = false;
    }

    fn input(&mut self, input: &[u8]) {
        assert!(!self.finished);
        self.length_bits += (input.len() as u128) << 3;
        let self_state = &mut self.state;
        self.buffer.input(input, |input| self_state.blocks(input));
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }

        let self_state = &mut self.state;
        self.buffer
            .standard_padding(16, |input| self_state.blocks(input));
        write_u128_be(self.buffer.next(16), self.length_bits);
        self_state.blocks(self.buffer.full_buffer());

        self.finished = true;
    }
}

// A structure that keeps track of the state of the Sha-256 operation and contains the logic
// necessary to perform the final calculations.
#[derive(Clone)]
struct Engine256 {
    length_bits: u64,
    buffer: FixedBuffer<64>,
    state: eng256::Engine,
    finished: bool,
}

impl Engine256 {
    fn new(h: &[u32; eng256::STATE_LEN]) -> Engine256 {
        Engine256 {
            length_bits: 0,
            buffer: FixedBuffer::new(),
            state: eng256::Engine::new(h),
            finished: false,
        }
    }

    fn reset(&mut self, h: &[u32; eng256::STATE_LEN]) {
        self.length_bits = 0;
        self.buffer.reset();
        self.state.reset(h);
        self.finished = false;
    }

    fn input(&mut self, input: &[u8]) {
        assert!(!self.finished);
        self.length_bits += (input.len() as u64) << 3;
        let self_state = &mut self.state;
        self.buffer.input(input, |input| self_state.blocks(input));
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }

        let self_state = &mut self.state;
        self.buffer
            .standard_padding(8, |input| self_state.blocks(input));
        write_u64_be(self.buffer.next(8), self.length_bits);
        self_state.blocks(self.buffer.full_buffer());

        self.finished = true;
    }
}

digest512!(Sha512, output_512bits_at, 512, H512);
digest512!(Sha384, output_384bits_at, 384, H384);
digest512!(Sha512Trunc256, output_256bits_at, 256, H512_TRUNC_256);
digest512!(Sha512Trunc224, output_224bits_at, 224, H512_TRUNC_224);
digest256!(Sha256, output_256bits_at, 256, H256);
digest256!(Sha224, output_224bits_at, 224, H224);

#[cfg(test)]
mod tests {
    use super::{Sha224, Sha256, Sha384, Sha512, Sha512Trunc224, Sha512Trunc256};
    use crate::cryptoutil::test::test_digest_1million_random;
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

        // Test that an arbitrary large message has the same result as one with small piece
        let mut v = [0u8; 512];
        for (i, vi) in v.iter_mut().enumerate() {
            *vi = i as u8;
        }
        sh.input(&v[..]);
        let out_str = sh.result_str();
        sh.reset();

        for i in 0..v.len() / 16 {
            sh.input(&v[i * 16..i * 16 + 16]);
        }
        let out_str2 = sh.result_str();

        assert_eq!(&out_str, &out_str2);
        //assert_eq!(0, 1);
    }

    #[test]
    fn test_sha512() {
        // Examples from wikipedia
        let wikipedia_tests = [
            Test {
                input: "",
                output_str: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog",
                output_str: "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog.",
                output_str: "91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed"
            },
        ];
        test_hash(Sha512::new(), &wikipedia_tests[..]);
    }

    #[test]
    fn test_sha384() {
        // Examples from wikipedia
        let wikipedia_tests = [
            Test {
                input: "",
                output_str: "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog",
                output_str: "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1"
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog.",
                output_str: "ed892481d8272ca6df370bf706e4d7bc1b5739fa2177aae6c50e946678718fc67a7af2819a021c2fc34e91bdb63409d7"
            },
        ];

        test_hash(Sha384::new(), &wikipedia_tests);
    }

    #[test]
    fn test_sha512_256() {
        // Examples from wikipedia
        let wikipedia_tests = [
            Test {
                input: "",
                output_str: "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog",
                output_str: "dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog.",
                output_str: "1546741840f8a492b959d9b8b2344b9b0eb51b004bba35c0aebaac86d45264c3",
            },
        ];
        test_hash(Sha512Trunc256::new(), &wikipedia_tests);
    }

    #[test]
    fn test_sha512_224() {
        // Examples from wikipedia
        let wikipedia_tests = [
            Test {
                input: "",
                output_str: "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog",
                output_str: "944cd2847fb54558d4775db0485a50003111c8e5daa63fe722c6aa37",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog.",
                output_str: "6d6a9279495ec4061769752e7ff9c68b6b0b3c5a281b7917ce0572de",
            },
        ];
        test_hash(Sha512Trunc224::new(), &wikipedia_tests);
    }

    #[test]
    fn test_sha256() {
        // Examples from wikipedia
        let wikipedia_tests = [
            Test {
                input: "",
                output_str: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog",
                output_str: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog.",
                output_str: "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
            },
        ];
        test_hash(Sha256::new(), &wikipedia_tests);
    }

    #[test]
    fn test_sha224() {
        // Examples from wikipedia
        let wikipedia_tests = [
            Test {
                input: "",
                output_str: "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog",
                output_str: "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog.",
                output_str: "619cba8e8e05826e9b8c519c0a5c68f4fb653e8a3d8aa04bb2c8cd4c",
            },
        ];
        test_hash(Sha224::new(), &wikipedia_tests);
    }

    #[test]
    fn test_1million_random_sha512() {
        let mut sh = Sha512::new();
        test_digest_1million_random(
            &mut sh,
            128,
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
    }

    #[test]
    fn test_1million_random_sha256() {
        let mut sh = Sha256::new();
        test_digest_1million_random(
            &mut sh,
            64,
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        );
    }
}

#[cfg(all(test, feature = "with-bench"))]
mod bench {
    use super::eng256;
    use super::eng512;
    use super::{Sha256, Sha512};
    use crate::digest::Digest;
    use test::Bencher;

    #[bench]
    pub fn sha256_block(bh: &mut Bencher) {
        let mut state = eng256::Engine::new(&[0u32; eng256::STATE_LEN]);
        let block = [1u8; 64];
        bh.iter(|| {
            state.blocks(&block);
        });
        bh.bytes = 64u64;
    }

    #[bench]
    pub fn sha512_block(bh: &mut Bencher) {
        let mut state = eng512::Engine::new(&[0u64; eng512::STATE_LEN]);
        let block = [1u8; 128];
        bh.iter(|| {
            state.blocks(&block);
        });
        bh.bytes = 128u64;
    }

    #[bench]
    pub fn sha256_10(bh: &mut Bencher) {
        let mut sh = Sha256::new();
        let bytes = [1u8; 10];
        bh.iter(|| {
            sh.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha256_1k(bh: &mut Bencher) {
        let mut sh = Sha256::new();
        let bytes = [1u8; 1000];
        bh.iter(|| {
            sh.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha256_64k(bh: &mut Bencher) {
        let mut sh = Sha256::new();
        let bytes = [1u8; 65536];
        bh.iter(|| {
            sh.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha512_10(bh: &mut Bencher) {
        let mut sh = Sha512::new();
        let bytes = [1u8; 10];
        bh.iter(|| {
            sh.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha512_1k(bh: &mut Bencher) {
        let mut sh = Sha512::new();
        let bytes = [1u8; 1024];
        bh.iter(|| {
            sh.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha512_64k(bh: &mut Bencher) {
        let mut sh = Sha512::new();
        let bytes = [1u8; 65536];
        bh.iter(|| {
            sh.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }
}
