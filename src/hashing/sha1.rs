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
//! use cryptoxide::hashing::sha1;
//!
//! let digest = sha1::Context::new().update(b"hello world").finalize();
//! ```

use crate::cryptoutil::{read_u32v_be, write_u32_be, FixedBuffer};
use crate::simd::u32x4;

const STATE_LEN: usize = 5;
const BLOCK_LEN: usize = 16;

const K0: u32 = 0x5A827999u32;
const K1: u32 = 0x6ED9EBA1u32;
const K2: u32 = 0x8F1BBCDCu32;
const K3: u32 = 0xCA62C1D6u32;

/// Not an intrinsic, but gets the first element of a vector.
#[inline]
pub fn sha1_first(w0: u32x4) -> u32 {
    w0.0
}

/// Not an intrinsic, but adds a word to the first element of a vector.
#[inline]
pub fn sha1_first_add(e: u32, w0: u32x4) -> u32x4 {
    let u32x4(a, b, c, d) = w0;
    u32x4(e.wrapping_add(a), b, c, d)
}

/// Emulates `llvm.x86.sha1msg1` intrinsic.
fn sha1msg1(a: u32x4, b: u32x4) -> u32x4 {
    let u32x4(_, _, w2, w3) = a;
    let u32x4(w4, w5, _, _) = b;
    a ^ u32x4(w2, w3, w4, w5)
}

/// Emulates `llvm.x86.sha1msg2` intrinsic.
fn sha1msg2(a: u32x4, b: u32x4) -> u32x4 {
    let u32x4(x0, x1, x2, x3) = a;
    let u32x4(_, w13, w14, w15) = b;

    let w16 = (x0 ^ w13).rotate_left(1);
    let w17 = (x1 ^ w14).rotate_left(1);
    let w18 = (x2 ^ w15).rotate_left(1);
    let w19 = (x3 ^ w16).rotate_left(1);

    u32x4(w16, w17, w18, w19)
}

/// Performs 4 rounds of the message schedule update.
pub fn sha1_schedule_x4(v0: u32x4, v1: u32x4, v2: u32x4, v3: u32x4) -> u32x4 {
    sha1msg2(sha1msg1(v0, v1) ^ v2, v3)
}

/// Emulates `llvm.x86.sha1nexte` intrinsic.
#[inline]
pub fn sha1_first_half(abcd: u32x4, msg: u32x4) -> u32x4 {
    sha1_first_add(sha1_first(abcd).rotate_left(30), msg)
}

/// Emulates `llvm.x86.sha1rnds4` intrinsic.
/// Performs 4 rounds of the message block digest.
pub fn sha1_digest_round_x4(abcd: u32x4, work: u32x4, i: i8) -> u32x4 {
    const K0V: u32x4 = u32x4(K0, K0, K0, K0);
    const K1V: u32x4 = u32x4(K1, K1, K1, K1);
    const K2V: u32x4 = u32x4(K2, K2, K2, K2);
    const K3V: u32x4 = u32x4(K3, K3, K3, K3);

    match i {
        0 => sha1rnds4c(abcd, work + K0V),
        1 => sha1rnds4p(abcd, work + K1V),
        2 => sha1rnds4m(abcd, work + K2V),
        3 => sha1rnds4p(abcd, work + K3V),
        _ => panic!("unknown icosaround index"),
    }
}

/// Not an intrinsic, but helps emulate `llvm.x86.sha1rnds4` intrinsic.
fn sha1rnds4c(abcd: u32x4, msg: u32x4) -> u32x4 {
    let u32x4(mut a, mut b, mut c, mut d) = abcd;
    let u32x4(t, u, v, w) = msg;
    let mut e = 0u32;

    macro_rules! bool3ary_202 {
        ($a:expr, $b:expr, $c:expr) => {
            ($c ^ ($a & ($b ^ $c)))
        };
    } // Choose, MD5F, SHA1C

    e = e
        .wrapping_add(a.rotate_left(5))
        .wrapping_add(bool3ary_202!(b, c, d))
        .wrapping_add(t);
    b = b.rotate_left(30);

    d = d
        .wrapping_add(e.rotate_left(5))
        .wrapping_add(bool3ary_202!(a, b, c))
        .wrapping_add(u);
    a = a.rotate_left(30);

    c = c
        .wrapping_add(d.rotate_left(5))
        .wrapping_add(bool3ary_202!(e, a, b))
        .wrapping_add(v);
    e = e.rotate_left(30);

    b = b
        .wrapping_add(c.rotate_left(5))
        .wrapping_add(bool3ary_202!(d, e, a))
        .wrapping_add(w);
    d = d.rotate_left(30);

    u32x4(b, c, d, e)
}

/// Not an intrinsic, but helps emulate `llvm.x86.sha1rnds4` intrinsic.
fn sha1rnds4p(abcd: u32x4, msg: u32x4) -> u32x4 {
    let u32x4(mut a, mut b, mut c, mut d) = abcd;
    let u32x4(t, u, v, w) = msg;
    let mut e = 0u32;

    macro_rules! bool3ary_150 {
        ($a:expr, $b:expr, $c:expr) => {
            ($a ^ $b ^ $c)
        };
    } // Parity, XOR, MD5H, SHA1P

    e = e
        .wrapping_add(a.rotate_left(5))
        .wrapping_add(bool3ary_150!(b, c, d))
        .wrapping_add(t);
    b = b.rotate_left(30);

    d = d
        .wrapping_add(e.rotate_left(5))
        .wrapping_add(bool3ary_150!(a, b, c))
        .wrapping_add(u);
    a = a.rotate_left(30);

    c = c
        .wrapping_add(d.rotate_left(5))
        .wrapping_add(bool3ary_150!(e, a, b))
        .wrapping_add(v);
    e = e.rotate_left(30);

    b = b
        .wrapping_add(c.rotate_left(5))
        .wrapping_add(bool3ary_150!(d, e, a))
        .wrapping_add(w);
    d = d.rotate_left(30);

    u32x4(b, c, d, e)
}

/// Not an intrinsic, but helps emulate `llvm.x86.sha1rnds4` intrinsic.
fn sha1rnds4m(abcd: u32x4, msg: u32x4) -> u32x4 {
    let u32x4(mut a, mut b, mut c, mut d) = abcd;
    let u32x4(t, u, v, w) = msg;
    let mut e = 0u32;

    macro_rules! bool3ary_232 {
        ($a:expr, $b:expr, $c:expr) => {
            ($a & $b) ^ ($a & $c) ^ ($b & $c)
        };
    } // Majority, SHA1M

    e = e
        .wrapping_add(a.rotate_left(5))
        .wrapping_add(bool3ary_232!(b, c, d))
        .wrapping_add(t);
    b = b.rotate_left(30);

    d = d
        .wrapping_add(e.rotate_left(5))
        .wrapping_add(bool3ary_232!(a, b, c))
        .wrapping_add(u);
    a = a.rotate_left(30);

    c = c
        .wrapping_add(d.rotate_left(5))
        .wrapping_add(bool3ary_232!(e, a, b))
        .wrapping_add(v);
    e = e.rotate_left(30);

    b = b
        .wrapping_add(c.rotate_left(5))
        .wrapping_add(bool3ary_232!(d, e, a))
        .wrapping_add(w);
    d = d.rotate_left(30);

    u32x4(b, c, d, e)
}

/// Process a block with the SHA-1 algorithm.
fn digest_block_u32(state: &mut [u32; 5], block: &[u32; 16]) {
    macro_rules! schedule {
        ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {
            sha1msg2(sha1msg1($v0, $v1) ^ $v2, $v3)
        };
    }

    macro_rules! rounds4 {
        ($h0:ident, $h1:ident, $wk:expr, $i:expr) => {
            sha1_digest_round_x4($h0, sha1_first_half($h1, $wk), $i)
        };
    }

    // Rounds 0..20
    let mut h0 = u32x4(state[0], state[1], state[2], state[3]);
    let mut w0 = u32x4(block[0], block[1], block[2], block[3]);
    let mut h1 = sha1_digest_round_x4(h0, sha1_first_add(state[4], w0), 0);
    let mut w1 = u32x4(block[4], block[5], block[6], block[7]);
    h0 = rounds4!(h1, h0, w1, 0);
    let mut w2 = u32x4(block[8], block[9], block[10], block[11]);
    h1 = rounds4!(h0, h1, w2, 0);
    let mut w3 = u32x4(block[12], block[13], block[14], block[15]);
    h0 = rounds4!(h1, h0, w3, 0);
    let mut w4 = schedule!(w0, w1, w2, w3);
    h1 = rounds4!(h0, h1, w4, 0);

    // Rounds 20..40
    w0 = schedule!(w1, w2, w3, w4);
    h0 = rounds4!(h1, h0, w0, 1);
    w1 = schedule!(w2, w3, w4, w0);
    h1 = rounds4!(h0, h1, w1, 1);
    w2 = schedule!(w3, w4, w0, w1);
    h0 = rounds4!(h1, h0, w2, 1);
    w3 = schedule!(w4, w0, w1, w2);
    h1 = rounds4!(h0, h1, w3, 1);
    w4 = schedule!(w0, w1, w2, w3);
    h0 = rounds4!(h1, h0, w4, 1);

    // Rounds 40..60
    w0 = schedule!(w1, w2, w3, w4);
    h1 = rounds4!(h0, h1, w0, 2);
    w1 = schedule!(w2, w3, w4, w0);
    h0 = rounds4!(h1, h0, w1, 2);
    w2 = schedule!(w3, w4, w0, w1);
    h1 = rounds4!(h0, h1, w2, 2);
    w3 = schedule!(w4, w0, w1, w2);
    h0 = rounds4!(h1, h0, w3, 2);
    w4 = schedule!(w0, w1, w2, w3);
    h1 = rounds4!(h0, h1, w4, 2);

    // Rounds 60..80
    w0 = schedule!(w1, w2, w3, w4);
    h0 = rounds4!(h1, h0, w0, 3);
    w1 = schedule!(w2, w3, w4, w0);
    h1 = rounds4!(h0, h1, w1, 3);
    w2 = schedule!(w3, w4, w0, w1);
    h0 = rounds4!(h1, h0, w2, 3);
    w3 = schedule!(w4, w0, w1, w2);
    h1 = rounds4!(h0, h1, w3, 3);
    w4 = schedule!(w0, w1, w2, w3);
    h0 = rounds4!(h1, h0, w4, 3);

    let e = sha1_first(h1).rotate_left(30);
    let u32x4(a, b, c, d) = h0;

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

/// Process a block with the SHA-1 algorithm. (See more...)
///
/// SHA-1 is a cryptographic hash function, and as such, it operates
/// on an arbitrary number of bytes. This function operates on a fixed
/// number of bytes. If you call this function with anything other than
/// 64 bytes, then it will panic! This function takes two arguments:
///
/// * `state` is reference to an **array** of 5 words.
/// * `block` is reference to a **slice** of 64 bytes.
///
/// If you want the function that performs a message digest on an arbitrary
/// number of bytes, then see also the `Sha1` struct above.
///
/// # Implementation
///
/// First, some background. Both ARM and Intel are releasing documentation
/// that they plan to include instruction set extensions for SHA1 and SHA256
/// sometime in the near future. Second, LLVM won't lower these intrinsics yet,
/// so these functions were written emulate these instructions. Finally,
/// the block function implemented with these emulated intrinsics turned out
/// to be quite fast! What follows is a discussion of this CPU-level view
/// of the SHA-1 algorithm and how it relates to the mathematical definition.
///
/// The SHA instruction set extensions can be divided up into two categories:
///
/// * message work schedule update calculation ("schedule" v., "work" n.)
/// * message block 80-round digest calculation ("digest" v., "block" n.)
///
/// The schedule-related functions can be used to easily perform 4 rounds
/// of the message work schedule update calculation, as shown below:
///
/// ```no_check
/// macro_rules! schedule_x4 {
///     ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => (
///         sha1msg2(sha1msg1($v0, $v1) ^ $v2, $v3)
///     )
/// }
///
/// macro_rules! round_x4 {
///     ($h0:ident, $h1:ident, $wk:expr, $i:expr) => (
///         sha1rnds4($h0, sha1_first_half($h1, $wk), $i)
///     )
/// }
/// ```
///
/// and also shown above is how the digest-related functions can be used to
/// perform 4 rounds of the message block digest calculation.
///
fn digest_block(state: &mut [u32; 5], block: &[u8]) {
    assert_eq!(block.len(), BLOCK_LEN * 4);
    let mut block2 = [0u32; BLOCK_LEN];
    read_u32v_be(&mut block2[..], block);
    digest_block_u32(state, &block2);
}

fn digest_blocks(state: &mut [u32; 5], block: &[u8]) {
    for b in block.chunks(BLOCK_LEN * 4) {
        digest_block(state, b);
    }
}

fn mk_result(st: &mut Context, rs: &mut [u8; 20]) {
    let st_h = &mut st.h;
    st.buffer
        .standard_padding(8, |d| digest_block(&mut *st_h, d));
    *st.buffer.next::<8>() = (st.processed_bytes << 3).to_be_bytes();
    digest_block(st_h, st.buffer.full_buffer());

    write_u32_be(&mut rs[0..4], st.h[0]);
    write_u32_be(&mut rs[4..8], st.h[1]);
    write_u32_be(&mut rs[8..12], st.h[2]);
    write_u32_be(&mut rs[12..16], st.h[3]);
    write_u32_be(&mut rs[16..20], st.h[4]);
}

/// Sha1 Algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha1;

impl Sha1 {
    pub const OUTPUT_BITS: usize = 160;
    pub const BLOCK_BYTES: usize = 64;

    /// Create a new context for this algorithm
    pub const fn new() -> Context {
        Context::new()
    }
}

/// Structure representing the state of a Sha1 computation
#[derive(Clone)]
pub struct Context {
    h: [u32; STATE_LEN],
    processed_bytes: u64,
    buffer: FixedBuffer<64>,
}

const H0: u32 = 0x67452301;
const H1: u32 = 0xEFCDAB89;
const H2: u32 = 0x98BADCFE;
const H3: u32 = 0x10325476;
const H4: u32 = 0xC3D2E1F0;
const H: [u32; STATE_LEN] = [H0, H1, H2, H3, H4];

impl Context {
    /// Construct a new default SHA1 context
    pub const fn new() -> Self {
        Self {
            h: H,
            processed_bytes: 0u64,
            buffer: FixedBuffer::new(),
        }
    }

    pub fn update(mut self, input: &[u8]) -> Self {
        self.update_mut(input);
        self
    }

    pub fn update_mut(&mut self, input: &[u8]) {
        self.processed_bytes += input.len() as u64;
        let h = &mut self.h;
        self.buffer.input(input, |d| {
            digest_blocks(h, d);
        });
    }

    pub fn finalize(mut self) -> [u8; 20] {
        let mut out = [0; 20];
        mk_result(&mut self, &mut out);
        out
    }

    pub fn reset(&mut self) {
        self.processed_bytes = 0;
        self.h = H;
        self.buffer.reset();
    }

    pub fn finalize_reset(&mut self) -> [u8; 20] {
        let mut out = [0; 20];
        mk_result(self, &mut out);
        self.reset();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{test_hashing, Test};
    use super::*;

    #[test]
    fn test() {
        let tests = [
            // Test messages from FIPS 180-1
            Test {
                input: b"abc",
                output: [
                    0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78,
                    0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D,
                ],
            },
            Test {
                input: b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                output: [
                    0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE, 0x4A, 0xA1, 0xF9,
                    0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1,
                ],
            },
            // Examples from wikipedia
            Test {
                input: b"The quick brown fox jumps over the lazy dog",
                output: [
                    0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb,
                    0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12,
                ],
            },
            Test {
                input: b"The quick brown fox jumps over the lazy cog",
                output: [
                    0xde, 0x9f, 0x2c, 0x7f, 0xd2, 0x5e, 0x1b, 0x3a, 0xfa, 0xd3, 0xe8, 0x5a, 0x0b,
                    0xd1, 0x7d, 0x9b, 0x10, 0x0d, 0xb4, 0xb3,
                ],
            },
        ];

        test_hashing(
            &tests,
            Sha1,
            |_| Context::new(),
            |ctx, input| ctx.update(input),
            |ctx, input| ctx.update_mut(input),
            |ctx| ctx.finalize(),
            |ctx| ctx.finalize_reset(),
            |ctx| ctx.reset(),
        )
    }
}

#[cfg(all(test, feature = "with-bench"))]
mod bench {
    use super::*;
    use test::Bencher;

    #[bench]
    pub fn sha1_block(bh: &mut Bencher) {
        let mut state = [0u32; STATE_LEN];
        let words = [1u32; BLOCK_LEN];
        bh.iter(|| {
            digest_block_u32(&mut state, &words);
        });
        bh.bytes = 64u64;
    }

    #[bench]
    pub fn sha1_10(bh: &mut Bencher) {
        let mut sh = Sha1::new();
        let bytes = [1u8; 10];
        bh.iter(|| {
            sh.update_mut(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha1_1k(bh: &mut Bencher) {
        let mut sh = Sha1::new();
        let bytes = [1u8; 1024];
        bh.iter(|| {
            sh.update_mut(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha1_64k(bh: &mut Bencher) {
        let mut sh = Sha1::new();
        let bytes = [1u8; 65536];
        bh.iter(|| {
            sh.update_mut(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }
}
