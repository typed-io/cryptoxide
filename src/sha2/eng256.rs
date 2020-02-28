use crate::cryptoutil::{read_u32v_be, write_u32v_be};

use crate::simd::u32x4;

pub(super) const STATE_LEN: usize = 8;
pub(super) const BLOCK_LEN: usize = 16;
pub(super) const BLOCK_LEN_BYTES: usize = BLOCK_LEN * core::mem::size_of::<u32>();

/// Not an intrinsic, but works like an unaligned load.
#[inline]
fn sha256load(v2: u32x4, v3: u32x4) -> u32x4 {
    u32x4(v3.3, v2.0, v2.1, v2.2)
}

/// Not an intrinsic, but useful for swapping vectors.
#[inline]
fn sha256swap(v0: u32x4) -> u32x4 {
    u32x4(v0.2, v0.3, v0.0, v0.1)
}

/// Emulates `llvm.x86.sha256msg1` intrinsic.
//#[inline]
fn sha256msg1(v0: u32x4, v1: u32x4) -> u32x4 {
    // sigma 0 on vectors
    #[inline]
    fn sigma0x4(x: u32x4) -> u32x4 {
        ((x >> u32x4(7, 7, 7, 7)) | (x << u32x4(25, 25, 25, 25)))
            ^ ((x >> u32x4(18, 18, 18, 18)) | (x << u32x4(14, 14, 14, 14)))
            ^ (x >> u32x4(3, 3, 3, 3))
    }

    v0 + sigma0x4(sha256load(v0, v1))
}

/// Emulates `llvm.x86.sha256msg2` intrinsic.
//#[inline]
fn sha256msg2(v4: u32x4, v3: u32x4) -> u32x4 {
    macro_rules! sigma1 {
        ($a:expr) => {
            $a.rotate_right(17) ^ $a.rotate_right(19) ^ ($a >> 10)
        };
    }

    let u32x4(x3, x2, x1, x0) = v4;
    let u32x4(w15, w14, _, _) = v3;

    let w16 = x0.wrapping_add(sigma1!(w14));
    let w17 = x1.wrapping_add(sigma1!(w15));
    let w18 = x2.wrapping_add(sigma1!(w16));
    let w19 = x3.wrapping_add(sigma1!(w17));

    u32x4(w19, w18, w17, w16)
}

/// Emulates `llvm.x86.sha256rnds2` intrinsic.
//#[inline]
fn digest_round_x2(cdgh: u32x4, abef: u32x4, wk: u32x4) -> u32x4 {
    macro_rules! big_sigma0 {
        ($a:expr) => {
            ($a.rotate_right(2) ^ $a.rotate_right(13) ^ $a.rotate_right(22))
        };
    }
    macro_rules! big_sigma1 {
        ($a:expr) => {
            ($a.rotate_right(6) ^ $a.rotate_right(11) ^ $a.rotate_right(25))
        };
    }
    macro_rules! bool3ary_202 {
        ($a:expr, $b:expr, $c:expr) => {
            $c ^ ($a & ($b ^ $c))
        };
    } // Choose, MD5F, SHA1C
    macro_rules! bool3ary_232 {
        ($a:expr, $b:expr, $c:expr) => {
            ($a & $b) ^ ($a & $c) ^ ($b & $c)
        };
    } // Majority, SHA1M

    let u32x4(_, _, wk1, wk0) = wk;
    let u32x4(a0, b0, e0, f0) = abef;
    let u32x4(c0, d0, g0, h0) = cdgh;

    // a round
    let x0 = big_sigma1!(e0)
        .wrapping_add(bool3ary_202!(e0, f0, g0))
        .wrapping_add(wk0)
        .wrapping_add(h0);
    let y0 = big_sigma0!(a0).wrapping_add(bool3ary_232!(a0, b0, c0));
    let (a1, b1, c1, d1, e1, f1, g1, h1) = (
        x0.wrapping_add(y0),
        a0,
        b0,
        c0,
        x0.wrapping_add(d0),
        e0,
        f0,
        g0,
    );

    // a round
    let x1 = big_sigma1!(e1)
        .wrapping_add(bool3ary_202!(e1, f1, g1))
        .wrapping_add(wk1)
        .wrapping_add(h1);
    let y1 = big_sigma0!(a1).wrapping_add(bool3ary_232!(a1, b1, c1));
    let (a2, b2, _, _, e2, f2, _, _) = (
        x1.wrapping_add(y1),
        a1,
        b1,
        c1,
        x1.wrapping_add(d1),
        e1,
        f1,
        g1,
    );

    u32x4(a2, b2, e2, f2)
}

/// Process a block with the SHA-256 algorithm.
fn digest_block_u32(state: &mut [u32; STATE_LEN], block: &[u32; BLOCK_LEN]) {
    let k = &K32X4;

    macro_rules! schedule {
        ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {
            sha256msg2(sha256msg1($v0, $v1) + sha256load($v2, $v3), $v3)
        };
    }

    macro_rules! rounds4 {
        ($abef:ident, $cdgh:ident, $rest:expr) => {{
            $cdgh = digest_round_x2($cdgh, $abef, $rest);
            $abef = digest_round_x2($abef, $cdgh, sha256swap($rest));
        }};
    }

    let mut abef = u32x4(state[0], state[1], state[4], state[5]);
    let mut cdgh = u32x4(state[2], state[3], state[6], state[7]);

    // Rounds 0..64
    let mut w0 = u32x4(block[3], block[2], block[1], block[0]);
    rounds4!(abef, cdgh, k[0] + w0);
    let mut w1 = u32x4(block[7], block[6], block[5], block[4]);
    rounds4!(abef, cdgh, k[1] + w1);
    let mut w2 = u32x4(block[11], block[10], block[9], block[8]);
    rounds4!(abef, cdgh, k[2] + w2);
    let mut w3 = u32x4(block[15], block[14], block[13], block[12]);
    rounds4!(abef, cdgh, k[3] + w3);
    let mut w4 = schedule!(w0, w1, w2, w3);
    rounds4!(abef, cdgh, k[4] + w4);
    w0 = schedule!(w1, w2, w3, w4);
    rounds4!(abef, cdgh, k[5] + w0);
    w1 = schedule!(w2, w3, w4, w0);
    rounds4!(abef, cdgh, k[6] + w1);
    w2 = schedule!(w3, w4, w0, w1);
    rounds4!(abef, cdgh, k[7] + w2);
    w3 = schedule!(w4, w0, w1, w2);
    rounds4!(abef, cdgh, k[8] + w3);
    w4 = schedule!(w0, w1, w2, w3);
    rounds4!(abef, cdgh, k[9] + w4);
    w0 = schedule!(w1, w2, w3, w4);
    rounds4!(abef, cdgh, k[10] + w0);
    w1 = schedule!(w2, w3, w4, w0);
    rounds4!(abef, cdgh, k[11] + w1);
    w2 = schedule!(w3, w4, w0, w1);
    rounds4!(abef, cdgh, k[12] + w2);
    w3 = schedule!(w4, w0, w1, w2);
    rounds4!(abef, cdgh, k[13] + w3);
    w4 = schedule!(w0, w1, w2, w3);
    rounds4!(abef, cdgh, k[14] + w4);
    w0 = schedule!(w1, w2, w3, w4);
    rounds4!(abef, cdgh, k[15] + w0);

    let u32x4(a, b, e, f) = abef;
    let u32x4(c, d, g, h) = cdgh;

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

// A structure that represents that state of a digest computation for
// the SHA-2 32 bits family of digest functions
#[derive(Clone)]
pub(super) struct Engine {
    h: [u32; STATE_LEN],
}

impl Engine {
    pub(super) fn new(h: &[u32; STATE_LEN]) -> Self {
        Self { h: *h }
    }

    pub(super) fn reset(&mut self, h: &[u32; STATE_LEN]) {
        self.h = *h;
    }

    /// Process a block with the SHA-2 32bits algorithm.
    #[allow(dead_code)]
    pub fn block(&mut self, block: &[u32; BLOCK_LEN]) {
        digest_block_u32(&mut self.h, block);
    }

    /// Process a block in bytes with the SHA-2 32bits algorithm.
    pub fn block_byteslice(&mut self, block: &[u8]) {
        assert_eq!(block.len(), BLOCK_LEN_BYTES);
        let mut block2 = [0u32; BLOCK_LEN];
        read_u32v_be(&mut block2[..], block);
        digest_block_u32(&mut self.h, &block2);
    }

    #[allow(dead_code)]
    pub(super) fn output_224bits(&self, out: &mut [u8; 28]) {
        write_u32v_be(out, &self.h[0..7]);
    }

    #[allow(dead_code)]
    pub(super) fn output_256bits(&self, out: &mut [u8; 32]) {
        write_u32v_be(out, &self.h);
    }

    pub(super) fn output_224bits_at(&self, out: &mut [u8]) {
        write_u32v_be(&mut out[0..28], &self.h[0..7]);
    }

    pub(super) fn output_256bits_at(&self, out: &mut [u8]) {
        write_u32v_be(&mut out[0..32], &self.h);
    }
}

/// Constants necessary for SHA-256 family of digests.
pub const K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Constants necessary for SHA-256 family of digests.
pub const K32X4: [u32x4; 16] = [
    u32x4(K32[3], K32[2], K32[1], K32[0]),
    u32x4(K32[7], K32[6], K32[5], K32[4]),
    u32x4(K32[11], K32[10], K32[9], K32[8]),
    u32x4(K32[15], K32[14], K32[13], K32[12]),
    u32x4(K32[19], K32[18], K32[17], K32[16]),
    u32x4(K32[23], K32[22], K32[21], K32[20]),
    u32x4(K32[27], K32[26], K32[25], K32[24]),
    u32x4(K32[31], K32[30], K32[29], K32[28]),
    u32x4(K32[35], K32[34], K32[33], K32[32]),
    u32x4(K32[39], K32[38], K32[37], K32[36]),
    u32x4(K32[43], K32[42], K32[41], K32[40]),
    u32x4(K32[47], K32[46], K32[45], K32[44]),
    u32x4(K32[51], K32[50], K32[49], K32[48]),
    u32x4(K32[55], K32[54], K32[53], K32[52]),
    u32x4(K32[59], K32[58], K32[57], K32[56]),
    u32x4(K32[63], K32[62], K32[61], K32[60]),
];
