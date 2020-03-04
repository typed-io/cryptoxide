use crate::cryptoutil::{read_u32v_le, read_u64v_le};

mod b {
    pub(super) const BLOCK_BYTES: usize = 128;
    pub(super) const MAX_KEYLEN: usize = 64;
    pub(super) const MAX_OUTLEN: usize = 64;
    pub(super) const R1: u32 = 32;
    pub(super) const R2: u32 = 24;
    pub(super) const R3: u32 = 16;
    pub(super) const R4: u32 = 63;

    pub(super) const IV: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    pub(super) const ROUNDS: usize = 12;
}

mod s {
    pub(super) const BLOCK_BYTES: usize = 64;
    pub(super) const MAX_KEYLEN: usize = 32;
    pub(super) const MAX_OUTLEN: usize = 32;
    pub(super) const R1: u32 = 16;
    pub(super) const R2: u32 = 12;
    pub(super) const R3: u32 = 8;
    pub(super) const R4: u32 = 7;

    pub(super) const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];

    pub(super) const ROUNDS: usize = 10;
}

// SIGMA is the same for the b and s variant. except that
// in the B variant, there's a 11th and 12th row that is copy of
// the 1st and 2nd.
pub(super) const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[derive(Clone, PartialEq, Eq)]
pub enum LastBlock {
    Yes,
    No,
}

macro_rules! G {
    ($conmod:ident, $r:expr, $i:expr, $a:expr, $b:expr, $c:expr, $d:expr, $m:expr) => {
        $a = $a.wrapping_add($b).wrapping_add($m[SIGMA[$r][2 * $i + 0]]);
        $d = ($d ^ $a).rotate_right($conmod::R1);
        $c = $c.wrapping_add($d);
        $b = ($b ^ $c).rotate_right($conmod::R2);
        $a = $a.wrapping_add($b).wrapping_add($m[SIGMA[$r][2 * $i + 1]]);
        $d = ($d ^ $a).rotate_right($conmod::R3);
        $c = $c.wrapping_add($d);
        $b = ($b ^ $c).rotate_right($conmod::R4);
    };
}

macro_rules! round {
    ($conmod: ident, $r:expr, $v:expr, $m:expr) => {
        G!($conmod, $r, 0, $v[0], $v[4], $v[8], $v[12], $m);
        G!($conmod, $r, 1, $v[1], $v[5], $v[9], $v[13], $m);
        G!($conmod, $r, 2, $v[2], $v[6], $v[10], $v[14], $m);
        G!($conmod, $r, 3, $v[3], $v[7], $v[11], $v[15], $m);
        G!($conmod, $r, 4, $v[0], $v[5], $v[10], $v[15], $m);
        G!($conmod, $r, 5, $v[1], $v[6], $v[11], $v[12], $m);
        G!($conmod, $r, 6, $v[2], $v[7], $v[8], $v[13], $m);
        G!($conmod, $r, 7, $v[3], $v[4], $v[9], $v[14], $m);
    };
}

macro_rules! compressbody {
    ($conmod: ident, $engine: ident, $t: ident, $read_f: ident, $buf: ident, $last: ident) => {{
        let mut ms: [$t; 16] = [0; 16];
        let mut vs: [$t; 16] = [0; 16];

        $read_f(&mut ms, $buf);

        vs[0..8].copy_from_slice(&$engine.h);
        vs[8..16].copy_from_slice(&$conmod::IV);

        vs[12] ^= $engine.t[0];
        vs[13] ^= $engine.t[1];
        if $last == LastBlock::Yes {
            vs[14] = !vs[14];
        }

        round!($conmod, 0, vs, ms);
        round!($conmod, 1, vs, ms);
        round!($conmod, 2, vs, ms);
        round!($conmod, 3, vs, ms);
        round!($conmod, 4, vs, ms);
        round!($conmod, 5, vs, ms);
        round!($conmod, 6, vs, ms);
        round!($conmod, 7, vs, ms);
        round!($conmod, 8, vs, ms);
        round!($conmod, 9, vs, ms);
        if $conmod::ROUNDS == 12 {
            round!($conmod, 10, vs, ms);
            round!($conmod, 11, vs, ms);
        }

        for (h_elem, (v_low, v_high)) in $engine
            .h
            .iter_mut()
            .zip(vs[0..8].iter().zip(vs[8..16].iter()))
        {
            *h_elem = *h_elem ^ *v_low ^ *v_high;
        }
    }};
}

/// Blake2b Context
#[derive(Clone)]
pub struct EngineB {
    pub h: [u64; 8],
    t: [u64; 2],
}

impl EngineB {
    pub const BLOCK_BYTES: usize = b::BLOCK_BYTES;
    pub const BLOCK_BYTES_NATIVE: u64 = b::BLOCK_BYTES as u64;
    pub const MAX_OUTLEN: usize = b::MAX_OUTLEN;
    pub const MAX_KEYLEN: usize = b::MAX_KEYLEN;

    pub fn new(outlen: usize, keylen: usize) -> Self {
        assert!(outlen > 0 && outlen <= b::MAX_OUTLEN);
        assert!(keylen <= b::MAX_KEYLEN);
        let mut h = b::IV;
        h[0] ^= 0x01010000 ^ ((keylen as u64) << 8) ^ outlen as u64;
        Self { h, t: [0, 0] }
    }

    pub fn reset(&mut self, outlen: usize, keylen: usize) {
        self.h = b::IV;
        self.h[0] ^= 0x01010000 ^ ((keylen as u64) << 8) ^ outlen as u64;
        self.t[0] = 0;
        self.t[1] = 0;
    }

    pub fn compress(&mut self, buf: &[u8], last: LastBlock) {
        compressbody!(b, self, u64, read_u64v_le, buf, last)
    }

    #[inline]
    pub fn increment_counter(&mut self, inc: u64) {
        self.t[0] += inc;
        self.t[1] += if self.t[0] < inc { 1 } else { 0 };
    }
}

/// Blake2s Context
#[derive(Clone)]
pub struct EngineS {
    pub h: [u32; 8],
    t: [u32; 2],
}

impl EngineS {
    pub const BLOCK_BYTES: usize = s::BLOCK_BYTES;
    pub const BLOCK_BYTES_NATIVE: u32 = s::BLOCK_BYTES as u32;
    pub const MAX_OUTLEN: usize = s::MAX_OUTLEN;
    pub const MAX_KEYLEN: usize = s::MAX_KEYLEN;

    pub fn new(outlen: usize, keylen: usize) -> Self {
        assert!(outlen > 0 && outlen <= s::MAX_OUTLEN);
        assert!(keylen <= s::MAX_KEYLEN);
        let mut h = s::IV;
        h[0] ^= 0x01010000 ^ ((keylen as u32) << 8) ^ outlen as u32;
        Self { h, t: [0, 0] }
    }

    pub fn reset(&mut self, outlen: usize, keylen: usize) {
        self.h = s::IV;
        self.h[0] ^= 0x01010000 ^ ((keylen as u32) << 8) ^ outlen as u32;
        self.t[0] = 0;
        self.t[1] = 0;
    }

    pub fn compress(&mut self, buf: &[u8], last: LastBlock) {
        compressbody!(s, self, u32, read_u32v_le, buf, last)
    }

    #[inline]
    pub fn increment_counter(&mut self, inc: u32) {
        self.t[0] += inc;
        self.t[1] += if self.t[0] < inc { 1 } else { 0 };
    }
}
