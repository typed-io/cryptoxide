use super::common::{b, s, LastBlock, SIGMA};
use crate::cryptoutil::{read_u32v_le, read_u64v_le};

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

        $engine.h[0] ^= vs[0] ^ vs[8];
        $engine.h[1] ^= vs[1] ^ vs[9];
        $engine.h[2] ^= vs[2] ^ vs[10];
        $engine.h[3] ^= vs[3] ^ vs[11];
        $engine.h[4] ^= vs[4] ^ vs[12];
        $engine.h[5] ^= vs[5] ^ vs[13];
        $engine.h[6] ^= vs[6] ^ vs[14];
        $engine.h[7] ^= vs[7] ^ vs[15];
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
