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
    ($conmod: ident, $h:expr, $t:expr, $ty:ident, $read_f: ident, $buf: ident, $last: ident) => {{
        let mut ms: [$ty; 16] = [0; 16];
        let mut vs: [$ty; 16] = [0; 16];

        $read_f(&mut ms, $buf);

        vs[0..8].copy_from_slice($h);
        vs[8..16].copy_from_slice(&$conmod::IV);

        vs[12] ^= $t[0];
        vs[13] ^= $t[1];
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

        $h[0] ^= vs[0] ^ vs[8];
        $h[1] ^= vs[1] ^ vs[9];
        $h[2] ^= vs[2] ^ vs[10];
        $h[3] ^= vs[3] ^ vs[11];
        $h[4] ^= vs[4] ^ vs[12];
        $h[5] ^= vs[5] ^ vs[13];
        $h[6] ^= vs[6] ^ vs[14];
        $h[7] ^= vs[7] ^ vs[15];
    }};
}

pub fn compress_b(h: &mut [u64; 8], t: &mut [u64; 2], buf: &[u8], last: LastBlock) {
    compressbody!(b, h, t, u64, read_u64v_le, buf, last)
}

pub fn compress_s(h: &mut [u32; 8], t: &mut [u32; 2], buf: &[u8], last: LastBlock) {
    compressbody!(s, h, t, u32, read_u32v_le, buf, last)
}
