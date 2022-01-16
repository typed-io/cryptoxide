#[cfg(target_arch = "x86")]
use core::arch::x86::*;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::reference;

const K32: [u32; 64] = reference::K32;

// takes 32 bits word from four data 64 bytes block and pack it into one simd u32x4
//
//   | block 3 | block 2 | block 1 | block 0 |
//
// x86 architecture can (currently) do unaligned load (at a cost if unaligned)
unsafe fn gather(block: *const u8) -> __m128i {
    use core::ptr::read;
    let mut temp: __m128i;
    let block = block as *const i32;

    temp = _mm_cvtsi32_si128(read(block));
    temp = _mm_insert_epi32(temp, read(block.add(16)), 1);
    temp = _mm_insert_epi32(temp, read(block.add(32)), 2);
    temp = _mm_insert_epi32(temp, read(block.add(48)), 3);
    temp
}

unsafe fn sigma0(w: __m128i) -> __m128i {
    _mm_xor_si128(
        _mm_xor_si128(
            _mm_xor_si128(_mm_srli_epi32(w, 7), _mm_srli_epi32(w, 18)),
            _mm_xor_si128(_mm_srli_epi32(w, 3), _mm_slli_epi32(w, 25)),
        ),
        _mm_slli_epi32(w, 14),
    )
}

unsafe fn sigma1(w: __m128i) -> __m128i {
    _mm_xor_si128(
        _mm_xor_si128(
            _mm_xor_si128(_mm_srli_epi32(w, 17), _mm_srli_epi32(w, 10)),
            _mm_xor_si128(_mm_srli_epi32(w, 19), _mm_slli_epi32(w, 15)),
        ),
        _mm_slli_epi32(w, 13),
    )
}

macro_rules! SCHEDULE_ROUND {
    ($schedule: ident, $i:expr, $w1:expr, $w2:expr, $w3:expr, $w4:expr) => {
        let s0 = sigma0($w1);
        let s1 = sigma1($w2);
        $schedule[$i] = _mm_add_epi32($w3, _mm_set1_epi32(K32[$i] as i32));
        $w3 = _mm_add_epi32(_mm_add_epi32($w3, $w4), _mm_add_epi32(s0, s1));
    };
}

macro_rules! SCHEDULE_ROUND_INC {
    ($schedule: ident, $i:expr, $w1:expr, $w2:expr, $w3:expr, $w4:expr) => {
        SCHEDULE_ROUND!($schedule, $i, $w1, $w2, $w3, $w4);
        $i += 1;
    };
}

/// compute the message schedule of 4 blocks (256 bytes)
#[inline]
pub unsafe fn message_schedule_4ways(schedule: &mut [__m128i; 64], message: &[u8]) {
    let bswap_mask: __m128i = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
    let (mut w0, mut w1, mut w2, mut w3, mut w4, mut w5, mut w6, mut w7);
    let (mut w8, mut w9, mut w10, mut w11, mut w12, mut w13, mut w14, mut w15);

    let message = message.as_ptr();
    w0 = gather(message);
    w1 = gather(message.add(4));
    w2 = gather(message.add(8));
    w3 = gather(message.add(12));
    w4 = gather(message.add(16));
    w5 = gather(message.add(20));
    w6 = gather(message.add(24));
    w7 = gather(message.add(28));
    w8 = gather(message.add(32));
    w9 = gather(message.add(36));
    w10 = gather(message.add(40));
    w11 = gather(message.add(44));
    w12 = gather(message.add(48));
    w13 = gather(message.add(52));
    w14 = gather(message.add(56));
    w15 = gather(message.add(60));
    w0 = _mm_shuffle_epi8(w0, bswap_mask);
    w1 = _mm_shuffle_epi8(w1, bswap_mask);
    w2 = _mm_shuffle_epi8(w2, bswap_mask);
    w3 = _mm_shuffle_epi8(w3, bswap_mask);
    w4 = _mm_shuffle_epi8(w4, bswap_mask);
    w5 = _mm_shuffle_epi8(w5, bswap_mask);
    w6 = _mm_shuffle_epi8(w6, bswap_mask);
    w7 = _mm_shuffle_epi8(w7, bswap_mask);
    w8 = _mm_shuffle_epi8(w8, bswap_mask);
    w9 = _mm_shuffle_epi8(w9, bswap_mask);
    w10 = _mm_shuffle_epi8(w10, bswap_mask);
    w11 = _mm_shuffle_epi8(w11, bswap_mask);
    w12 = _mm_shuffle_epi8(w12, bswap_mask);
    w13 = _mm_shuffle_epi8(w13, bswap_mask);
    w14 = _mm_shuffle_epi8(w14, bswap_mask);
    w15 = _mm_shuffle_epi8(w15, bswap_mask);
    let mut i = 0;
    while i < 32 {
        SCHEDULE_ROUND_INC!(schedule, i, w1, w14, w0, w9);
        SCHEDULE_ROUND_INC!(schedule, i, w2, w15, w1, w10);
        SCHEDULE_ROUND_INC!(schedule, i, w3, w0, w2, w11);
        SCHEDULE_ROUND_INC!(schedule, i, w4, w1, w3, w12);
        SCHEDULE_ROUND_INC!(schedule, i, w5, w2, w4, w13);
        SCHEDULE_ROUND_INC!(schedule, i, w6, w3, w5, w14);
        SCHEDULE_ROUND_INC!(schedule, i, w7, w4, w6, w15);
        SCHEDULE_ROUND_INC!(schedule, i, w8, w5, w7, w0);
        SCHEDULE_ROUND_INC!(schedule, i, w9, w6, w8, w1);
        SCHEDULE_ROUND_INC!(schedule, i, w10, w7, w9, w2);
        SCHEDULE_ROUND_INC!(schedule, i, w11, w8, w10, w3);
        SCHEDULE_ROUND_INC!(schedule, i, w12, w9, w11, w4);
        SCHEDULE_ROUND_INC!(schedule, i, w13, w10, w12, w5);
        SCHEDULE_ROUND_INC!(schedule, i, w14, w11, w13, w6);
        SCHEDULE_ROUND_INC!(schedule, i, w15, w12, w14, w7);
        SCHEDULE_ROUND_INC!(schedule, i, w0, w13, w15, w8);
    }
    SCHEDULE_ROUND_INC!(schedule, i, w1, w14, w0, w9);
    schedule[48] = _mm_add_epi32(w0, _mm_set1_epi32(K32[48] as i32));
    SCHEDULE_ROUND_INC!(schedule, i, w2, w15, w1, w10);
    schedule[49] = _mm_add_epi32(w1, _mm_set1_epi32(K32[49] as i32));
    SCHEDULE_ROUND_INC!(schedule, i, w3, w0, w2, w11);
    schedule[50] = _mm_add_epi32(w2, _mm_set1_epi32(K32[50] as i32));
    SCHEDULE_ROUND_INC!(schedule, i, w4, w1, w3, w12);
    schedule[51] = _mm_add_epi32(w3, _mm_set1_epi32(K32[51] as i32));
    SCHEDULE_ROUND_INC!(schedule, i, w5, w2, w4, w13);
    schedule[52] = _mm_add_epi32(w4, _mm_set1_epi32(K32[52] as i32));
    SCHEDULE_ROUND_INC!(schedule, i, w6, w3, w5, w14);
    schedule[53] = _mm_add_epi32(w5, _mm_set1_epi32(K32[53] as i32));
    SCHEDULE_ROUND_INC!(schedule, i, w7, w4, w6, w15);
    schedule[54] = _mm_add_epi32(w6, _mm_set1_epi32(K32[54] as i32));
    SCHEDULE_ROUND_INC!(schedule, i, w8, w5, w7, w0);
    schedule[55] = _mm_add_epi32(w7, _mm_set1_epi32(K32[55] as i32));
    SCHEDULE_ROUND_INC!(schedule, i, w9, w6, w8, w1);
    schedule[56] = _mm_add_epi32(w8, _mm_set1_epi32(K32[56] as i32));
    SCHEDULE_ROUND_INC!(schedule, i, w10, w7, w9, w2);
    schedule[57] = _mm_add_epi32(w9, _mm_set1_epi32(K32[57] as i32));
    SCHEDULE_ROUND_INC!(schedule, i, w11, w8, w10, w3);
    schedule[58] = _mm_add_epi32(w10, _mm_set1_epi32(K32[58] as i32));
    SCHEDULE_ROUND_INC!(schedule, i, w12, w9, w11, w4);
    schedule[59] = _mm_add_epi32(w11, _mm_set1_epi32(K32[59] as i32));
    SCHEDULE_ROUND_INC!(schedule, i, w13, w10, w12, w5);
    schedule[60] = _mm_add_epi32(w12, _mm_set1_epi32(K32[60] as i32));
    SCHEDULE_ROUND_INC!(schedule, i, w14, w11, w13, w6);
    schedule[61] = _mm_add_epi32(w13, _mm_set1_epi32(K32[61] as i32));
    SCHEDULE_ROUND_INC!(schedule, i, w15, w12, w14, w7);
    schedule[62] = _mm_add_epi32(w14, _mm_set1_epi32(K32[62] as i32));
    SCHEDULE_ROUND!(schedule, i, w0, w13, w15, w8);
    schedule[63] = _mm_add_epi32(w15, _mm_set1_epi32(K32[63] as i32));
}

unsafe fn compress_4ways(state: &mut [u32; 8], schedule: &[__m128i; 64]) {
    use super::reference::{e0, e1};
    macro_rules! round {
        ($a: ident, $b: ident, $c: ident, $d: ident, $e: ident, $f: ident, $g: ident, $h: ident, $i: expr, $j: expr) => {
            let kwi = _mm_extract_epi32(*schedule.get_unchecked($i), $j) as u32;
            let t1 = $h
                .wrapping_add(e1($e))
                .wrapping_add($g ^ ($e & ($f ^ $g)))
                .wrapping_add(kwi);
            let t2 = e0($a).wrapping_add(($a & $b) | ($c & ($a | $b)));
            $d = $d.wrapping_add(t1);
            $h = t1.wrapping_add(t2);
        };
    }

    // Compression function main loop:
    macro_rules! compress_once {
        ($j: expr) => {
            let mut a = state[0];
            let mut b = state[1];
            let mut c = state[2];
            let mut d = state[3];
            let mut e = state[4];
            let mut f = state[5];
            let mut g = state[6];
            let mut h = state[7];

            let mut i = 0;
            while i != 64 {
                round!(a, b, c, d, e, f, g, h, i + 0, $j);
                round!(h, a, b, c, d, e, f, g, i + 1, $j);
                round!(g, h, a, b, c, d, e, f, i + 2, $j);
                round!(f, g, h, a, b, c, d, e, i + 3, $j);
                round!(e, f, g, h, a, b, c, d, i + 4, $j);
                round!(d, e, f, g, h, a, b, c, i + 5, $j);
                round!(c, d, e, f, g, h, a, b, i + 6, $j);
                round!(b, c, d, e, f, g, h, a, i + 7, $j);
                i += 8;
            }

            //Add the compressed chunk to the current hash value:
            state[0] = state[0].wrapping_add(a);
            state[1] = state[1].wrapping_add(b);
            state[2] = state[2].wrapping_add(c);
            state[3] = state[3].wrapping_add(d);
            state[4] = state[4].wrapping_add(e);
            state[5] = state[5].wrapping_add(f);
            state[6] = state[6].wrapping_add(g);
            state[7] = state[7].wrapping_add(h);
        };
    }

    compress_once!(0);
    compress_once!(1);
    compress_once!(2);
    compress_once!(3);
}

pub(crate) fn digest_block(state: &mut [u32; 8], mut block: &[u8]) {
    unsafe {
        let mut schedule = [_mm_set1_epi32(0); 64];
        while block.len() >= 256 {
            message_schedule_4ways(&mut schedule, &block);
            compress_4ways(state, &schedule);
            block = &block[256..]
        }
    }
    if block.len() > 0 {
        reference::digest_block(state, block)
    }
}
