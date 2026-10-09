//! SHA512 message schedule of 4 blocks at a time using AVX2.

use core::arch::x86_64::*;

use super::reference;
use super::sse41;

const K64: [u64; 80] = reference::K64;

// takes one 64-bit word from four 128-byte blocks and packs it into one simd u64x4
//
//   | block 3 | block 2 | block 1 | block 0 |
//
// x86 architecture can (currently) do unaligned load (at a cost if unaligned)
unsafe fn gather(block: *const i64) -> __m256i {
    use core::ptr::read;
    let mut temp = _mm256_insert_epi64(_mm256_setzero_si256(), read(block), 0);
    temp = _mm256_insert_epi64(temp, read(block.add(16)), 1);
    temp = _mm256_insert_epi64(temp, read(block.add(32)), 2);
    temp = _mm256_insert_epi64(temp, read(block.add(48)), 3);
    temp
}

unsafe fn sigma0(w: __m256i) -> __m256i {
    _mm256_xor_si256(
        _mm256_xor_si256(
            _mm256_xor_si256(_mm256_srli_epi64(w, 1), _mm256_slli_epi64(w, 63)),
            _mm256_xor_si256(_mm256_srli_epi64(w, 8), _mm256_slli_epi64(w, 56)),
        ),
        _mm256_srli_epi64(w, 7),
    )
}

unsafe fn sigma1(w: __m256i) -> __m256i {
    _mm256_xor_si256(
        _mm256_xor_si256(
            _mm256_xor_si256(_mm256_srli_epi64(w, 19), _mm256_slli_epi64(w, 45)),
            _mm256_xor_si256(_mm256_srli_epi64(w, 61), _mm256_slli_epi64(w, 3)),
        ),
        _mm256_srli_epi64(w, 6),
    )
}

macro_rules! SCHEDULE_ROUND {
    ($schedule: ident, $i:expr, $w1:expr, $w2:expr, $w3:expr, $w4:expr) => {
        let s0 = sigma0($w1);
        let s1 = sigma1($w2);
        $schedule[$i] = _mm256_add_epi64($w3, _mm256_set1_epi64x(K64[$i] as i64));
        $w3 = _mm256_add_epi64(_mm256_add_epi64($w3, $w4), _mm256_add_epi64(s0, s1));
    };
}

/// `SCHEDULE_ROUND` without the live message word update, for the final group
/// whose recomputed words would only feed the non-existent `W[80..]`.
macro_rules! SCHEDULE_ROUND_TAIL {
    ($schedule: ident, $i:expr, $w3:expr) => {
        $schedule[$i] = _mm256_add_epi64($w3, _mm256_set1_epi64x(K64[$i] as i64));
    };
}

/// The 16 schedule rounds `$base .. $base+16`.
///
/// After 16 rounds every one of the 16 live message words has been updated
/// exactly once and the rotation is back at its starting position, so the
/// groups simply chain. Keeping `$base` a constant is what lets the compiler
/// see that the whole schedule buffer is written before it is read
macro_rules! SCHEDULE_ROUNDS_16 {
    ($schedule:ident, $base:expr,
     $w0:ident, $w1:ident, $w2:ident, $w3:ident, $w4:ident, $w5:ident, $w6:ident, $w7:ident,
     $w8:ident, $w9:ident, $w10:ident, $w11:ident, $w12:ident, $w13:ident, $w14:ident,
     $w15:ident) => {
        SCHEDULE_ROUND!($schedule, $base + 0, $w1, $w14, $w0, $w9);
        SCHEDULE_ROUND!($schedule, $base + 1, $w2, $w15, $w1, $w10);
        SCHEDULE_ROUND!($schedule, $base + 2, $w3, $w0, $w2, $w11);
        SCHEDULE_ROUND!($schedule, $base + 3, $w4, $w1, $w3, $w12);
        SCHEDULE_ROUND!($schedule, $base + 4, $w5, $w2, $w4, $w13);
        SCHEDULE_ROUND!($schedule, $base + 5, $w6, $w3, $w5, $w14);
        SCHEDULE_ROUND!($schedule, $base + 6, $w7, $w4, $w6, $w15);
        SCHEDULE_ROUND!($schedule, $base + 7, $w8, $w5, $w7, $w0);
        SCHEDULE_ROUND!($schedule, $base + 8, $w9, $w6, $w8, $w1);
        SCHEDULE_ROUND!($schedule, $base + 9, $w10, $w7, $w9, $w2);
        SCHEDULE_ROUND!($schedule, $base + 10, $w11, $w8, $w10, $w3);
        SCHEDULE_ROUND!($schedule, $base + 11, $w12, $w9, $w11, $w4);
        SCHEDULE_ROUND!($schedule, $base + 12, $w13, $w10, $w12, $w5);
        SCHEDULE_ROUND!($schedule, $base + 13, $w14, $w11, $w13, $w6);
        SCHEDULE_ROUND!($schedule, $base + 14, $w15, $w12, $w14, $w7);
        SCHEDULE_ROUND!($schedule, $base + 15, $w0, $w13, $w15, $w8);
    };
}

/// compute the message schedule of 4 blocks (512 bytes)
#[inline]
pub unsafe fn message_schedule_4ways(schedule: &mut [__m256i; 80], message: &[u8]) {
    let bswap_mask: __m256i = _mm256_set_epi8(
        24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 8, 9, 10, 11, 12, 13, 14,
        15, 0, 1, 2, 3, 4, 5, 6, 7,
    );
    let (mut w0, mut w1, mut w2, mut w3, mut w4, mut w5, mut w6, mut w7);
    let (mut w8, mut w9, mut w10, mut w11, mut w12, mut w13, mut w14, mut w15);

    let message = message.as_ptr() as *const i64;
    w0 = gather(message);
    w1 = gather(message.add(1));
    w2 = gather(message.add(2));
    w3 = gather(message.add(3));
    w4 = gather(message.add(4));
    w5 = gather(message.add(5));
    w6 = gather(message.add(6));
    w7 = gather(message.add(7));
    w8 = gather(message.add(8));
    w9 = gather(message.add(9));
    w10 = gather(message.add(10));
    w11 = gather(message.add(11));
    w12 = gather(message.add(12));
    w13 = gather(message.add(13));
    w14 = gather(message.add(14));
    w15 = gather(message.add(15));
    w0 = _mm256_shuffle_epi8(w0, bswap_mask);
    w1 = _mm256_shuffle_epi8(w1, bswap_mask);
    w2 = _mm256_shuffle_epi8(w2, bswap_mask);
    w3 = _mm256_shuffle_epi8(w3, bswap_mask);
    w4 = _mm256_shuffle_epi8(w4, bswap_mask);
    w5 = _mm256_shuffle_epi8(w5, bswap_mask);
    w6 = _mm256_shuffle_epi8(w6, bswap_mask);
    w7 = _mm256_shuffle_epi8(w7, bswap_mask);
    w8 = _mm256_shuffle_epi8(w8, bswap_mask);
    w9 = _mm256_shuffle_epi8(w9, bswap_mask);
    w10 = _mm256_shuffle_epi8(w10, bswap_mask);
    w11 = _mm256_shuffle_epi8(w11, bswap_mask);
    w12 = _mm256_shuffle_epi8(w12, bswap_mask);
    w13 = _mm256_shuffle_epi8(w13, bswap_mask);
    w14 = _mm256_shuffle_epi8(w14, bswap_mask);
    w15 = _mm256_shuffle_epi8(w15, bswap_mask);
    SCHEDULE_ROUNDS_16!(
        schedule, 0, w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15
    );
    SCHEDULE_ROUNDS_16!(
        schedule, 16, w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15
    );
    SCHEDULE_ROUNDS_16!(
        schedule, 32, w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15
    );
    SCHEDULE_ROUNDS_16!(
        schedule, 48, w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15
    );
    // the last 16 schedule entries take their message words straight from the
    // live registers, without advancing them
    SCHEDULE_ROUND_TAIL!(schedule, 64, w0);
    SCHEDULE_ROUND_TAIL!(schedule, 65, w1);
    SCHEDULE_ROUND_TAIL!(schedule, 66, w2);
    SCHEDULE_ROUND_TAIL!(schedule, 67, w3);
    SCHEDULE_ROUND_TAIL!(schedule, 68, w4);
    SCHEDULE_ROUND_TAIL!(schedule, 69, w5);
    SCHEDULE_ROUND_TAIL!(schedule, 70, w6);
    SCHEDULE_ROUND_TAIL!(schedule, 71, w7);
    SCHEDULE_ROUND_TAIL!(schedule, 72, w8);
    SCHEDULE_ROUND_TAIL!(schedule, 73, w9);
    SCHEDULE_ROUND_TAIL!(schedule, 74, w10);
    SCHEDULE_ROUND_TAIL!(schedule, 75, w11);
    SCHEDULE_ROUND_TAIL!(schedule, 76, w12);
    SCHEDULE_ROUND_TAIL!(schedule, 77, w13);
    SCHEDULE_ROUND_TAIL!(schedule, 78, w14);
    SCHEDULE_ROUND_TAIL!(schedule, 79, w15);
}

unsafe fn compress_4ways(state: &mut [u64; 8], schedule: &[__m256i; 80]) {
    macro_rules! compress_once {
        ($j:expr) => {{
            let mut w = [0u64; 80];
            for i in 0..80 {
                w[i] = _mm256_extract_epi64(*schedule.get_unchecked(i), $j) as u64;
            }
            reference::compress(state, &w);
        }};
    }
    compress_once!(0);
    compress_once!(1);
    compress_once!(2);
    compress_once!(3);
}

pub(crate) fn digest_block(state: &mut [u64; 8], mut block: &[u8]) {
    unsafe {
        let mut schedule = [_mm256_setzero_si256(); 80];
        while block.len() >= 512 {
            message_schedule_4ways(&mut schedule, block);
            compress_4ways(state, &schedule);
            block = &block[512..]
        }
    }
    sse41::digest_block(state, block)
}
