//! SHA-1 compression using the x86 SHA extensions (SHA-NI).
//!
//! The state is kept in the register layout the `sha1rnds4`/`sha1nexte`
//! instructions operate on: `A..D` live in the four lanes of one register
//! (with `A` in the most-significant lane) and `E` in the most-significant lane
//! of a second one. The round constants are baked into `sha1rnds4` through its
//! `func` immediate, so only the raw message words are fed in.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::STATE_LEN;

macro_rules! rounds4 {
    ($h0:ident, $h1:ident, $wk:expr, $i:expr) => {
        _mm_sha1rnds4_epu32($h0, _mm_sha1nexte_epu32($h1, $wk), $i)
    };
}

macro_rules! schedule {
    ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {
        _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32($v0, $v1), $v2), $v3)
    };
}

macro_rules! schedule_rounds4 {
    (
        $h0:ident, $h1:ident,
        $w0:expr, $w1:expr, $w2:expr, $w3:expr, $w4:expr,
        $i:expr
    ) => {
        $w4 = schedule!($w0, $w1, $w2, $w3);
        $h1 = rounds4!($h0, $h1, $w4, $i);
    };
}

pub(super) fn digest_block(state: &mut [u32; STATE_LEN], block: &[u8]) {
    if block.is_empty() {
        return;
    }
    unsafe { digest_blocks(state, block) }
}

unsafe fn digest_blocks(state: &mut [u32; STATE_LEN], block: &[u8]) {
    // reverse the bytes of each 16-byte chunk, turning the big-endian message
    // words into native order
    let mask: __m128i = _mm_set_epi64x(0x0001_0203_0405_0607, 0x0809_0a0b_0c0d_0e0f);

    // `sha1rnds4` works on a `[D, C, B, A]` layout, with `E` kept in the
    // most-significant lane of a separate register.
    let mut state_abcd = _mm_loadu_si128(state.as_ptr() as *const __m128i);
    state_abcd = _mm_shuffle_epi32(state_abcd, 0x1b);
    let mut state_e = _mm_set_epi32(state[4] as i32, 0, 0, 0);

    let mut data = block.as_ptr() as *const __m128i;
    let mut len = block.len();

    while len >= 64 {
        let mut w0 = _mm_shuffle_epi8(_mm_loadu_si128(data), mask);
        let mut w1 = _mm_shuffle_epi8(_mm_loadu_si128(data.add(1)), mask);
        let mut w2 = _mm_shuffle_epi8(_mm_loadu_si128(data.add(2)), mask);
        let mut w3 = _mm_shuffle_epi8(_mm_loadu_si128(data.add(3)), mask);
        let mut w4;

        let mut h0 = state_abcd;
        let mut h1 = _mm_add_epi32(state_e, w0);

        // Rounds 0..20
        h1 = _mm_sha1rnds4_epu32(h0, h1, 0);
        h0 = rounds4!(h1, h0, w1, 0);
        h1 = rounds4!(h0, h1, w2, 0);
        h0 = rounds4!(h1, h0, w3, 0);
        schedule_rounds4!(h0, h1, w0, w1, w2, w3, w4, 0);

        // Rounds 20..40
        schedule_rounds4!(h1, h0, w1, w2, w3, w4, w0, 1);
        schedule_rounds4!(h0, h1, w2, w3, w4, w0, w1, 1);
        schedule_rounds4!(h1, h0, w3, w4, w0, w1, w2, 1);
        schedule_rounds4!(h0, h1, w4, w0, w1, w2, w3, 1);
        schedule_rounds4!(h1, h0, w0, w1, w2, w3, w4, 1);

        // Rounds 40..60
        schedule_rounds4!(h0, h1, w1, w2, w3, w4, w0, 2);
        schedule_rounds4!(h1, h0, w2, w3, w4, w0, w1, 2);
        schedule_rounds4!(h0, h1, w3, w4, w0, w1, w2, 2);
        schedule_rounds4!(h1, h0, w4, w0, w1, w2, w3, 2);
        schedule_rounds4!(h0, h1, w0, w1, w2, w3, w4, 2);

        // Rounds 60..80
        schedule_rounds4!(h1, h0, w1, w2, w3, w4, w0, 3);
        schedule_rounds4!(h0, h1, w2, w3, w4, w0, w1, 3);
        schedule_rounds4!(h1, h0, w3, w4, w0, w1, w2, 3);
        schedule_rounds4!(h0, h1, w4, w0, w1, w2, w3, 3);
        schedule_rounds4!(h1, h0, w0, w1, w2, w3, w4, 3);

        state_abcd = _mm_add_epi32(state_abcd, h0);
        state_e = _mm_sha1nexte_epu32(h1, state_e);

        data = data.add(4);
        len -= 64;
    }

    state_abcd = _mm_shuffle_epi32(state_abcd, 0x1b);
    _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, state_abcd);
    state[4] = _mm_extract_epi32(state_e, 3) as u32;
}
