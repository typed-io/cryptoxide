// adapted from the original blake2 sse implementation

use super::common::{b, s, LastBlock};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[inline(always)]
unsafe fn rotate16_epi64(r: __m128i) -> __m128i {
    let r16 = _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
    _mm_shuffle_epi8(r, r16)
}

#[inline(always)]
unsafe fn rotate24_epi64(r: __m128i) -> __m128i {
    let r24 = _mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);
    _mm_shuffle_epi8(r, r24)
}

#[inline(always)]
unsafe fn rotate32_epi64(r: __m128i) -> __m128i {
    _mm_shuffle_epi32(r, _MM_SHUFFLE(2, 3, 0, 1))
}

#[inline(always)]
unsafe fn rotate63_epi64(r: __m128i) -> __m128i {
    _mm_xor_si128(_mm_srli_epi64(r, 63), _mm_slli_epi64(r, 64 - 63))
}

#[inline(always)]
unsafe fn rotate7_epi32(r: __m128i) -> __m128i {
    _mm_xor_si128(_mm_srli_epi32(r, 7), _mm_slli_epi32(r, 32 - 7))
}

#[inline(always)]
unsafe fn rotate8_epi32(r: __m128i) -> __m128i {
    let r8 = _mm_set_epi8(12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1);
    _mm_shuffle_epi8(r, r8)
}

#[inline(always)]
unsafe fn rotate12_epi32(r: __m128i) -> __m128i {
    _mm_xor_si128(_mm_srli_epi32(r, 12), _mm_slli_epi32(r, 32 - 12))
}

#[inline(always)]
unsafe fn rotate16_epi32(r: __m128i) -> __m128i {
    let r16 = _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
    _mm_shuffle_epi8(r, r16)
}

#[allow(non_snake_case)]
const fn _MM_SHUFFLE(z: u32, y: u32, x: u32, w: u32) -> i32 {
    ((z << 6) | (y << 4) | (x << 2) | w) as i32
}

#[inline(always)]
unsafe fn compress_b_avx(
    h: *mut __m128i,
    block: *const __m128i,
    iv: *const __m128i,
    t: *const __m128i,
    f: __m128i,
) {
    debug_assert!(h.align_offset(16) == 0);

    let m0 = _mm_loadu_si128(block);
    let m1 = _mm_loadu_si128(block.add(1));
    let m2 = _mm_loadu_si128(block.add(2));
    let m3 = _mm_loadu_si128(block.add(3));
    let m4 = _mm_loadu_si128(block.add(4));
    let m5 = _mm_loadu_si128(block.add(5));
    let m6 = _mm_loadu_si128(block.add(6));
    let m7 = _mm_loadu_si128(block.add(7));

    let mut row1l = _mm_load_si128(h);
    let mut row1h = _mm_load_si128(h.add(1));
    let mut row2l = _mm_load_si128(h.add(2));
    let mut row2h = _mm_load_si128(h.add(3));
    let mut row3l = _mm_loadu_si128(iv);
    let mut row3h = _mm_loadu_si128(iv.add(1));
    let mut row4l = _mm_xor_si128(_mm_loadu_si128(iv.add(2)), _mm_loadu_si128(t));
    let mut row4h = _mm_xor_si128(_mm_loadu_si128(iv.add(3)), f);

    let orig_a0 = row1l;
    let orig_a1 = row1h;
    let orig_b0 = row2l;
    let orig_b1 = row2h;

    macro_rules! G {
        ($b0: ident, $b1: ident, $rot1: expr, $rot2: expr) => {
            row1l = _mm_add_epi64(_mm_add_epi64(row1l, $b0), row2l);
            row1h = _mm_add_epi64(_mm_add_epi64(row1h, $b1), row2h);
            row4l = _mm_xor_si128(row4l, row1l);
            row4h = _mm_xor_si128(row4h, row1h);
            row4l = $rot1(row4l);
            row4h = $rot1(row4h);
            row3l = _mm_add_epi64(row3l, row4l);
            row3h = _mm_add_epi64(row3h, row4h);
            row2l = _mm_xor_si128(row2l, row3l);
            row2h = _mm_xor_si128(row2h, row3h);
            row2l = $rot2(row2l);
            row2h = $rot2(row2h);
        };
    }

    macro_rules! G1 {
        ($b0: ident, $b1: ident) => {
            G!($b0, $b1, rotate32_epi64, rotate24_epi64);
        };
    }

    macro_rules! G2 {
        ($b0: ident, $b1: ident) => {
            G!($b0, $b1, rotate16_epi64, rotate63_epi64);
        };
    }

    macro_rules! DIAGONALIZE {
        () => {
            let mut t0 = _mm_alignr_epi8(row2h, row2l, 8);
            let mut t1 = _mm_alignr_epi8(row2l, row2h, 8);
            row2l = t0;
            row2h = t1;
            t0 = row3l;
            row3l = row3h;
            row3h = t0;
            t0 = _mm_alignr_epi8(row4h, row4l, 8);
            t1 = _mm_alignr_epi8(row4l, row4h, 8);
            row4l = t1;
            row4h = t0;
        };
    }

    macro_rules! UNDIAGONALIZE {
        () => {
            let mut t0 = _mm_alignr_epi8(row2l, row2h, 8);
            let mut t1 = _mm_alignr_epi8(row2h, row2l, 8);
            row2l = t0;
            row2h = t1;
            t0 = row3l;
            row3l = row3h;
            row3h = t0;
            t0 = _mm_alignr_epi8(row4l, row4h, 8);
            t1 = _mm_alignr_epi8(row4h, row4l, 8);
            row4l = t1;
            row4h = t0;
        };
    }

    macro_rules! ROUND {
        ($load: expr) => {
            let (b0, b1, b2, b3, b4, b5, b6, b7) = $load;
            G1!(b0, b1);
            G2!(b2, b3);
            DIAGONALIZE!();
            G1!(b4, b5);
            G2!(b6, b7);
            UNDIAGONALIZE!();
        };
    }
    macro_rules! load0 {
        () => {
            (
                _mm_unpacklo_epi64(m0, m1),
                _mm_unpacklo_epi64(m2, m3),
                _mm_unpackhi_epi64(m0, m1),
                _mm_unpackhi_epi64(m2, m3),
                _mm_unpacklo_epi64(m4, m5),
                _mm_unpacklo_epi64(m6, m7),
                _mm_unpackhi_epi64(m4, m5),
                _mm_unpackhi_epi64(m6, m7),
            )
        };
    }
    macro_rules! load1 {
        () => {
            (
                _mm_unpacklo_epi64(m7, m2),
                _mm_unpackhi_epi64(m4, m6),
                _mm_unpacklo_epi64(m5, m4),
                _mm_alignr_epi8(m3, m7, 8),
                _mm_shuffle_epi32(m0, _MM_SHUFFLE(1, 0, 3, 2)),
                _mm_unpackhi_epi64(m5, m2),
                _mm_unpacklo_epi64(m6, m1),
                _mm_unpackhi_epi64(m3, m1),
            )
        };
    }

    macro_rules! load2 {
        () => {
            (
                _mm_alignr_epi8(m6, m5, 8),
                _mm_unpackhi_epi64(m2, m7),
                _mm_unpacklo_epi64(m4, m0),
                _mm_blend_epi16(m1, m6, 0xF0),
                _mm_blend_epi16(m5, m1, 0xF0),
                _mm_unpackhi_epi64(m3, m4),
                _mm_unpacklo_epi64(m7, m3),
                _mm_alignr_epi8(m2, m0, 8),
            )
        };
    }

    macro_rules! load3 {
        () => {
            (
                _mm_unpackhi_epi64(m3, m1),
                _mm_unpackhi_epi64(m6, m5),
                _mm_unpackhi_epi64(m4, m0),
                _mm_unpacklo_epi64(m6, m7),
                _mm_blend_epi16(m1, m2, 0xF0),
                _mm_blend_epi16(m2, m7, 0xF0),
                _mm_unpacklo_epi64(m3, m5),
                _mm_unpacklo_epi64(m0, m4),
            )
        };
    }

    macro_rules! load4 {
        () => {
            (
                _mm_unpackhi_epi64(m4, m2),
                _mm_unpacklo_epi64(m1, m5),
                _mm_blend_epi16(m0, m3, 0xF0),
                _mm_blend_epi16(m2, m7, 0xF0),
                _mm_blend_epi16(m7, m5, 0xF0),
                _mm_blend_epi16(m3, m1, 0xF0),
                _mm_alignr_epi8(m6, m0, 8),
                _mm_blend_epi16(m4, m6, 0xF0),
            )
        };
    }

    macro_rules! load5 {
        () => {
            (
                _mm_unpacklo_epi64(m1, m3),
                _mm_unpacklo_epi64(m0, m4),
                _mm_unpacklo_epi64(m6, m5),
                _mm_unpackhi_epi64(m5, m1),
                _mm_blend_epi16(m2, m3, 0xF0),
                _mm_unpackhi_epi64(m7, m0),
                _mm_unpackhi_epi64(m6, m2),
                _mm_blend_epi16(m7, m4, 0xF0),
            )
        };
    }

    macro_rules! load6 {
        () => {
            (
                _mm_blend_epi16(m6, m0, 0xF0),
                _mm_unpacklo_epi64(m7, m2),
                _mm_unpackhi_epi64(m2, m7),
                _mm_alignr_epi8(m5, m6, 8),
                _mm_unpacklo_epi64(m0, m3),
                _mm_shuffle_epi32(m4, _MM_SHUFFLE(1, 0, 3, 2)),
                _mm_unpackhi_epi64(m3, m1),
                _mm_blend_epi16(m1, m5, 0xF0),
            )
        };
    }

    macro_rules! load7 {
        () => {
            (
                _mm_unpackhi_epi64(m6, m3),
                _mm_blend_epi16(m6, m1, 0xF0),
                _mm_alignr_epi8(m7, m5, 8),
                _mm_unpackhi_epi64(m0, m4),
                _mm_unpackhi_epi64(m2, m7),
                _mm_unpacklo_epi64(m4, m1),
                _mm_unpacklo_epi64(m0, m2),
                _mm_unpacklo_epi64(m3, m5),
            )
        };
    }

    macro_rules! load8 {
        () => {
            (
                _mm_unpacklo_epi64(m3, m7),
                _mm_alignr_epi8(m0, m5, 8),
                _mm_unpackhi_epi64(m7, m4),
                _mm_alignr_epi8(m4, m1, 8),
                m6,
                _mm_alignr_epi8(m5, m0, 8),
                _mm_blend_epi16(m1, m3, 0xF0),
                m2,
            )
        };
    }

    macro_rules! load9 {
        () => {
            (
                _mm_unpacklo_epi64(m5, m4),
                _mm_unpackhi_epi64(m3, m0),
                _mm_unpacklo_epi64(m1, m2),
                _mm_blend_epi16(m3, m2, 0xF0),
                _mm_unpackhi_epi64(m7, m4),
                _mm_unpackhi_epi64(m1, m6),
                _mm_alignr_epi8(m7, m5, 8),
                _mm_unpacklo_epi64(m6, m0),
            )
        };
    }

    ROUND!(load0!());
    ROUND!(load1!());
    ROUND!(load2!());
    ROUND!(load3!());
    ROUND!(load4!());
    ROUND!(load5!());
    ROUND!(load6!());
    ROUND!(load7!());
    ROUND!(load8!());
    ROUND!(load9!());
    ROUND!(load0!());
    ROUND!(load1!());

    // now xor the original state with the and current state, store it back into the state (h)
    row1l = _mm_xor_si128(row3l, row1l);
    row1h = _mm_xor_si128(row3h, row1h);
    _mm_store_si128(h, _mm_xor_si128(orig_a0, row1l));
    _mm_store_si128(h.add(1), _mm_xor_si128(orig_a1, row1h));
    row2l = _mm_xor_si128(row4l, row2l);
    row2h = _mm_xor_si128(row4h, row2h);
    _mm_store_si128(h.add(2), _mm_xor_si128(orig_b0, row2l));
    _mm_store_si128(h.add(3), _mm_xor_si128(orig_b1, row2h));
}

#[inline(always)]
unsafe fn compress_s_avx(h: *mut __m128i, block: *const __m128i, iv: *const __m128i, t: __m128i) {
    let m0 = _mm_loadu_si128(block);
    let m1 = _mm_loadu_si128(block.add(1));
    let m2 = _mm_loadu_si128(block.add(2));
    let m3 = _mm_loadu_si128(block.add(3));

    let mut row1 = _mm_load_si128(h);
    let mut row2 = _mm_load_si128(h.add(1));
    let mut row3 = _mm_loadu_si128(iv);
    let mut row4 = _mm_xor_si128(_mm_loadu_si128(iv.add(1)), t);
    let orig_a = row1;
    let orig_b = row2;

    macro_rules! G {
        ($b: ident, $rol1: expr, $rol2: expr) => {
            row1 = _mm_add_epi32(_mm_add_epi32(row1, $b), row2);
            row4 = _mm_xor_si128(row4, row1);
            row4 = $rol1(row4);
            row3 = _mm_add_epi32(row3, row4);
            row2 = _mm_xor_si128(row2, row3);
            row2 = $rol2(row2);
        };
    }

    macro_rules! G1 {
        ($b: ident) => {
            G!($b, rotate16_epi32, rotate12_epi32);
        };
    }

    macro_rules! G2 {
        ($b: ident) => {
            G!($b, rotate8_epi32, rotate7_epi32);
        };
    }

    macro_rules! DIAGONALIZE {
        () => {
            row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2, 1, 0, 3));
            row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
            row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0, 3, 2, 1));
        };
    }

    macro_rules! UNDIAGONALIZE {
        () => {
            row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0, 3, 2, 1));
            row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
            row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2, 1, 0, 3));
        };
    }

    macro_rules! ROUND {
        ($r: expr, $load: expr) => {
            let (b0, b1, b2, b3) = $load;
            G1!(b0);
            G2!(b1);
            DIAGONALIZE!();
            G1!(b2);
            G2!(b3);
            UNDIAGONALIZE!();
        };
    }

    macro_rules! load0 {
        () => {
            (
                _mm_castps_si128(_mm_shuffle_ps(
                    _mm_castsi128_ps(m0),
                    _mm_castsi128_ps(m1),
                    _MM_SHUFFLE(2, 0, 2, 0),
                )),
                _mm_castps_si128(_mm_shuffle_ps(
                    _mm_castsi128_ps(m0),
                    _mm_castsi128_ps(m1),
                    _MM_SHUFFLE(3, 1, 3, 1),
                )),
                _mm_castps_si128(_mm_shuffle_ps(
                    _mm_castsi128_ps(m2),
                    _mm_castsi128_ps(m3),
                    _MM_SHUFFLE(2, 0, 2, 0),
                )),
                _mm_castps_si128(_mm_shuffle_ps(
                    _mm_castsi128_ps(m2),
                    _mm_castsi128_ps(m3),
                    _MM_SHUFFLE(3, 1, 3, 1),
                )),
            )
        };
    }

    macro_rules! load1 {
        () => {
            (
                {
                    let t0 = _mm_blend_epi16(m1, m2, 0x0C);
                    let t1 = _mm_slli_si128(m3, 4);
                    let t2 = _mm_blend_epi16(t0, t1, 0xF0);
                    _mm_shuffle_epi32(t2, _MM_SHUFFLE(2, 1, 0, 3))
                },
                {
                    let t0 = _mm_shuffle_epi32(m2, _MM_SHUFFLE(0, 0, 2, 0));
                    let t1 = _mm_blend_epi16(m1, m3, 0xC0);
                    let t2 = _mm_blend_epi16(t0, t1, 0xF0);
                    _mm_shuffle_epi32(t2, _MM_SHUFFLE(2, 3, 0, 1))
                },
                {
                    let t0 = _mm_slli_si128(m1, 4);
                    let t1 = _mm_blend_epi16(m2, t0, 0x30);
                    let t2 = _mm_blend_epi16(m0, t1, 0xF0);
                    _mm_shuffle_epi32(t2, _MM_SHUFFLE(2, 3, 0, 1))
                },
                {
                    let t0 = _mm_unpackhi_epi32(m0, m1);
                    let t1 = _mm_slli_si128(m3, 4);
                    let t2 = _mm_blend_epi16(t0, t1, 0x0C);
                    _mm_shuffle_epi32(t2, _MM_SHUFFLE(2, 3, 0, 1))
                },
            )
        };
    }

    macro_rules! load2 {
        () => {
            (
                {
                    let t0 = _mm_unpackhi_epi32(m2, m3);
                    let t1 = _mm_blend_epi16(m3, m1, 0x0C);
                    let t2 = _mm_blend_epi16(t0, t1, 0x0F);
                    _mm_shuffle_epi32(t2, _MM_SHUFFLE(3, 1, 0, 2))
                },
                {
                    let t0 = _mm_unpacklo_epi32(m2, m0);
                    let t1 = _mm_blend_epi16(t0, m0, 0xF0);
                    let t2 = _mm_slli_si128(m3, 8);
                    _mm_blend_epi16(t1, t2, 0xC0)
                },
                {
                    let t0 = _mm_blend_epi16(m0, m2, 0x3C);
                    let t1 = _mm_srli_si128(m1, 12);
                    let t2 = _mm_blend_epi16(t0, t1, 0x03);
                    _mm_shuffle_epi32(t2, _MM_SHUFFLE(1, 0, 3, 2))
                },
                {
                    let t0 = _mm_slli_si128(m3, 4);
                    let t1 = _mm_blend_epi16(m0, m1, 0x33);
                    let t2 = _mm_blend_epi16(t1, t0, 0xC0);
                    _mm_shuffle_epi32(t2, _MM_SHUFFLE(0, 1, 2, 3))
                },
            )
        };
    }

    macro_rules! load3 {
        () => {
            (
                {
                    let t0 = _mm_unpackhi_epi32(m0, m1);
                    let t1 = _mm_unpackhi_epi32(t0, m2);
                    let t2 = _mm_blend_epi16(t1, m3, 0x0C);
                    _mm_shuffle_epi32(t2, _MM_SHUFFLE(3, 1, 0, 2))
                },
                {
                    let t0 = _mm_slli_si128(m2, 8);
                    let t1 = _mm_blend_epi16(m3, m0, 0x0C);
                    let t2 = _mm_blend_epi16(t1, t0, 0xC0);
                    _mm_shuffle_epi32(t2, _MM_SHUFFLE(2, 0, 1, 3))
                },
                {
                    let t0 = _mm_blend_epi16(m0, m1, 0x0F);
                    let t1 = _mm_blend_epi16(t0, m3, 0xC0);
                    _mm_shuffle_epi32(t1, _MM_SHUFFLE(3, 0, 1, 2))
                },
                {
                    let t0 = _mm_unpacklo_epi32(m0, m2);
                    let t1 = _mm_unpackhi_epi32(m1, m2);
                    _mm_unpacklo_epi64(t1, t0)
                },
            )
        };
    }

    macro_rules! load4 {
        () => {
            (
                {
                    let t0 = _mm_unpacklo_epi64(m1, m2);
                    let t1 = _mm_unpackhi_epi64(m0, m2);
                    let t2 = _mm_blend_epi16(t0, t1, 0x33);
                    _mm_shuffle_epi32(t2, _MM_SHUFFLE(2, 0, 1, 3))
                },
                {
                    let t0 = _mm_unpackhi_epi64(m1, m3);
                    let t1 = _mm_unpacklo_epi64(m0, m1);
                    _mm_blend_epi16(t0, t1, 0x33)
                },
                {
                    let t0 = _mm_unpackhi_epi64(m3, m1);
                    let t1 = _mm_unpackhi_epi64(m2, m0);
                    _mm_blend_epi16(t1, t0, 0x33)
                },
                {
                    let t0 = _mm_blend_epi16(m0, m2, 0x03);
                    let t1 = _mm_slli_si128(t0, 8);
                    let t2 = _mm_blend_epi16(t1, m3, 0x0F);
                    _mm_shuffle_epi32(t2, _MM_SHUFFLE(1, 2, 0, 3))
                },
            )
        };
    }

    macro_rules! load5 {
        () => {
            (
                {
                    let t0 = _mm_unpackhi_epi32(m0, m1);
                    let t1 = _mm_unpacklo_epi32(m0, m2);
                    _mm_unpacklo_epi64(t0, t1)
                },
                {
                    let t0 = _mm_srli_si128(m2, 4);
                    let t1 = _mm_blend_epi16(m0, m3, 0x03);
                    _mm_blend_epi16(t1, t0, 0x3C)
                },
                {
                    let t0 = _mm_blend_epi16(m1, m0, 0x0C);
                    let t1 = _mm_srli_si128(m3, 4);
                    let t2 = _mm_blend_epi16(t0, t1, 0x30);
                    _mm_shuffle_epi32(t2, _MM_SHUFFLE(1, 2, 3, 0))
                },
                {
                    let t0 = _mm_unpacklo_epi64(m1, m2);
                    let t1 = _mm_shuffle_epi32(m3, _MM_SHUFFLE(0, 2, 0, 1));
                    _mm_blend_epi16(t0, t1, 0x33)
                },
            )
        };
    }

    macro_rules! load6 {
        () => {
            (
                {
                    let t0 = _mm_slli_si128(m1, 12);
                    let t1 = _mm_blend_epi16(m0, m3, 0x33);
                    _mm_blend_epi16(t1, t0, 0xC0)
                },
                {
                    let t0 = _mm_blend_epi16(m3, m2, 0x30);
                    let t1 = _mm_srli_si128(m1, 4);
                    let t2 = _mm_blend_epi16(t0, t1, 0x03);
                    _mm_shuffle_epi32(t2, _MM_SHUFFLE(2, 1, 3, 0))
                },
                {
                    let t0 = _mm_unpacklo_epi64(m0, m2);
                    let t1 = _mm_srli_si128(m1, 4);
                    _mm_shuffle_epi32(_mm_blend_epi16(t0, t1, 0x0C), _MM_SHUFFLE(2, 3, 1, 0))
                },
                {
                    let t0 = _mm_unpackhi_epi32(m1, m2);
                    let t1 = _mm_unpackhi_epi64(m0, t0);
                    _mm_shuffle_epi32(t1, _MM_SHUFFLE(3, 0, 1, 2))
                },
            )
        };
    }

    macro_rules! load7 {
        () => {
            (
                {
                    let t0 = _mm_unpackhi_epi32(m0, m1);
                    let t1 = _mm_blend_epi16(t0, m3, 0x0F);
                    _mm_shuffle_epi32(t1, _MM_SHUFFLE(2, 0, 3, 1))
                },
                {
                    let t0 = _mm_blend_epi16(m2, m3, 0x30);
                    let t1 = _mm_srli_si128(m0, 4);
                    let t2 = _mm_blend_epi16(t0, t1, 0x03);
                    _mm_shuffle_epi32(t2, _MM_SHUFFLE(1, 0, 2, 3))
                },
                {
                    let t0 = _mm_unpackhi_epi64(m0, m3);
                    let t1 = _mm_unpacklo_epi64(m1, m2);
                    let t2 = _mm_blend_epi16(t0, t1, 0x3C);
                    _mm_shuffle_epi32(t2, _MM_SHUFFLE(0, 2, 3, 1))
                },
                {
                    let t0 = _mm_unpacklo_epi32(m0, m1);
                    let t1 = _mm_unpackhi_epi32(m1, m2);
                    _mm_unpacklo_epi64(t0, t1)
                },
            )
        };
    }

    macro_rules! load8 {
        () => {
            (
                {
                    let t0 = _mm_unpackhi_epi32(m1, m3);
                    let t1 = _mm_unpacklo_epi64(t0, m0);
                    let t2 = _mm_blend_epi16(t1, m2, 0xC0);
                    _mm_shufflehi_epi16(t2, _MM_SHUFFLE(1, 0, 3, 2))
                },
                {
                    let t0 = _mm_unpackhi_epi32(m0, m3);
                    let t1 = _mm_blend_epi16(m2, t0, 0xF0);
                    _mm_shuffle_epi32(t1, _MM_SHUFFLE(0, 2, 1, 3))
                },
                {
                    let t0 = _mm_blend_epi16(m2, m0, 0x0C);
                    let t1 = _mm_slli_si128(t0, 4);
                    _mm_blend_epi16(t1, m3, 0x0F)
                },
                {
                    let t0 = _mm_blend_epi16(m1, m0, 0x30);
                    _mm_shuffle_epi32(t0, _MM_SHUFFLE(1, 0, 3, 2))
                },
            )
        };
    }
    macro_rules! load9 {
        () => {
            (
                {
                    let t0 = _mm_blend_epi16(m0, m2, 0x03);
                    let t1 = _mm_blend_epi16(m1, m2, 0x30);
                    let t2 = _mm_blend_epi16(t1, t0, 0x0F);
                    _mm_shuffle_epi32(t2, _MM_SHUFFLE(1, 3, 0, 2))
                },
                {
                    let t0 = _mm_slli_si128(m0, 4);
                    let t1 = _mm_blend_epi16(m1, t0, 0xC0);
                    _mm_shuffle_epi32(t1, _MM_SHUFFLE(1, 2, 0, 3))
                },
                {
                    let t0 = _mm_unpackhi_epi32(m0, m3);
                    let t1 = _mm_unpacklo_epi32(m2, m3);
                    let t2 = _mm_unpackhi_epi64(t0, t1);
                    _mm_shuffle_epi32(t2, _MM_SHUFFLE(3, 0, 2, 1))
                },
                {
                    let t0 = _mm_blend_epi16(m3, m2, 0xC0);
                    let t1 = _mm_unpacklo_epi32(m0, m3);
                    let t2 = _mm_blend_epi16(t0, t1, 0x0F);
                    _mm_shuffle_epi32(t2, _MM_SHUFFLE(0, 1, 2, 3))
                },
            )
        };
    }

    ROUND!(0, load0!());
    ROUND!(1, load1!());
    ROUND!(2, load2!());
    ROUND!(3, load3!());
    ROUND!(4, load4!());
    ROUND!(5, load5!());
    ROUND!(6, load6!());
    ROUND!(7, load7!());
    ROUND!(8, load8!());
    ROUND!(9, load9!());

    _mm_store_si128(h, _mm_xor_si128(orig_a, _mm_xor_si128(row1, row3)));
    _mm_store_si128(h.add(1), _mm_xor_si128(orig_b, _mm_xor_si128(row2, row4)));
}

pub fn compress_b(h: &mut [u64; 8], t: &mut [u64; 2], buf: &[u8], last: LastBlock) {
    let block = buf.as_ptr() as *const __m128i;
    let h = h.as_mut_ptr() as *mut __m128i;
    let iv = b::IV.as_ptr() as *const __m128i;
    let t = t.as_ptr() as *const __m128i;

    let f = unsafe {
        if last == LastBlock::Yes {
            _mm_set_epi64x(0, -1i64)
        } else {
            _mm_set1_epi64x(0)
        }
    };

    unsafe {
        compress_b_avx(h, block, iv, t, f);
    }
}

pub fn compress_s(h: &mut [u32; 8], t: &[u32; 2], buf: &[u8], last: LastBlock) {
    let block = buf.as_ptr() as *const __m128i;
    let h = h.as_mut_ptr() as *mut __m128i;
    let iv = s::IV.as_ptr() as *const __m128i;
    let t = unsafe {
        if last == LastBlock::Yes {
            _mm_set_epi32(0, -1i32, t[1] as i32, t[0] as i32)
        } else {
            _mm_set_epi32(0, 0, t[1] as i32, t[0] as i32)
        }
    };

    unsafe {
        compress_s_avx(h, block, iv, t);
    }
}
