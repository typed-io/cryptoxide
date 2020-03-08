// adapted from the original blake2 sse implementation

use super::common::{b, s, LastBlock};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// Blake2b Context
#[derive(Clone)]
pub struct EngineB {
    pub h: [u64; 8],
    t: [u64; 2],
}

#[inline(always)]
unsafe fn _mm_roti_epi64(r: __m128i, c: u32) -> __m128i {
    if c == 32 {
        _mm_shuffle_epi32(r, _MM_SHUFFLE(2, 3, 0, 1))
    } else if c == 24 {
        let r24 = _mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);
        _mm_shuffle_epi8(r, r24)
    } else if c == 16 {
        let r16 = _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
        _mm_shuffle_epi8(r, r16)
    } else if c == 63 {
        _mm_xor_si128(_mm_srli_epi64(r, 63), _mm_slli_epi64(r, 64 - 63))
    } else {
        unreachable!()
    }
}

#[inline(always)]
unsafe fn _mm_roti_epi32(r: __m128i, c: u32) -> __m128i {
    if c == 8 {
        let r8 = _mm_set_epi8(12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1);
        _mm_shuffle_epi8(r, r8)
    } else if c == 16 {
        let r16 = _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
        _mm_shuffle_epi8(r, r16)
    } else if c == 7 {
        _mm_xor_si128(_mm_srli_epi32(r, 7), _mm_slli_epi32(r, 32 - 7))
    } else if c == 12 {
        _mm_xor_si128(_mm_srli_epi32(r, 12), _mm_slli_epi32(r, 32 - 12))
    } else {
        unreachable!()
    }
}

#[allow(non_snake_case)]
const fn _MM_SHUFFLE(z: u32, y: u32, x: u32, w: u32) -> i32 {
    ((z << 6) | (y << 4) | (x << 2) | w) as i32
}

#[inline(always)]
unsafe fn compress_b(
    h: *mut __m128i,
    block: *const __m128i,
    iv: *const __m128i,
    t: *const __m128i,
    f: __m128i,
) {
    let m0 = _mm_loadu_si128(block);
    let m1 = _mm_loadu_si128(block.add(1));
    let m2 = _mm_loadu_si128(block.add(2));
    let m3 = _mm_loadu_si128(block.add(3));
    let m4 = _mm_loadu_si128(block.add(4));
    let m5 = _mm_loadu_si128(block.add(5));
    let m6 = _mm_loadu_si128(block.add(6));
    let m7 = _mm_loadu_si128(block.add(7));

    let mut row1l = _mm_loadu_si128(h);
    let mut row1h = _mm_loadu_si128(h.add(1));
    let mut row2l = _mm_loadu_si128(h.add(2));
    let mut row2h = _mm_loadu_si128(h.add(3));
    let mut row3l = _mm_loadu_si128(iv);
    let mut row3h = _mm_loadu_si128(iv.add(1));
    let mut row4l = _mm_xor_si128(_mm_loadu_si128(iv.add(2)), _mm_loadu_si128(t));
    let mut row4h = _mm_xor_si128(_mm_loadu_si128(iv.add(3)), f);

    macro_rules! xG {
        ($b0: ident, $b1: ident, $r1: expr, $r2: expr) => {
            row1l = _mm_add_epi64(_mm_add_epi64(row1l, $b0), row2l);
            row1h = _mm_add_epi64(_mm_add_epi64(row1h, $b1), row2h);
            row4l = _mm_xor_si128(row4l, row1l);
            row4h = _mm_xor_si128(row4h, row1h);
            row4l = _mm_roti_epi64(row4l, $r1);
            row4h = _mm_roti_epi64(row4h, $r1);
            row3l = _mm_add_epi64(row3l, row4l);
            row3h = _mm_add_epi64(row3h, row4h);
            row2l = _mm_xor_si128(row2l, row3l);
            row2h = _mm_xor_si128(row2h, row3h);
            row2l = _mm_roti_epi64(row2l, $r2);
            row2h = _mm_roti_epi64(row2h, $r2);
        };
    }

    macro_rules! G1 {
        ($b0: ident, $b1: ident) => {
            xG!($b0, $b1, b::R1, b::R2);
        };
    }

    macro_rules! G2 {
        ($b0: ident, $b1: ident) => {
            xG!($b0, $b1, b::R3, b::R4);
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
    macro_rules! load_0 {
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
    macro_rules! load_1 {
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

    macro_rules! load_2 {
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

    macro_rules! load_3 {
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

    macro_rules! load_4 {
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

    macro_rules! load_5 {
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

    macro_rules! load_6 {
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

    macro_rules! load_7 {
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

    macro_rules! load_8 {
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

    macro_rules! load_9 {
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

    macro_rules! load_10 {
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

    macro_rules! load_11 {
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

    ROUND!(load_0!());
    ROUND!(load_1!());
    ROUND!(load_2!());
    ROUND!(load_3!());
    ROUND!(load_4!());
    ROUND!(load_5!());
    ROUND!(load_6!());
    ROUND!(load_7!());
    ROUND!(load_8!());
    ROUND!(load_9!());
    ROUND!(load_10!());
    ROUND!(load_11!());

    row1l = _mm_xor_si128(row3l, row1l);
    row1h = _mm_xor_si128(row3h, row1h);
    _mm_storeu_si128(h, _mm_xor_si128(_mm_loadu_si128(h), row1l));
    _mm_storeu_si128(h.add(1), _mm_xor_si128(_mm_loadu_si128(h.add(1)), row1h));
    row2l = _mm_xor_si128(row4l, row2l);
    row2h = _mm_xor_si128(row4h, row2h);
    _mm_storeu_si128(h.add(2), _mm_xor_si128(_mm_loadu_si128(h.add(2)), row2l));
    _mm_storeu_si128(h.add(3), _mm_xor_si128(_mm_loadu_si128(h.add(3)), row2h));
}

#[inline(always)]
unsafe fn compress_s(h: *mut __m128i, block: *const __m128i, iv: *const __m128i, t: __m128i) {
    let m0 = _mm_loadu_si128(block);
    let m1 = _mm_loadu_si128(block.add(1));
    let m2 = _mm_loadu_si128(block.add(2));
    let m3 = _mm_loadu_si128(block.add(3));

    let mut row1 = _mm_loadu_si128(h);
    let mut row2 = _mm_loadu_si128(h.add(1));
    let mut row3 = _mm_loadu_si128(iv);
    let mut row4 = _mm_xor_si128(_mm_loadu_si128(iv.add(1)), t);
    let ff0 = row1;
    let ff1 = row2;

    macro_rules! xG {
        ($b: ident, $r1: expr, $r2: expr) => {
            row1 = _mm_add_epi32(_mm_add_epi32(row1, $b), row2);
            row4 = _mm_xor_si128(row4, row1);
            row4 = _mm_roti_epi32(row4, $r1);
            row3 = _mm_add_epi32(row3, row4);
            row2 = _mm_xor_si128(row2, row3);
            row2 = _mm_roti_epi32(row2, $r2);
        };
    }

    macro_rules! G1 {
        ($b: ident) => {
            xG!($b, s::R1, s::R2);
        };
    }

    macro_rules! G2 {
        ($b: ident) => {
            xG!($b, s::R3, s::R4);
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

    macro_rules! load_0 {
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

    macro_rules! load_1 {
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

    macro_rules! load_2 {
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

    macro_rules! load_3 {
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

    macro_rules! load_4 {
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

    macro_rules! load_5 {
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

    macro_rules! load_6 {
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

    macro_rules! load_7 {
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

    macro_rules! load_8 {
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
    macro_rules! load_9 {
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

    ROUND!(0, load_0!());
    ROUND!(1, load_1!());
    ROUND!(2, load_2!());
    ROUND!(3, load_3!());
    ROUND!(4, load_4!());
    ROUND!(5, load_5!());
    ROUND!(6, load_6!());
    ROUND!(7, load_7!());
    ROUND!(8, load_8!());
    ROUND!(9, load_9!());

    _mm_storeu_si128(h, _mm_xor_si128(ff0, _mm_xor_si128(row1, row3)));
    _mm_storeu_si128(h.add(1), _mm_xor_si128(ff1, _mm_xor_si128(row2, row4)));
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
        let block = buf.as_ptr() as *const __m128i;
        let h = self.h.as_mut_ptr() as *mut __m128i;
        let iv = b::IV.as_ptr() as *const __m128i;
        let t = self.t.as_ptr() as *const __m128i;

        let f = unsafe {
            if last == LastBlock::Yes {
                _mm_set_epi64x(0, -1i64)
            } else {
                _mm_set1_epi64x(0)
            }
        };

        unsafe {
            compress_b(h, block, iv, t, f);
        }
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
        let block = buf.as_ptr() as *const __m128i;
        let h = self.h.as_mut_ptr() as *mut __m128i;
        let iv = s::IV.as_ptr() as *const __m128i;
        let t = unsafe {
            if last == LastBlock::Yes {
                _mm_set_epi32(0, -1i32, self.t[1] as i32, self.t[0] as i32)
            } else {
                _mm_set_epi32(0, 0, self.t[1] as i32, self.t[0] as i32)
            }
        };

        unsafe {
            compress_s(h, block, iv, t);
        }
    }

    #[inline]
    pub fn increment_counter(&mut self, inc: u32) {
        self.t[0] += inc;
        self.t[1] += if self.t[0] < inc { 1 } else { 0 };
    }
}
