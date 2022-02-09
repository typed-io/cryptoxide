use super::common::{b, LastBlock};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[allow(non_snake_case)]
const fn _MM_SHUFFLE(z: u32, y: u32, x: u32, w: u32) -> i32 {
    ((z << 6) | (y << 4) | (x << 2) | w) as i32
}

unsafe fn rot32(v: __m256i) -> __m256i {
    _mm256_shuffle_epi32(v, _MM_SHUFFLE(2, 3, 0, 1))
}

unsafe fn rot16(v: __m256i) -> __m256i {
    let r16 = _mm256_setr_epi8(
        2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12,
        13, 14, 15, 8, 9,
    );
    _mm256_shuffle_epi8(v, r16)
}

unsafe fn rot24(v: __m256i) -> __m256i {
    let r24 = _mm256_setr_epi8(
        3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13,
        14, 15, 8, 9, 10,
    );
    _mm256_shuffle_epi8(v, r24)
}

unsafe fn rot63(v: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_srli_epi64(v, 63), _mm256_add_epi64(v, v))
}

unsafe fn compress_b_avx2(
    h: *mut __m256i,
    m: *const __m128i,
    iv: *const __m256i,
    f_and_t: __m256i,
) {
    let m0 = _mm256_broadcastsi128_si256(_mm_loadu_si128(m));
    let m1 = _mm256_broadcastsi128_si256(_mm_loadu_si128(m.add(1)));
    let m2 = _mm256_broadcastsi128_si256(_mm_loadu_si128(m.add(2)));
    let m3 = _mm256_broadcastsi128_si256(_mm_loadu_si128(m.add(3)));
    let m4 = _mm256_broadcastsi128_si256(_mm_loadu_si128(m.add(4)));
    let m5 = _mm256_broadcastsi128_si256(_mm_loadu_si128(m.add(5)));
    let m6 = _mm256_broadcastsi128_si256(_mm_loadu_si128(m.add(6)));
    let m7 = _mm256_broadcastsi128_si256(_mm_loadu_si128(m.add(7)));

    let mut a = _mm256_load_si256(h);
    let mut b = _mm256_load_si256(h.add(1));
    let mut c = _mm256_loadu_si256(iv);
    let mut d = _mm256_xor_si256(_mm256_loadu_si256(iv.add(1)), f_and_t);
    let state_a = a;
    let state_b = b;

    macro_rules! G {
        ($m: ident, $rot1: ident, $rot2: ident) => {
            a = _mm256_add_epi64(a, $m);
            a = _mm256_add_epi64(a, b);
            d = _mm256_xor_si256(d, a);
            d = $rot1(d);
            c = _mm256_add_epi64(c, d);
            b = _mm256_xor_si256(b, c);
            b = $rot2(b);
        };
    }
    macro_rules! G1 {
        ($m: ident) => {
            G!($m, rot32, rot24)
        };
    }
    macro_rules! G2 {
        ($m: ident) => {
            G!($m, rot16, rot63)
        };
    }
    macro_rules! DIAGONALIZE {
        () => {
            a = _mm256_permute4x64_epi64(a, _MM_SHUFFLE(2, 1, 0, 3));
            d = _mm256_permute4x64_epi64(d, _MM_SHUFFLE(1, 0, 3, 2));
            c = _mm256_permute4x64_epi64(c, _MM_SHUFFLE(0, 3, 2, 1));
        };
    }

    macro_rules! UNDIAGONALIZE {
        () => {
            a = _mm256_permute4x64_epi64(a, _MM_SHUFFLE(0, 3, 2, 1));
            d = _mm256_permute4x64_epi64(d, _MM_SHUFFLE(1, 0, 3, 2));
            c = _mm256_permute4x64_epi64(c, _MM_SHUFFLE(2, 1, 0, 3));
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

    macro_rules! blend {
        ($a: expr, $b: expr) => {
            _mm256_blend_epi32($a, $b, 0xF0)
        };
    }

    macro_rules! lo_lo {
        ($x0: ident, $x1: ident, $x2: ident, $x3: ident) => {
            blend!(
                _mm256_unpacklo_epi64($x0, $x1),
                _mm256_unpacklo_epi64($x2, $x3)
            )
        };
    }
    macro_rules! lo_hi {
        ($x0: ident, $x1: ident, $x2: ident, $x3: ident) => {
            blend!(
                _mm256_unpacklo_epi64($x0, $x1),
                _mm256_unpackhi_epi64($x2, $x3)
            )
        };
    }
    macro_rules! hi_lo {
        ($x0: ident, $x1: ident, $x2: ident, $x3: ident) => {
            blend!(
                _mm256_unpackhi_epi64($x0, $x1),
                _mm256_unpacklo_epi64($x2, $x3)
            )
        };
    }
    macro_rules! hi_hi {
        ($x0: ident, $x1: ident, $x2: ident, $x3: ident) => {
            blend!(
                _mm256_unpackhi_epi64($x0, $x1),
                _mm256_unpackhi_epi64($x2, $x3)
            )
        };
    }

    macro_rules! load0 {
        () => {
            (
                { lo_lo!(m0, m1, m2, m3) },
                { hi_hi!(m0, m1, m2, m3) },
                { lo_lo!(m7, m4, m5, m6) },
                { hi_hi!(m7, m4, m5, m6) },
            )
        };
    }
    macro_rules! load1 {
        () => {
            (
                { lo_hi!(m7, m2, m4, m6) },
                { blend!(_mm256_unpacklo_epi64(m5, m4), _mm256_alignr_epi8(m3, m7, 8)) },
                {
                    blend!(
                        _mm256_unpackhi_epi64(m2, m0),
                        _mm256_blend_epi32(m5, m0, 0b0011_0011)
                    )
                },
                {
                    blend!(
                        _mm256_alignr_epi8(m6, m1, 8),
                        _mm256_blend_epi32(m3, m1, 0b0011_0011)
                    )
                },
            )
        };
    }
    macro_rules! load2 {
        () => {
            (
                { blend!(_mm256_alignr_epi8(m6, m5, 8), _mm256_unpackhi_epi64(m2, m7)) },
                {
                    blend!(
                        _mm256_unpacklo_epi64(m4, m0),
                        _mm256_blend_epi32(m6, m1, 0b0011_0011)
                    )
                },
                { blend!(_mm256_alignr_epi8(m5, m4, 8), _mm256_unpackhi_epi64(m1, m3)) },
                {
                    blend!(
                        _mm256_unpacklo_epi64(m2, m7),
                        _mm256_blend_epi32(m0, m3, 0b0011_0011)
                    )
                },
            )
        };
    }
    macro_rules! load3 {
        () => {
            (
                { hi_hi!(m3, m1, m6, m5) },
                { hi_lo!(m4, m0, m6, m7) },
                {
                    blend!(
                        _mm256_alignr_epi8(m1, m7, 8),
                        _mm256_shuffle_epi32(m2, _MM_SHUFFLE(1, 0, 3, 2))
                    )
                },
                { blend!(_mm256_unpacklo_epi64(m4, m3), _mm256_unpacklo_epi64(m5, m0)) },
            )
        };
    }
    macro_rules! load4 {
        () => {
            (
                { hi_lo!(m4, m2, m1, m5) },
                {
                    blend!(
                        _mm256_blend_epi32(m3, m0, 0b0011_0011),
                        _mm256_blend_epi32(m7, m2, 0b0011_0011)
                    )
                },
                { blend!(_mm256_alignr_epi8(m7, m1, 8), _mm256_alignr_epi8(m3, m5, 8)) },
                { blend!(_mm256_unpackhi_epi64(m6, m0), _mm256_unpacklo_epi64(m6, m4)) },
            )
        };
    }
    macro_rules! load5 {
        () => {
            (
                { lo_lo!(m1, m3, m0, m4) },
                { lo_hi!(m6, m5, m5, m1) },
                { blend!(_mm256_alignr_epi8(m2, m0, 8), _mm256_unpackhi_epi64(m3, m7)) },
                { blend!(_mm256_unpackhi_epi64(m4, m6), _mm256_alignr_epi8(m7, m2, 8)) },
            )
        };
    }
    macro_rules! load6 {
        () => {
            (
                {
                    blend!(
                        _mm256_blend_epi32(m0, m6, 0b0011_0011),
                        _mm256_unpacklo_epi64(m7, m2)
                    )
                },
                { blend!(_mm256_unpackhi_epi64(m2, m7), _mm256_alignr_epi8(m5, m6, 8)) },
                {
                    blend!(
                        _mm256_unpacklo_epi64(m4, m0),
                        _mm256_blend_epi32(m4, m3, 0b0011_0011)
                    )
                },
                {
                    blend!(
                        _mm256_unpackhi_epi64(m5, m3),
                        _mm256_shuffle_epi32(m1, _MM_SHUFFLE(1, 0, 3, 2))
                    )
                },
            )
        };
    }
    macro_rules! load7 {
        () => {
            (
                {
                    blend!(
                        _mm256_unpackhi_epi64(m6, m3),
                        _mm256_blend_epi32(m1, m6, 0b0011_0011)
                    )
                },
                { blend!(_mm256_alignr_epi8(m7, m5, 8), _mm256_unpackhi_epi64(m0, m4)) },
                {
                    blend!(
                        _mm256_blend_epi32(m2, m1, 0b0011_0011),
                        _mm256_alignr_epi8(m4, m7, 8)
                    )
                },
                { blend!(_mm256_unpacklo_epi64(m5, m0), _mm256_unpacklo_epi64(m2, m3)) },
            )
        };
    }
    macro_rules! load8 {
        () => {
            (
                { blend!(_mm256_unpacklo_epi64(m3, m7), _mm256_alignr_epi8(m0, m5, 8)) },
                { blend!(_mm256_unpackhi_epi64(m7, m4), _mm256_alignr_epi8(m4, m1, 8)) },
                { lo_hi!(m5, m6, m6, m0) },
                { blend!(_mm256_alignr_epi8(m1, m2, 8), _mm256_alignr_epi8(m2, m3, 8)) },
            )
        };
    }
    macro_rules! load9 {
        () => {
            (
                { blend!(_mm256_unpacklo_epi64(m5, m4), _mm256_unpackhi_epi64(m3, m0)) },
                {
                    blend!(
                        _mm256_unpacklo_epi64(m1, m2),
                        _mm256_blend_epi32(m2, m3, 0b0011_0011)
                    )
                },
                { blend!(_mm256_unpackhi_epi64(m6, m7), _mm256_unpackhi_epi64(m4, m1)) },
                {
                    blend!(
                        _mm256_blend_epi32(m5, m0, 0b0011_0011),
                        _mm256_unpacklo_epi64(m7, m6)
                    )
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
    ROUND!(10, load0!());
    ROUND!(11, load1!());

    // now xor the original state with the and current state, store it back into the state (h)
    a = _mm256_xor_si256(a, c);
    b = _mm256_xor_si256(b, d);
    a = _mm256_xor_si256(a, state_a);
    b = _mm256_xor_si256(b, state_b);
    _mm256_storeu_si256(h, a);
    _mm256_storeu_si256(h.add(1), b);
}

pub fn compress_b(h: &mut [u64; 8], t: &mut [u64; 2], buf: &[u8], last: LastBlock) {
    let block = buf.as_ptr() as *const __m128i;
    let h = h.as_mut_ptr() as *mut __m256i;
    let iv = b::IV.as_ptr() as *const __m256i;
    let t_and_f = unsafe {
        if last == LastBlock::Yes {
            _mm256_set_epi64x(0, -1i64, t[1] as i64, t[0] as i64)
        } else {
            _mm256_set_epi64x(0, 0, t[1] as i64, t[0] as i64)
        }
    };

    unsafe {
        compress_b_avx2(h, block, iv, t_and_f);
    }
}
