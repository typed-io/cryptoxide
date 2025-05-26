// adapted from the original blake2 sse implementation

use super::common::{b, s, LastBlock};

use core::arch::aarch64::*;

#[inline(always)]
unsafe fn compress_b_neon(
    h: *mut uint64x2_t,
    block: &[u8; 128],
    iv: &[uint64x2_t; 4],
    t: uint64x2_t,
    f: uint64x2_t,
) {
    let m0 = vreinterpretq_u64_u8(vld1q_u8((&block[0..]).as_ptr()));
    let m1 = vreinterpretq_u64_u8(vld1q_u8((&block[16..]).as_ptr()));
    let m2 = vreinterpretq_u64_u8(vld1q_u8((&block[32..]).as_ptr()));
    let m3 = vreinterpretq_u64_u8(vld1q_u8((&block[48..]).as_ptr()));
    let m4 = vreinterpretq_u64_u8(vld1q_u8((&block[64..]).as_ptr()));
    let m5 = vreinterpretq_u64_u8(vld1q_u8((&block[80..]).as_ptr()));
    let m6 = vreinterpretq_u64_u8(vld1q_u8((&block[96..]).as_ptr()));
    let m7 = vreinterpretq_u64_u8(vld1q_u8((&block[112..]).as_ptr()));

    let row1l = *h;
    let row1h = *h.add(1);
    let row2l = *h.add(2);
    let row2h = *h.add(3);

    let row3l = iv[0];
    let row3h = iv[1];
    let row4l = veorq_u64(iv[2], t);
    let row4h = veorq_u64(iv[3], f);

    macro_rules! G {
        ($b0: ident, $b1: ident, $rot1: expr, $rot2: expr) => {};
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
        () => {};
    }

    macro_rules! UNDIAGONALIZE {
        () => {};
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
                vcombine_u64(vget_low_u64(m0), vget_low_u64(m1)),
                vcombine_u64(vget_low_u64(m2), vget_low_u64(m3)),
                vcombine_u64(vget_high_u64(m0), vget_high_u64(m1)),
                vcombine_u64(vget_high_u64(m2), vget_high_u64(m3)),
                vcombine_u64(vget_low_u64(m4), vget_low_u64(m5)),
                vcombine_u64(vget_low_u64(m6), vget_low_u64(m7)),
                vcombine_u64(vget_high_u64(m4), vget_high_u64(m5)),
                vcombine_u64(vget_high_u64(m6), vget_high_u64(m7)),
            )
        };
    }
    macro_rules! load1 {
        () => {
            (
                vcombine_u64(vget_low_u64(m7), vget_low_u64(m2)),
                vcombine_u64(vget_high_u64(m4), vget_high_u64(m6)),
                vcombine_u64(vget_low_u64(m5), vget_low_u64(m4)),
                vextq_u64(m7, m3, 1),
                vextq_u64(m0, m0, 1),
                vcombine_u64(vget_high_u64(m5), vget_high_u64(m2)),
                vcombine_u64(vget_low_u64(m6), vget_low_u64(m1)),
                vcombine_u64(vget_high_u64(m3), vget_high_u64(m1)),
            )
        };
    }

    macro_rules! load2 {
        () => {
            (
                vextq_u64(m5, m6, 1),
                vcombine_u64(vget_high_u64(m2), vget_high_u64(m7)),
                vcombine_u64(vget_low_u64(m4), vget_low_u64(m0)),
                vcombine_u64(vget_low_u64(m1), vget_high_u64(m6)),
                vcombine_u64(vget_low_u64(m5), vget_high_u64(m1)),
                vcombine_u64(vget_high_u64(m3), vget_high_u64(m4)),
                vcombine_u64(vget_low_u64(m7), vget_low_u64(m3)),
                vextq_u64(m0, m2, 1),
            )
        };
    }

    macro_rules! load3 {
        () => {
            (
                vcombine_u64(vget_high_u64(m3), vget_high_u64(m1)),
                vcombine_u64(vget_high_u64(m6), vget_high_u64(m5)),
                vcombine_u64(vget_high_u64(m4), vget_high_u64(m0)),
                vcombine_u64(vget_low_u64(m6), vget_low_u64(m7)),
                vcombine_u64(vget_low_u64(m1), vget_high_u64(m2)),
                vcombine_u64(vget_low_u64(m2), vget_high_u64(m7)),
                vcombine_u64(vget_low_u64(m3), vget_low_u64(m5)),
                vcombine_u64(vget_low_u64(m0), vget_low_u64(m4)),
            )
        };
    }

    macro_rules! load4 {
        () => {
            (
                vcombine_u64(vget_high_u64(m4), vget_high_u64(m2)),
                vcombine_u64(vget_low_u64(m1), vget_low_u64(m5)),
                vcombine_u64(vget_low_u64(m0), vget_high_u64(m3)),
                vcombine_u64(vget_low_u64(m2), vget_high_u64(m7)),
                vcombine_u64(vget_low_u64(m7), vget_high_u64(m5)),
                vcombine_u64(vget_low_u64(m3), vget_high_u64(m1)),
                vextq_u64(m0, m6, 1),
                vcombine_u64(vget_low_u64(m4), vget_high_u64(m6)),
            )
        };
    }

    macro_rules! load5 {
        () => {
            (
                vcombine_u64(vget_low_u64(m1), vget_low_u64(m3)),
                vcombine_u64(vget_low_u64(m0), vget_low_u64(m4)),
                vcombine_u64(vget_low_u64(m6), vget_low_u64(m5)),
                vcombine_u64(vget_high_u64(m5), vget_high_u64(m1)),
                vcombine_u64(vget_low_u64(m2), vget_high_u64(m3)),
                vcombine_u64(vget_high_u64(m7), vget_high_u64(m0)),
                vcombine_u64(vget_high_u64(m6), vget_high_u64(m2)),
                vcombine_u64(vget_low_u64(m7), vget_high_u64(m4)),
            )
        };
    }

    macro_rules! load6 {
        () => {
            (
                vcombine_u64(vget_low_u64(m6), vget_high_u64(m0)),
                vcombine_u64(vget_low_u64(m7), vget_low_u64(m2)),
                vcombine_u64(vget_high_u64(m2), vget_high_u64(m7)),
                vextq_u64(m6, m5, 1),
                vcombine_u64(vget_low_u64(m0), vget_low_u64(m3)),
                vextq_u64(m4, m4, 1),
                vcombine_u64(vget_high_u64(m3), vget_high_u64(m1)),
                vcombine_u64(vget_low_u64(m1), vget_high_u64(m5)),
            )
        };
    }

    macro_rules! load7 {
        () => {
            (
                vcombine_u64(vget_high_u64(m6), vget_high_u64(m3)),
                vcombine_u64(vget_low_u64(m6), vget_high_u64(m1)),
                vextq_u64(m5, m7, 1),
                vcombine_u64(vget_high_u64(m0), vget_high_u64(m4)),
                vcombine_u64(vget_high_u64(m2), vget_high_u64(m7)),
                vcombine_u64(vget_low_u64(m4), vget_low_u64(m1)),
                vcombine_u64(vget_low_u64(m0), vget_low_u64(m2)),
                vcombine_u64(vget_low_u64(m3), vget_low_u64(m5)),
            )
        };
    }

    macro_rules! load8 {
        () => {
            (
                vcombine_u64(vget_low_u64(m3), vget_low_u64(m7)),
                vextq_u64(m5, m0, 1),
                vcombine_u64(vget_high_u64(m7), vget_high_u64(m4)),
                vextq_u64(m1, m4, 1),
                m6,
                vextq_u64(m0, m5, 1),
                vcombine_u64(vget_low_u64(m1), vget_high_u64(m3)),
                m2,
            )
        };
    }

    macro_rules! load9 {
        () => {
            (
                vcombine_u64(vget_low_u64(m5), vget_low_u64(m4)),
                vcombine_u64(vget_high_u64(m3), vget_high_u64(m0)),
                vcombine_u64(vget_low_u64(m1), vget_low_u64(m2)),
                vcombine_u64(vget_low_u64(m3), vget_high_u64(m2)),
                vcombine_u64(vget_high_u64(m7), vget_high_u64(m4)),
                vcombine_u64(vget_high_u64(m1), vget_high_u64(m6)),
                vextq_u64(m5, m7, 1),
                vcombine_u64(vget_low_u64(m6), vget_low_u64(m0)),
            )
        };
    }

    macro_rules! G {
        ($b: ident, $rol1: expr, $rol2: expr) => {};
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
        () => {};
    }

    macro_rules! UNDIAGONALIZE {
        () => {};
    }

    macro_rules! ROUND {
        ($load: expr) => {
            let (b0, b1, b2, b3, b4, b5, b6, b7) = $load;
            G1!(b0);
            G2!(b1);
            DIAGONALIZE!();
            G1!(b2);
            G2!(b3);
            UNDIAGONALIZE!();
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

    *h = veorq_u64(*h, veorq_u64(row1l, row3l));
    *h.add(1) = veorq_u64(*h.add(1), veorq_u64(row1h, row3h));
    *h.add(2) = veorq_u64(*h.add(2), veorq_u64(row2l, row4l));
    *h.add(3) = veorq_u64(*h.add(3), veorq_u64(row2h, row4h));
}

pub fn compress_b(h: &mut [u64; 8], t: &mut [u64; 2], buf: &[u8], last: LastBlock) {
    unsafe {
        let h = h.as_ptr() as *mut uint64x2_t;
        //let iv = b::IV.as_ptr() as *const uint64x2_t;
        let iv = [
            vld1q_u64(b::IV.as_ptr()),
            vld1q_u64(b::IV.as_ptr().add(2)),
            vld1q_u64(b::IV.as_ptr().add(4)),
            vld1q_u64(b::IV.as_ptr().add(6)),
        ];
        let t = vld1q_u64(t.as_ptr());

        let f = vld1q_u64(if last == LastBlock::Yes {
            [0xffff_ffff_ffff_ffff, 0].as_ptr()
        } else {
            [0, 0].as_ptr()
        });

        compress_b_neon(h, <&[u8; 128]>::try_from(buf).unwrap(), &iv, t, f);
    }
}

pub fn compress_s(h: &mut [u32; 8], t: &[u32; 2], buf: &[u8], last: LastBlock) {
    todo!()
}
