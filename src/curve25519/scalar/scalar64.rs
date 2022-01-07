use super::super::fe::load::{load_3i, load_4i};

const M: [u64; 5] = [
    0x12631a5cf5d3ed,
    0xf9dea2f79cd658,
    0x000000000014de,
    0x00000000000000,
    0x00000010000000,
];

const MU: [u64; 5] = [
    0x9ce5a30a2c131b,
    0x215d086329a7ed,
    0xffffffffeb2106,
    0xffffffffffffff,
    0x00000fffffffff,
];

#[inline]
const fn lt_modm(a: u64, b: u64) -> u64 {
    (a.wrapping_sub(b)) >> 63
}

#[rustfmt::skip]
fn reduce256_modm(r: &mut [u64; 5]) {
    // t = r - m
    let mut t = [0u64; 5];
    let mut pb = 0;
    pb += M[0]; let b = lt_modm(r[0], pb); t[0] = r[0].wrapping_sub(pb).wrapping_add(b << 56); pb = b;
    pb += M[1]; let b = lt_modm(r[1], pb); t[1] = r[1].wrapping_sub(pb).wrapping_add(b << 56); pb = b;
    pb += M[2]; let b = lt_modm(r[2], pb); t[2] = r[2].wrapping_sub(pb).wrapping_add(b << 56); pb = b;
    pb += M[3]; let b = lt_modm(r[3], pb); t[3] = r[3].wrapping_sub(pb).wrapping_add(b << 56); pb = b;
    pb += M[4]; let b = lt_modm(r[4], pb); t[4] = r[4].wrapping_sub(pb).wrapping_add(b << 32);

    // keep r if r was smaller than m
    let mask = b.wrapping_sub(1);

    r[0] ^= mask & (r[0] ^ t[0]);
    r[1] ^= mask & (r[1] ^ t[1]);
    r[2] ^= mask & (r[2] ^ t[2]);
    r[3] ^= mask & (r[3] ^ t[3]);
    r[4] ^= mask & (r[4] ^ t[4]);
}

#[inline]
const fn mul128(a: u64, b: u64) -> u128 {
    a as u128 * b as u128
}

const fn shr128(value: u128, shift: usize) -> u64 {
    (value >> shift) as u64
}

const MASK16: u64 = 0x0000_0000_0000_ffff;
const MASK40: u64 = 0x0000_00ff_ffff_ffff;
const MASK56: u64 = 0x00ff_ffff_ffff_ffff;

#[rustfmt::skip]
fn barrett_reduce256_modm(out: &mut [u64; 5], q1: &[u64; 5], r1: [u64; 5]) {
    let mut r2 = [0; 5];
    let mut q3 = [0; 5];
    let mut c : u128;
    let mut mul : u128;
    let mut f : u64;
    let mut b : u64;
    let mut pb : u64;

    // q1 = x >> 248 = 264 bits = 5 56 bit elements
    // q2 = mu * q1
    // q3 = (q2 / 256(32+1)) = q2 / (2^8)^(32+1) = q2 >> 264

    c = mul128(MU[0], q1[3]);                 mul = mul128(MU[3], q1[0]); c += mul; mul = mul128(MU[1], q1[2]); c += mul; mul = mul128(MU[2], q1[1]); c += mul; f = shr128(c, 56);
    c = mul128(MU[0], q1[4]); c += f as u128; mul = mul128(MU[4], q1[0]); c += mul; mul = mul128(MU[3], q1[1]); c += mul; mul = mul128(MU[1], q1[3]); c += mul; mul = mul128(MU[2], q1[2]); c += mul;
    f = c as u64; q3[0] = (f >> 40) & MASK16; f = shr128(c, 56);
    c = mul128(MU[4], q1[1]); c += f as u128; mul = mul128(MU[1], q1[4]); c += mul; mul = mul128(MU[2], q1[3]); c += mul; mul = mul128(MU[3], q1[2]); c += mul;
    f = c as u64; q3[0] |= (f << 16) & MASK56; q3[1] = (f >> 40) & MASK16; f = shr128(c, 56);
    c = mul128(MU[4], q1[2]); c += f as u128; mul = mul128(MU[2], q1[4]); c += mul; mul = mul128(MU[3], q1[3]); c += mul;
    f = c as u64; q3[1] |= (f << 16) & MASK56; q3[2] = (f >> 40) & MASK16; f = shr128(c, 56);
    c = mul128(MU[4], q1[3]); c += f as u128; mul = mul128(MU[3], q1[4]); c += mul;
    f = c as u64; q3[2] |= (f << 16) & MASK56; q3[3] = (f >> 40) & MASK16; f = shr128(c, 56);
    c = mul128(MU[4], q1[4]); c += f as u128;
    f = c as u64; q3[3] |= (f << 16) & MASK56; q3[4] = (f >> 40) & MASK16; f = shr128(c, 56);
    q3[4] |= f << 16;

    c = mul128(M[0], q3[0]);
    r2[0] = (c as u64) & MASK56;  f = shr128(c, 56);
    c = mul128(M[0], q3[1]); c += f as u128; mul = mul128(M[1], q3[0]); c += mul;
    r2[1] = (c as u64) & MASK56; f = shr128(c, 56);
    c = mul128(M[0], q3[2]); c += f as u128; mul = mul128(M[2], q3[0]); c += mul; mul = mul128(M[1], q3[1]); c += mul;
    r2[2] = (c as u64) & MASK56; f = shr128(c, 56);
    c = mul128(M[0], q3[3]); c += f as u128; mul = mul128(M[3], q3[0]); c += mul; mul = mul128(M[1], q3[2]); c += mul; mul = mul128(M[2], q3[1]); c += mul;
    r2[3] = (c as u64) & MASK56; f = shr128(c, 56);
    c = mul128(M[0], q3[4]); c += f as u128; mul = mul128(M[4], q3[0]); c += mul; mul = mul128(M[3], q3[1]); c += mul; mul = mul128(M[1], q3[3]); c += mul; mul = mul128(M[2], q3[2]); c += mul;
    r2[4] = (c as u64) & MASK40;

    pb = 0;
    pb += r2[0]; b = lt_modm(r1[0], pb); out[0] = r1[0].wrapping_sub(pb).wrapping_add(b << 56); pb = b;
    pb += r2[1]; b = lt_modm(r1[1], pb); out[1] = r1[1].wrapping_sub(pb).wrapping_add(b << 56); pb = b;
    pb += r2[2]; b = lt_modm(r1[2], pb); out[2] = r1[2].wrapping_sub(pb).wrapping_add(b << 56); pb = b;
    pb += r2[3]; b = lt_modm(r1[3], pb); out[3] = r1[3].wrapping_sub(pb).wrapping_add(b << 56); pb = b;
    pb += r2[4]; b = lt_modm(r1[4], pb); out[4] = r1[4].wrapping_sub(pb).wrapping_add(b << 40);

    reduce256_modm(out);
    reduce256_modm(out);
}

fn to_bytes(limbs: &[u64; 5]) -> [u8; 32] {
    let mut out_saturated = [0u64; 4];
    out_saturated[0] = limbs[1] << 56 | limbs[0];
    out_saturated[1] = limbs[2] << 48 | limbs[1] >> 8;
    out_saturated[2] = limbs[3] << 40 | limbs[2] >> 16;
    out_saturated[3] = limbs[4] << 32 | limbs[3] >> 24;

    let mut bytes = [0u8; 32];
    crate::cryptoutil::write_u64v_le(&mut bytes, &out_saturated);
    bytes
}

/*
Input:
    s[0]+256*s[1]+...+256^63*s[63] = s

Output:
    s[0]+256*s[1]+...+256^31*s[31] = s mod l
    where l = 2^252 + 27742317777372353535851937790883648493.
*/
#[rustfmt::skip]
#[must_use]
pub(crate) fn reduce(s: &[u8; 64]) -> [u8; 32] {
        // load 8 bytes from input[ofs..ofs+7] as little endian u64
        #[inline]
        const fn load(bytes: &[u8; 64], ofs: usize) -> u64 {
            (bytes[ofs] as u64)
                | ((bytes[ofs + 1] as u64) << 8)
                | ((bytes[ofs + 2] as u64) << 16)
                | ((bytes[ofs + 3] as u64) << 24)
                | ((bytes[ofs + 4] as u64) << 32)
                | ((bytes[ofs + 5] as u64) << 40)
                | ((bytes[ofs + 6] as u64) << 48)
                | ((bytes[ofs + 7] as u64) << 56)
        }

        // load little endian bytes to u64
        let x0 = load(s, 0);
        let x1 = load(s, 8);
        let x2 = load(s, 16);
        let x3 = load(s, 24);
        let x4 = load(s, 32);
        let x5 = load(s, 40);
        let x6 = load(s, 48);
        let x7 = load(s, 56);

        /* r1 = (x mod 256^(32+1)) = x mod (2^8)(31+1) = x & ((1 << 264) - 1) */
        let mut out = [0; 5];
        out[0] = (                     x0) & 0x00ff_ffff_ffff_ffff;
        out[1] = ((x0 >> 56) | (x1 <<  8)) & 0x00ff_ffff_ffff_ffff;
        out[2] = ((x1 >> 48) | (x2 << 16)) & 0x00ff_ffff_ffff_ffff;
        out[3] = ((x2 >> 40) | (x3 << 24)) & 0x00ff_ffff_ffff_ffff;
        out[4] = ((x3 >> 32) | (x4 << 32)) & 0x0000_00ff_ffff_ffff;

        /*
        /* under 252 bits, no need to reduce */
        if (len < 32)
                return;
        */

        /* q1 = x >> 248 = 264 bits */
        let mut q1 = [0; 5];
        q1[0] = ((x3 >> 56) | (x4 <<  8)) & 0xffffffffffffff;
        q1[1] = ((x4 >> 48) | (x5 << 16)) & 0xffffffffffffff;
        q1[2] = ((x5 >> 40) | (x6 << 24)) & 0xffffffffffffff;
        q1[3] = ((x6 >> 32) | (x7 << 32)) & 0xffffffffffffff;
        q1[4] = x7 >> 24;

        let mut out2 = [0; 5];
        barrett_reduce256_modm(&mut out2, &q1, out);

        to_bytes(&out2)
}

/*
Input:
    a[0]+256*a[1]+...+256^31*a[31] = a
    b[0]+256*b[1]+...+256^31*b[31] = b
    c[0]+256*c[1]+...+256^31*c[31] = c

Output:
    s[0]+256*s[1]+...+256^31*s[31] = (ab+c) mod l
    where l = 2^252 + 27742317777372353535851937790883648493.
*/
#[rustfmt::skip]
pub(crate) fn muladd(s: &mut[u8; 32], a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) {
    let a0 = 2097151 & load_3i(&a[0..3]);
    let a1 = 2097151 & (load_4i(&a[2..6]) >> 5);
    let a2 = 2097151 & (load_3i(&a[5..8]) >> 2);
    let a3 = 2097151 & (load_4i(&a[7..11]) >> 7);
    let a4 = 2097151 & (load_4i(&a[10..14]) >> 4);
    let a5 = 2097151 & (load_3i(&a[13..16]) >> 1);
    let a6 = 2097151 & (load_4i(&a[15..19]) >> 6);
    let a7 = 2097151 & (load_3i(&a[18..21]) >> 3);
    let a8 = 2097151 & load_3i(&a[21..24]);
    let a9 = 2097151 & (load_4i(&a[23..27]) >> 5);
    let a10 = 2097151 & (load_3i(&a[26..29]) >> 2);
    let a11 = load_4i(&a[28..32]) >> 7;
    let b0 = 2097151 & load_3i(&b[0..3]);
    let b1 = 2097151 & (load_4i(&b[2..6]) >> 5);
    let b2 = 2097151 & (load_3i(&b[5..8]) >> 2);
    let b3 = 2097151 & (load_4i(&b[7..11]) >> 7);
    let b4 = 2097151 & (load_4i(&b[10..14]) >> 4);
    let b5 = 2097151 & (load_3i(&b[13..16]) >> 1);
    let b6 = 2097151 & (load_4i(&b[15..19]) >> 6);
    let b7 = 2097151 & (load_3i(&b[18..21]) >> 3);
    let b8 = 2097151 & load_3i(&b[21..24]);
    let b9 = 2097151 & (load_4i(&b[23..27]) >> 5);
    let b10 = 2097151 & (load_3i(&b[26..29]) >> 2);
    let b11 = load_4i(&b[28..32]) >> 7;
    let c0 = 2097151 & load_3i(&c[0..3]);
    let c1 = 2097151 & (load_4i(&c[2..6]) >> 5);
    let c2 = 2097151 & (load_3i(&c[5..8]) >> 2);
    let c3 = 2097151 & (load_4i(&c[7..11]) >> 7);
    let c4 = 2097151 & (load_4i(&c[10..14]) >> 4);
    let c5 = 2097151 & (load_3i(&c[13..16]) >> 1);
    let c6 = 2097151 & (load_4i(&c[15..19]) >> 6);
    let c7 = 2097151 & (load_3i(&c[18..21]) >> 3);
    let c8 = 2097151 & load_3i(&c[21..24]);
    let c9 = 2097151 & (load_4i(&c[23..27]) >> 5);
    let c10 = 2097151 & (load_3i(&c[26..29]) >> 2);
    let c11 = load_4i(&c[28..32]) >> 7;
    let mut s0: i64;
    let mut s1: i64;
    let mut s2: i64;
    let mut s3: i64;
    let mut s4: i64;
    let mut s5: i64;
    let mut s6: i64;
    let mut s7: i64;
    let mut s8: i64;
    let mut s9: i64;
    let mut s10: i64;
    let mut s11: i64;
    let mut s12: i64;
    let mut s13: i64;
    let mut s14: i64;
    let mut s15: i64;
    let mut s16: i64;
    let mut s17: i64;
    let mut s18: i64;
    let mut s19: i64;
    let mut s20: i64;
    let mut s21: i64;
    let mut s22: i64;
    let mut s23: i64;
    let mut carry0: i64;
    let mut carry1: i64;
    let mut carry2: i64;
    let mut carry3: i64;
    let mut carry4: i64;
    let mut carry5: i64;
    let mut carry6: i64;
    let mut carry7: i64;
    let mut carry8: i64;
    let mut carry9: i64;
    let mut carry10: i64;
    let mut carry11: i64;
    let mut carry12: i64;
    let mut carry13: i64;
    let mut carry14: i64;
    let mut carry15: i64;
    let mut carry16: i64;
    let carry17: i64;
    let carry18: i64;
    let carry19: i64;
    let carry20: i64;
    let carry21: i64;
    let carry22: i64;

    s0 = c0 + a0*b0;
    s1 = c1 + a0*b1 + a1*b0;
    s2 = c2 + a0*b2 + a1*b1 + a2*b0;
    s3 = c3 + a0*b3 + a1*b2 + a2*b1 + a3*b0;
    s4 = c4 + a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0;
    s5 = c5 + a0*b5 + a1*b4 + a2*b3 + a3*b2 + a4*b1 + a5*b0;
    s6 = c6 + a0*b6 + a1*b5 + a2*b4 + a3*b3 + a4*b2 + a5*b1 + a6*b0;
    s7 = c7 + a0*b7 + a1*b6 + a2*b5 + a3*b4 + a4*b3 + a5*b2 + a6*b1 + a7*b0;
    s8 = c8 + a0*b8 + a1*b7 + a2*b6 + a3*b5 + a4*b4 + a5*b3 + a6*b2 + a7*b1 + a8*b0;
    s9 = c9 + a0*b9 + a1*b8 + a2*b7 + a3*b6 + a4*b5 + a5*b4 + a6*b3 + a7*b2 + a8*b1 + a9*b0;
    s10 = c10 + a0*b10 + a1*b9 + a2*b8 + a3*b7 + a4*b6 + a5*b5 + a6*b4 + a7*b3 + a8*b2 + a9*b1 + a10*b0;
    s11 = c11 + a0*b11 + a1*b10 + a2*b9 + a3*b8 + a4*b7 + a5*b6 + a6*b5 + a7*b4 + a8*b3 + a9*b2 + a10*b1 + a11*b0;
    s12 = a1*b11 + a2*b10 + a3*b9 + a4*b8 + a5*b7 + a6*b6 + a7*b5 + a8*b4 + a9*b3 + a10*b2 + a11*b1;
    s13 = a2*b11 + a3*b10 + a4*b9 + a5*b8 + a6*b7 + a7*b6 + a8*b5 + a9*b4 + a10*b3 + a11*b2;
    s14 = a3*b11 + a4*b10 + a5*b9 + a6*b8 + a7*b7 + a8*b6 + a9*b5 + a10*b4 + a11*b3;
    s15 = a4*b11 + a5*b10 + a6*b9 + a7*b8 + a8*b7 + a9*b6 + a10*b5 + a11*b4;
    s16 = a5*b11 + a6*b10 + a7*b9 + a8*b8 + a9*b7 + a10*b6 + a11*b5;
    s17 = a6*b11 + a7*b10 + a8*b9 + a9*b8 + a10*b7 + a11*b6;
    s18 = a7*b11 + a8*b10 + a9*b9 + a10*b8 + a11*b7;
    s19 = a8*b11 + a9*b10 + a10*b9 + a11*b8;
    s20 = a9*b11 + a10*b10 + a11*b9;
    s21 = a10*b11 + a11*b10;
    s22 = a11*b11;
    s23 = 0;

    carry0 = (s0 + (1<<20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry2 = (s2 + (1<<20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry4 = (s4 + (1<<20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
    carry12 = (s12 + (1<<20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
    carry14 = (s14 + (1<<20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
    carry16 = (s16 + (1<<20)) >> 21; s17 += carry16; s16 -= carry16 << 21;
    carry18 = (s18 + (1<<20)) >> 21; s19 += carry18; s18 -= carry18 << 21;
    carry20 = (s20 + (1<<20)) >> 21; s21 += carry20; s20 -= carry20 << 21;
    carry22 = (s22 + (1<<20)) >> 21; s23 += carry22; s22 -= carry22 << 21;

    carry1 = (s1 + (1<<20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry3 = (s3 + (1<<20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry5 = (s5 + (1<<20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
    carry13 = (s13 + (1<<20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
    carry15 = (s15 + (1<<20)) >> 21; s16 += carry15; s15 -= carry15 << 21;
    carry17 = (s17 + (1<<20)) >> 21; s18 += carry17; s17 -= carry17 << 21;
    carry19 = (s19 + (1<<20)) >> 21; s20 += carry19; s19 -= carry19 << 21;
    carry21 = (s21 + (1<<20)) >> 21; s22 += carry21; s21 -= carry21 << 21;

    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;


    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;


    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;


    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;


    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;


    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;


    carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
    carry12 = (s12 + (1<<20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
    carry14 = (s14 + (1<<20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
    carry16 = (s16 + (1<<20)) >> 21; s17 += carry16; s16 -= carry16 << 21;

    carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
    carry13 = (s13 + (1<<20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
    carry15 = (s15 + (1<<20)) >> 21; s16 += carry15; s15 -= carry15 << 21;

    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;


    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;


    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;


    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;


    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;


    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = (s0 + (1<<20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry2 = (s2 + (1<<20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry4 = (s4 + (1<<20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;

    carry1 = (s1 + (1<<20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry3 = (s3 + (1<<20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry5 = (s5 + (1<<20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
    carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;


    carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

    s[0] = (s0 >> 0) as u8;
    s[1] = (s0 >> 8) as u8;
    s[2] = ((s0 >> 16) | (s1 << 5)) as u8;
    s[3] = (s1 >> 3) as u8;
    s[4] = (s1 >> 11) as u8;
    s[5] = ((s1 >> 19) | (s2 << 2)) as u8;
    s[6] = (s2 >> 6) as u8;
    s[7] = ((s2 >> 14) | (s3 << 7)) as u8;
    s[8] = (s3 >> 1) as u8;
    s[9] = (s3 >> 9) as u8;
    s[10] = ((s3 >> 17) | (s4 << 4)) as u8;
    s[11] = (s4 >> 4) as u8;
    s[12] = (s4 >> 12) as u8;
    s[13] = ((s4 >> 20) | (s5 << 1)) as u8;
    s[14] = (s5 >> 7) as u8;
    s[15] = ((s5 >> 15) | (s6 << 6)) as u8;
    s[16] = (s6 >> 2) as u8;
    s[17] = (s6 >> 10) as u8;
    s[18] = ((s6 >> 18) | (s7 << 3)) as u8;
    s[19] = (s7 >> 5) as u8;
    s[20] = (s7 >> 13) as u8;
    s[21] = (s8 >> 0) as u8;
    s[22] = (s8 >> 8) as u8;
    s[23] = ((s8 >> 16) | (s9 << 5)) as u8;
    s[24] = (s9 >> 3) as u8;
    s[25] = (s9 >> 11) as u8;
    s[26] = ((s9 >> 19) | (s10 << 2)) as u8;
    s[27] = (s10 >> 6) as u8;
    s[28] = ((s10 >> 14) | (s11 << 7)) as u8;
    s[29] = (s11 >> 1) as u8;
    s[30] = (s11 >> 9) as u8;
    s[31] = (s11 >> 17) as u8;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduction() {
        assert_eq!(reduce(&[0; 64]), [0; 32]);
        assert_eq!(
            reduce(&[
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]
        );

        assert_eq!(
            reduce(&[
                30, 1, 102, 252, 230, 223, 126, 62, 154, 62, 25, 173, 159, 16, 157, 227, 21, 140,
                223, 132, 84, 209, 86, 118, 35, 85, 26, 144, 12, 4, 76, 170, 93, 151, 77, 147, 32,
                213, 10, 135, 235, 26, 71, 94, 108, 45, 193, 229, 106, 233, 198, 109, 246, 81, 108,
                91, 63, 108, 220, 6, 119, 115, 9, 117
            ]),
            [
                4, 135, 152, 112, 4, 206, 189, 109, 105, 80, 162, 79, 191, 218, 37, 85, 225, 159,
                163, 149, 143, 3, 101, 222, 2, 81, 255, 223, 235, 242, 30, 12
            ]
        )
    }
}
