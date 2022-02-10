//! Scalar ℤ/(2^252 + 27742317777372353535851937790883648493) implementations
//!
//! port of <https://github.com/floodyberry/ed25519-donna/blob/master/modm-donna-64bit.h>
//!
//! scalar is back by 5 Limbs in 56 bits unsaturated (except last)

/// Scalar in the field ℤ/2^252 + 27742317777372353535851937790883648493)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scalar([u64; 5]);

/// Order of Scalar :
///
/// $M = 2^252 + 27742317777372353535851937790883648493$
const M: [u64; 5] = [
    0x0012_631a_5cf5_d3ed,
    0x00f9_dea2_f79c_d658,
    0x0000_0000_0000_14de,
    0x0000_0000_0000_0000,
    0x0000_0000_1000_0000,
];

const MU: [u64; 5] = [
    0x009c_e5a3_0a2c_131b,
    0x0021_5d08_6329_a7ed,
    0x00ff_ffff_ffeb_2106,
    0x00ff_ffff_ffff_ffff,
    0x0000_000f_ffff_ffff,
];

#[inline]
const fn lt(a: u64, b: u64) -> u64 {
    (a.wrapping_sub(b)) >> 63
}

const fn lt_order(v: &[u64; 5]) -> bool {
    // v - L < 0 => borrow is 1
    let b = lt(v[0], M[0]);
    let b = lt(v[1], b + M[1]);
    let b = lt(v[2], b + M[2]);
    let b = lt(v[3], b + M[3]);
    let b = lt(v[4], b + M[4]);
    b == 1
}

#[rustfmt::skip]
const fn reduce256(mut r: [u64; 5]) -> [u64;5] {
    // t = r - m
    let mut t = [0u64; 5];
    let mut pb;

    let b = lt(r[0], M[0]); t[0] = r[0].wrapping_sub(M[0]).wrapping_add(b << 56); pb = b + M[1];
    let b = lt(r[1], pb); t[1] = r[1].wrapping_sub(pb).wrapping_add(b << 56); pb = b + M[2];
    let b = lt(r[2], pb); t[2] = r[2].wrapping_sub(pb).wrapping_add(b << 56); pb = b + M[3];
    let b = lt(r[3], pb); t[3] = r[3].wrapping_sub(pb).wrapping_add(b << 56); pb = b + M[4];
    let b = lt(r[4], pb); t[4] = r[4].wrapping_sub(pb).wrapping_add(b << 32);

    // keep r if r was smaller than m
    let mask = b.wrapping_sub(1);

    r[0] ^= mask & (r[0] ^ t[0]);
    r[1] ^= mask & (r[1] ^ t[1]);
    r[2] ^= mask & (r[2] ^ t[2]);
    r[3] ^= mask & (r[3] ^ t[3]);
    r[4] ^= mask & (r[4] ^ t[4]);
    r
}

#[inline]
const fn mul128(a: u64, b: u64) -> u128 {
    a as u128 * b as u128
}

#[inline]
const fn shr128(value: u128, shift: usize) -> u64 {
    (value >> shift) as u64
}

const MASK16: u64 = 0x0000_0000_0000_ffff;
const MASK40: u64 = 0x0000_00ff_ffff_ffff;
const MASK56: u64 = 0x00ff_ffff_ffff_ffff;

impl Scalar {
    pub const ZERO: Self = Scalar([0, 0, 0, 0, 0]);
    pub const ONE: Self = Scalar([1, 0, 0, 0, 0]);

    pub const fn from_bytes(bytes: &[u8; 32]) -> Self {
        // load 8 bytes from input[ofs..ofs+7] as little endian u64
        #[inline]
        const fn load(bytes: &[u8; 32], ofs: usize) -> u64 {
            (bytes[ofs] as u64)
                | ((bytes[ofs + 1] as u64) << 8)
                | ((bytes[ofs + 2] as u64) << 16)
                | ((bytes[ofs + 3] as u64) << 24)
                | ((bytes[ofs + 4] as u64) << 32)
                | ((bytes[ofs + 5] as u64) << 40)
                | ((bytes[ofs + 6] as u64) << 48)
                | ((bytes[ofs + 7] as u64) << 56)
        }

        let x0 = load(bytes, 0);
        let x1 = load(bytes, 8);
        let x2 = load(bytes, 16);
        let x3 = load(bytes, 24);

        let out0 = x0 & MASK56;
        let out1 = (x0 >> 56 | x1 << 8) & MASK56;
        let out2 = (x1 >> 48 | x2 << 16) & MASK56;
        let out3 = (x2 >> 40 | x3 << 24) & MASK56;
        let out4 = x3 >> 32;
        Scalar([out0, out1, out2, out3, out4])
    }

    // Same as from_bytes but check whether the value
    pub fn from_bytes_canonical(bytes: &[u8; 32]) -> Option<Self> {
        let scalar = Self::from_bytes(bytes);
        if lt_order(&scalar.0) {
            Some(scalar)
        } else {
            None
        }
    }

    pub const fn to_bytes(&self) -> [u8; 32] {
        // contract limbs into saturated limbs
        let c0 = self.0[1] << 56 | self.0[0];
        let c1 = self.0[2] << 48 | self.0[1] >> 8;
        let c2 = self.0[3] << 40 | self.0[2] >> 16;
        let c3 = self.0[4] << 32 | self.0[3] >> 24;

        // write saturated limbs into little endian bytes
        let mut out = [0u8; 32];
        macro_rules! write8 {
            ($ofs:literal, $v:ident) => {
                let x = $v.to_le_bytes();
                out[$ofs] = x[0];
                out[$ofs + 1] = x[1];
                out[$ofs + 2] = x[2];
                out[$ofs + 3] = x[3];
                out[$ofs + 4] = x[4];
                out[$ofs + 5] = x[5];
                out[$ofs + 6] = x[6];
                out[$ofs + 7] = x[7];
            };
        }
        write8!(0, c0);
        write8!(8, c1);
        write8!(16, c2);
        write8!(24, c3);
        out
    }

    #[inline]
    pub(crate) fn bits(&self) -> [i8; 256] {
        // contract limbs into saturated limbs
        let mut c = [0; 4];
        c[0] = self.0[1] << 56 | self.0[0];
        c[1] = self.0[2] << 48 | self.0[1] >> 8;
        c[2] = self.0[3] << 40 | self.0[2] >> 16;
        c[3] = self.0[4] << 32 | self.0[3] >> 24;

        let mut r = [0i8; 256];
        for i in 0..256 {
            r[i] = (1 & (c[i >> 6] >> (i & 0x3f))) as i8;
        }
        r
    }

    /// Get the scalar in a form of 64 nibbles
    ///
    /// nibble is a group of 4-bits
    pub(crate) fn nibbles(&self) -> [i8; 64] {
        let mut es: [i8; 64] = [0; 64];

        // contract limbs
        let mut c = [0; 4];
        c[0] = self.0[1] << 56 | self.0[0];
        c[1] = self.0[2] << 48 | self.0[1] >> 8;
        c[2] = self.0[3] << 40 | self.0[2] >> 16;
        c[3] = self.0[4] << 32 | self.0[3] >> 24;

        // write 16 nibbles for each saturated limbs, for 64 nibbles
        for b in 0..4 {
            es[16 * b + 0] = ((c[b] >> 0) & 0b1111) as i8;
            es[16 * b + 1] = ((c[b] >> 4) & 0b1111) as i8;
            es[16 * b + 2] = ((c[b] >> 8) & 0b1111) as i8;
            es[16 * b + 3] = ((c[b] >> 12) & 0b1111) as i8;
            es[16 * b + 4] = ((c[b] >> 16) & 0b1111) as i8;
            es[16 * b + 5] = ((c[b] >> 20) & 0b1111) as i8;
            es[16 * b + 6] = ((c[b] >> 24) & 0b1111) as i8;
            es[16 * b + 7] = ((c[b] >> 28) & 0b1111) as i8;
            es[16 * b + 8] = ((c[b] >> 32) & 0b1111) as i8;
            es[16 * b + 9] = ((c[b] >> 36) & 0b1111) as i8;
            es[16 * b + 10] = ((c[b] >> 40) & 0b1111) as i8;
            es[16 * b + 11] = ((c[b] >> 44) & 0b1111) as i8;
            es[16 * b + 12] = ((c[b] >> 48) & 0b1111) as i8;
            es[16 * b + 13] = ((c[b] >> 52) & 0b1111) as i8;
            es[16 * b + 14] = ((c[b] >> 56) & 0b1111) as i8;
            es[16 * b + 15] = ((c[b] >> 60) & 0b1111) as i8;
        }
        es
    }
}

#[rustfmt::skip]
const fn barrett_reduce256(q1: &[u64; 5], r1: &[u64; 5]) -> [u64; 5] {
    let mut r2 = [0; 5];
    let mut q3 = [0; 5];
    let mut c : u128;
    let mut f : u64;
    let mut b : u64;
    let mut pb : u64;

    // q1 = x >> 248 = 264 bits = 5 56 bit elements
    // q2 = mu * q1
    // q3 = (q2 / 256(32+1)) = q2 / (2^8)^(32+1) = q2 >> 264

    c = mul128(MU[0], q1[3]) + mul128(MU[3], q1[0]) + mul128(MU[1], q1[2]) + mul128(MU[2], q1[1]); f = shr128(c, 56);
    c = mul128(MU[0], q1[4]) + (f as u128) + mul128(MU[4], q1[0]) + mul128(MU[3], q1[1]) + mul128(MU[1], q1[3]) + mul128(MU[2], q1[2]);
    f = c as u64; q3[0] = (f >> 40) & MASK16; f = shr128(c, 56);
    c = mul128(MU[4], q1[1]) + (f as u128) + mul128(MU[1], q1[4]) + mul128(MU[2], q1[3]) + mul128(MU[3], q1[2]);
    f = c as u64; q3[0] |= (f << 16) & MASK56; q3[1] = (f >> 40) & MASK16; f = shr128(c, 56);
    c = mul128(MU[4], q1[2]) + (f as u128) + mul128(MU[2], q1[4]) + mul128(MU[3], q1[3]);
    f = c as u64; q3[1] |= (f << 16) & MASK56; q3[2] = (f >> 40) & MASK16; f = shr128(c, 56);
    c = mul128(MU[4], q1[3]) + (f as u128) + mul128(MU[3], q1[4]);
    f = c as u64; q3[2] |= (f << 16) & MASK56; q3[3] = (f >> 40) & MASK16; f = shr128(c, 56);
    c = mul128(MU[4], q1[4]) + (f as u128);
    f = c as u64; q3[3] |= (f << 16) & MASK56; q3[4] = (f >> 40) & MASK16; f = shr128(c, 56);
    q3[4] |= f << 16;

    c = mul128(M[0], q3[0]);
    r2[0] = (c as u64) & MASK56; f = shr128(c, 56);
    c = mul128(M[0], q3[1]) + (f as u128) + mul128(M[1], q3[0]);
    r2[1] = (c as u64) & MASK56; f = shr128(c, 56);
    c = mul128(M[0], q3[2]) + (f as u128) + mul128(M[2], q3[0]) + mul128(M[1], q3[1]);
    r2[2] = (c as u64) & MASK56; f = shr128(c, 56);
    c = mul128(M[0], q3[3]) + (f as u128) + mul128(M[3], q3[0]) + mul128(M[1], q3[2]) + mul128(M[2], q3[1]);
    r2[3] = (c as u64) & MASK56; f = shr128(c, 56);
    c = mul128(M[0], q3[4]) + (f as u128) + mul128(M[4], q3[0]) + mul128(M[3], q3[1]) + mul128(M[1], q3[3]) + mul128(M[2], q3[2]);
    r2[4] = (c as u64) & MASK40;

    let mut out = [0u64;5];

    pb = 0;
    pb += r2[0]; b = lt(r1[0], pb); out[0] = r1[0].wrapping_sub(pb).wrapping_add(b << 56); pb = b;
    pb += r2[1]; b = lt(r1[1], pb); out[1] = r1[1].wrapping_sub(pb).wrapping_add(b << 56); pb = b;
    pb += r2[2]; b = lt(r1[2], pb); out[2] = r1[2].wrapping_sub(pb).wrapping_add(b << 56); pb = b;
    pb += r2[3]; b = lt(r1[3], pb); out[3] = r1[3].wrapping_sub(pb).wrapping_add(b << 56); pb = b;
    pb += r2[4]; b = lt(r1[4], pb); out[4] = r1[4].wrapping_sub(pb).wrapping_add(b << 40);

    reduce256(reduce256(out))
}

impl Scalar {
    /// Create a new scalar from 64 bytes (512 bits) reducing
    /// the scalar to an element of the field
    ///
    /// Input is a little endian 512 bits scalar value:
    /// `s=s[0]+256*s[1]+...+256^63*s[63]`
    ///
    /// And the output scalar is a `s % order of field`
    #[must_use]
    pub const fn reduce_from_wide_bytes(s: &[u8; 64]) -> Scalar {
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
        out[0] = x0 & MASK56;
        out[1] = ((x0 >> 56) | (x1 << 8)) & MASK56;
        out[2] = ((x1 >> 48) | (x2 << 16)) & MASK56;
        out[3] = ((x2 >> 40) | (x3 << 24)) & MASK56;
        out[4] = ((x3 >> 32) | (x4 << 32)) & MASK40;

        /* q1 = x >> 248 = 264 bits */
        let mut q1 = [0; 5];
        q1[0] = ((x3 >> 56) | (x4 << 8)) & MASK56;
        q1[1] = ((x4 >> 48) | (x5 << 16)) & MASK56;
        q1[2] = ((x5 >> 40) | (x6 << 24)) & MASK56;
        q1[3] = ((x6 >> 32) | (x7 << 32)) & MASK56;
        q1[4] = x7 >> 24;

        Scalar(barrett_reduce256(&q1, &out))
    }
}

/// Add 2 scalars and return the reduced scalar
#[rustfmt::skip]
const fn add(Scalar(x): &Scalar, Scalar(y): &Scalar) -> Scalar {
    let mut c;
    let mut r = [0; 5];

	c  = x[0] + y[0]; r[0] = c & MASK56; c >>= 56;
	c += x[1] + y[1]; r[1] = c & MASK56; c >>= 56;
	c += x[2] + y[2]; r[2] = c & MASK56; c >>= 56;
	c += x[3] + y[3]; r[3] = c & MASK56; c >>= 56;
	c += x[4] + y[4]; r[4] = c;

	Scalar(reduce256(r))
}

/// Multiply two scalars and return the reduced scalar
#[rustfmt::skip]
const fn mul(Scalar(x): &Scalar, Scalar(y): &Scalar) -> Scalar {
    let mut q1 = [0; 5];
    let mut r1 = [0; 5];

	let c = mul128(x[0], y[0]);
	r1[0] = (c as u64) & MASK56; let f = shr128(c, 56);
	let c = mul128(x[0], y[1]) + (f as u128) + mul128(x[1], y[0]);
	r1[1] = (c as u64) & MASK56; let f = shr128(c, 56);
	let c = mul128(x[0], y[2]) + (f as u128) + mul128(x[2], y[0]) + mul128(x[1], y[1]);
	r1[2] = (c as u64) & MASK56; let f = shr128(c, 56);
	let c = mul128(x[0], y[3]) + (f as u128) + mul128(x[3], y[0]) + mul128(x[1], y[2]) + mul128(x[2], y[1]);
	r1[3] = (c as u64) & MASK56; let f = shr128(c, 56);
	let c = mul128(x[0], y[4]) + (f as u128) + mul128(x[4], y[0]) + mul128(x[3], y[1]) + mul128(x[1], y[3]) + mul128(x[2], y[2]);
	r1[4] = (c as u64) & MASK40; q1[0] = ((c as u64) >> 24) & 0xffffffff; let f = shr128(c, 56);

	let c = mul128(x[4], y[1]) + (f as u128) + mul128(x[1], y[4]) + mul128(x[2], y[3]) + mul128(x[3], y[2]);
	let f = c as u64; q1[0] |= (f << 32) & MASK56; q1[1] = (f >> 24) & 0xffffffff; let f = shr128(c, 56);
	let c = mul128(x[4], y[2]) + (f as u128) + mul128(x[2], y[4]) + mul128(x[3], y[3]);
	let f = c as u64; q1[1] |= (f << 32) & MASK56; q1[2] = (f >> 24) & 0xffffffff; let f = shr128(c, 56);
	let c = mul128(x[4], y[3]) + (f as u128) + mul128(x[3], y[4]);
	let f = c as u64; q1[2] |= (f << 32) & MASK56; q1[3] = (f >> 24) & 0xffffffff; let f = shr128(c, 56);
	let c = mul128(x[4], y[4]) + (f as u128);
	let f = c as u64; q1[3] |= (f << 32) & MASK56; q1[4] = (f >> 24) & 0xffffffff; let f = shr128(c, 56);
	q1[4] |= f << 32;

	Scalar(barrett_reduce256(&q1, &r1))
}

/// Compute `s = (a * b + c) mod L`
///
/// where
///   `a = a[0]+256*a[1]+...+256^31*a[31]`
///   `b = b[0]+256*b[1]+...+256^31*b[31]`
///   `c = c[0]+256*c[1]+...+256^31*c[31]`
pub(crate) fn muladd(a: &Scalar, b: &Scalar, c: &Scalar) -> Scalar {
    let m = mul(&a, &b);
    let r = add(&m, &c);
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve25519::testrng::{GeneratorOf, GeneratorOf2, GeneratorRaw};

    fn next_scalar(gen: &mut GeneratorRaw) -> Scalar {
        let mut bytes = gen.bytes();
        bytes[31] &= 0x0f; // 2^252 max for simplicity
        Scalar::from_bytes(&bytes)
    }

    #[test]
    fn serialization() {
        for scalar in GeneratorOf::new(0, 100, next_scalar) {
            let after_serialization = Scalar::from_bytes(&scalar.to_bytes());
            assert_eq!(scalar, after_serialization);
        }
    }

    #[test]
    fn add_iv() {
        struct Iv {
            a: [u8; 32],
            b: [u8; 32],
            r: [u8; 32],
        }

        let ivs = [Iv {
            a: [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            b: [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 15, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ],
            r: [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 15, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ],
        }];

        for (i, iv) in ivs.iter().enumerate() {
            let a = Scalar::from_bytes(&iv.a);
            let b = Scalar::from_bytes(&iv.b);
            let r = add(&a, &b);
            assert_eq!(r.to_bytes(), iv.r, "iv test {} failed", i);
        }
    }

    #[test]
    fn add_commutes() {
        for (x, y) in GeneratorOf2::new(0, 100, next_scalar) {
            assert_eq!(add(&x, &y), add(&y, &x));
        }
    }

    #[test]
    fn mul_commutes() {
        for (x, y) in GeneratorOf2::new(0, 100, next_scalar) {
            assert_eq!(mul(&x, &y), mul(&y, &x));
        }
    }

    #[test]
    fn canonical() {
        const L: [u8; 32] = [
            237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
        ];
        const LM1: [u8; 32] = [
            236, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
        ];
        const LP1: [u8; 32] = [
            238, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
        ];
        assert!(Scalar::from_bytes_canonical(&Scalar::ZERO.to_bytes()).is_some());
        assert!(Scalar::from_bytes_canonical(&Scalar::ONE.to_bytes()).is_some());
        // order
        assert!(Scalar::from_bytes_canonical(&LM1).is_some());
        assert!(Scalar::from_bytes_canonical(&L).is_none());
        assert!(Scalar::from_bytes_canonical(&LP1).is_none());
    }

    #[test]
    fn reduction() {
        assert_eq!(Scalar::reduce_from_wide_bytes(&[0; 64]).to_bytes(), [0; 32]);
        assert_eq!(
            Scalar::reduce_from_wide_bytes(&[
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ])
            .to_bytes(),
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]
        );

        assert_eq!(
            Scalar::reduce_from_wide_bytes(&[
                30, 1, 102, 252, 230, 223, 126, 62, 154, 62, 25, 173, 159, 16, 157, 227, 21, 140,
                223, 132, 84, 209, 86, 118, 35, 85, 26, 144, 12, 4, 76, 170, 93, 151, 77, 147, 32,
                213, 10, 135, 235, 26, 71, 94, 108, 45, 193, 229, 106, 233, 198, 109, 246, 81, 108,
                91, 63, 108, 220, 6, 119, 115, 9, 117
            ])
            .to_bytes(),
            [
                4, 135, 152, 112, 4, 206, 189, 109, 105, 80, 162, 79, 191, 218, 37, 85, 225, 159,
                163, 149, 143, 3, 101, 222, 2, 81, 255, 223, 235, 242, 30, 12
            ]
        )
    }
}
