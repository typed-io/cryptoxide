//! Polynomials of `R_q = Z_q[X]/(X^256 + 1)`, along with the sampling and
//! serialisation routines that ML-DSA defines on them

use super::group::{self, add, center, from_centered, low_bits, mul, sub, Zq, D, INV256, Q, ZETAS};
use crate::hashing::shake::{Shake128, Shake256};

/// Number of coefficients of a polynomial of `R_q`
pub(super) const N: usize = 256;

/// The widest coefficient encoding used by any parameter set, the `1 +
/// bitlen(GAMMA1 - 1)` of ML-DSA-65 and ML-DSA-87
const MAX_GAMMA1_BITS: usize = 20;

/// A polynomial of `R_q`, or an element of `T_q` once transformed by [`Poly::ntt`]
///
/// `X^256 + 1` splits into 256 distinct linear factors modulo `Q`
#[derive(Clone, Copy)]
pub(super) struct Poly([Zq; N]);

/// The hint bits that a signature carries for one polynomial
///
/// One bit per coefficient, held in the little endian bit order that
/// `HintBitPack` reads them out in.
#[derive(Clone, Copy)]
pub(super) struct Hint([u8; N / 8]);

impl Hint {
    pub(super) const ZERO: Self = Hint([0; N / 8]);

    pub(super) fn get(&self, i: usize) -> bool {
        (self.0[i / 8] >> (i % 8)) & 1 == 1
    }

    pub(super) fn set(&mut self, i: usize) {
        self.0[i / 8] |= 1 << (i % 8);
    }

    /// Number of set hint bits, the `ones(h)` of FIPS 204
    pub(super) fn count(&self) -> u32 {
        self.0.iter().map(|b| b.count_ones()).sum()
    }
}

impl Poly {
    pub(super) const ZERO: Self = Poly([0; N]);

    pub(super) fn add_mut(&mut self, rhs: &Poly) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a = add(*a, *b);
        }
    }

    pub(super) fn sub_mut(&mut self, rhs: &Poly) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a = sub(*a, *b);
        }
    }

    /// FIPS 204 Algorithm 41 `NTT`: in place number theoretic transform
    ///
    /// Maps `R_q` to `T_q`, in which the multiplication of two polynomials
    /// becomes a coefficient wise product.
    pub(super) fn ntt(&mut self) {
        let f = &mut self.0;
        let mut i = 1;
        let mut len = 128;
        while len >= 1 {
            let mut start = 0;
            while start < N {
                let zeta = ZETAS[i];
                i += 1;
                for j in start..start + len {
                    let t = mul(zeta, f[j + len]);
                    f[j + len] = sub(f[j], t);
                    f[j] = add(f[j], t);
                }
                start += 2 * len;
            }
            len >>= 1;
        }
    }

    /// FIPS 204 Algorithm 42 `NTT^-1`: in place inverse of [`Poly::ntt`]
    pub(super) fn inv_ntt(&mut self) {
        let f = &mut self.0;
        let mut i = 255;
        let mut len = 1;
        while len < N {
            let mut start = 0;
            while start < N {
                let zeta = ZETAS[i];
                i -= 1;
                for j in start..start + len {
                    let t = f[j];
                    f[j] = add(t, f[j + len]);
                    f[j + len] = mul(zeta, sub(f[j + len], t));
                }
                start += 2 * len;
            }
            len <<= 1;
        }
        for c in f.iter_mut() {
            *c = mul(*c, INV256);
        }
    }

    /// FIPS 204 Algorithm 45 `MultiplyNTT`: add the product of `a` and `b`,
    /// both in `T_q`, to `self`
    ///
    /// Accumulating rather than returning the product keeps the matrix by
    /// vector products down to a single temporary polynomial.
    pub(super) fn mul_acc(&mut self, a: &Poly, b: &Poly) {
        for (s, (x, y)) in self.0.iter_mut().zip(a.0.iter().zip(b.0.iter())) {
            *s = add(*s, mul(*x, *y));
        }
    }

    /// The infinity norm of the polynomial: the largest `|c mod± q|`
    pub(super) fn norm(&self) -> u32 {
        self.0.iter().fold(0, |m, c| m.max(group::norm(*c)))
    }

    /// The infinity norm of the low parts of the coefficients, ie.
    /// `||LowBits(self)||` of FIPS 204
    pub(super) fn low_bits_norm<const GAMMA2: u32>(&self) -> u32 {
        self.0
            .iter()
            .fold(0, |m, c| m.max(low_bits::<GAMMA2>(*c).unsigned_abs()))
    }

    /// FIPS 204 Algorithm 35 `Power2Round` applied coefficient wise, returning
    /// the high and low halves as two polynomials
    pub(super) fn power2round(&self) -> (Poly, Poly) {
        let mut t1 = Poly::ZERO;
        let mut t0 = Poly::ZERO;
        for (i, c) in self.0.iter().enumerate() {
            (t1.0[i], t0.0[i]) = group::power2round(*c);
        }
        (t1, t0)
    }

    /// FIPS 204 Algorithm 37 `HighBits` applied coefficient wise
    pub(super) fn high_bits<const GAMMA2: u32>(&self) -> Poly {
        Poly(core::array::from_fn(|i| {
            group::high_bits::<GAMMA2>(self.0[i])
        }))
    }

    /// Multiply every coefficient by `2^D`, the scaling that `Verify` applies
    /// to the `t1` it reads from the public key
    pub(super) fn scale_2d(&self) -> Poly {
        Poly(core::array::from_fn(|i| mul(self.0[i], 1 << D)))
    }

    /// FIPS 204 Algorithm 39 `MakeHint` applied coefficient wise, on `r` and
    /// `r + z` rather than on `r` and `z`
    pub(super) fn make_hint<const GAMMA2: u32>(r: &Poly, r_plus_z: &Poly) -> Hint {
        let mut h = Hint::ZERO;
        for (i, (a, b)) in r.0.iter().zip(r_plus_z.0.iter()).enumerate() {
            if group::make_hint::<GAMMA2>(*a, *b) {
                h.set(i);
            }
        }
        h
    }

    /// FIPS 204 Algorithm 40 `UseHint` applied coefficient wise
    pub(super) fn use_hint<const GAMMA2: u32>(&self, h: &Hint) -> Poly {
        Poly(core::array::from_fn(|i| {
            group::use_hint::<GAMMA2>(h.get(i), self.0[i])
        }))
    }

    /// FIPS 204 Algorithm 16 `SimpleBitPack`, on coefficients that are already
    /// plain integers below `2^BITS`
    pub(super) fn simple_pack<const BITS: usize>(&self, out: &mut [u8]) {
        pack::<BITS>(&self.0, out)
    }

    /// FIPS 204 Algorithm 18 `SimpleBitUnpack`
    pub(super) fn simple_unpack<const BITS: usize>(input: &[u8]) -> Self {
        Poly(unpack::<BITS>(input))
    }

    /// FIPS 204 Algorithm 17 `BitPack`: serialise the signed representatives,
    /// each offset by `b` so that the whole range `-a..=b` becomes unsigned
    pub(super) fn signed_pack<const BITS: usize>(&self, b: i32, out: &mut [u8]) {
        let mut t = [0u32; N];
        for (o, c) in t.iter_mut().zip(self.0.iter()) {
            *o = (b - center(*c)) as u32;
        }
        pack::<BITS>(&t, out)
    }

    /// FIPS 204 Algorithm 19 `BitUnpack`, the inverse of [`Poly::signed_pack`]
    pub(super) fn signed_unpack<const BITS: usize>(input: &[u8], b: i32) -> Self {
        let mut f = unpack::<BITS>(input);
        for c in f.iter_mut() {
            *c = from_centered(b - (*c as i32));
        }
        Poly(f)
    }
}

/// Concatenate the 256 coefficients as `BITS` bits little endian integers
///
/// The accumulator never holds more than `7 + BITS` bits, which the widest
/// encoding of any parameter set keeps well inside a `u32`.
fn pack<const BITS: usize>(f: &[u32; N], out: &mut [u8]) {
    assert_eq!(out.len(), 32 * BITS);
    // a coefficient wider than its encoding would silently corrupt the next
    // one; every caller is bounded by the parameter set it comes from
    debug_assert!(f.iter().all(|c| c >> BITS == 0));
    let mut acc = 0u32;
    let mut bits = 0;
    let mut o = out.iter_mut();
    for c in f.iter() {
        acc |= *c << bits;
        bits += BITS;
        while bits >= 8 {
            *o.next().unwrap() = acc as u8;
            acc >>= 8;
            bits -= 8;
        }
    }
}

/// Split `32 * BITS` bytes back into 256 `BITS` bits little endian integers
fn unpack<const BITS: usize>(input: &[u8]) -> [u32; N] {
    assert_eq!(input.len(), 32 * BITS);
    let mut f = [0u32; N];
    let mut acc = 0u32;
    let mut bits = 0;
    let mut i = input.iter();
    for c in f.iter_mut() {
        while bits < BITS {
            acc |= (*i.next().unwrap() as u32) << bits;
            bits += 8;
        }
        *c = acc & ((1 << BITS) - 1);
        acc >>= BITS;
        bits -= BITS;
    }
    f
}

/// FIPS 204 Algorithm 30 `RejNTTPoly`, seeded the way `ExpandA` (Algorithm 32)
/// asks for the entry at row `r` and column `s` of the matrix
///
/// The rejection sampling loop makes the running time depend on the public
/// seed rho and on the matrix position, both of which are public.
pub(super) fn rej_ntt_poly(rho: &[u8; 32], s: u8, r: u8) -> Poly {
    let mut xof = Shake128::new().update(rho).update(&[s, r]).finalize_xof();
    // squeeze whole blocks, each holding a round number of 3 bytes groups
    let mut buf = [0u8; Shake128::BLOCK_BYTES];

    let mut f = [0u32; N];
    let mut j = 0;
    'outer: loop {
        xof.fill(&mut buf);
        for c in buf.chunks_exact(3) {
            // CoefFromThreeBytes (Algorithm 14): a 23 bits value, kept only if
            // it is a canonical residue
            let z = (c[0] as u32) | ((c[1] as u32) << 8) | (((c[2] & 0x7f) as u32) << 16);
            if z < Q {
                f[j] = z;
                j += 1;
                if j == N {
                    break 'outer;
                }
            }
        }
    }
    Poly(f)
}

/// FIPS 204 Algorithm 15 `CoefFromHalfByte`
///
/// Only the `eta` of 2 and 4 that the standard defines are handled; any other
/// value would reject every half byte and loop forever, which the parameter
/// set definitions assert against.
const fn coef_from_half_byte<const ETA: u32>(b: u8) -> Option<Zq> {
    if ETA == 2 && b < 15 {
        // the 15 accepted half bytes cover -2..=2 three times each
        Some(from_centered(2 - ((b % 5) as i32)))
    } else if ETA == 4 && b < 9 {
        Some(from_centered(4 - (b as i32)))
    } else {
        None
    }
}

/// FIPS 204 Algorithm 31 `RejBoundedPoly`, seeded the way `ExpandS`
/// (Algorithm 33) asks for the polynomial at index `nonce`
pub(super) fn rej_bounded_poly<const ETA: u32>(rho: &[u8; 64], nonce: u16) -> Poly {
    let mut xof = Shake256::new()
        .update(rho)
        .update(&nonce.to_le_bytes())
        .finalize_xof();
    let mut buf = [0u8; Shake256::BLOCK_BYTES];

    let mut f = [0u32; N];
    let mut j = 0;
    'outer: loop {
        xof.fill(&mut buf);
        for b in buf.iter() {
            // the low half byte first, then the high one
            for half in [*b & 0xf, *b >> 4] {
                if let Some(v) = coef_from_half_byte::<ETA>(half) {
                    f[j] = v;
                    j += 1;
                    if j == N {
                        break 'outer;
                    }
                }
            }
        }
    }
    Poly(f)
}

/// FIPS 204 Algorithm 29 `SampleInBall`: expand the commitment hash into a
/// polynomial with `TAU` coefficients of `+-1` and all the others zero
///
/// The rejection loop makes the running time depend on `c_tilde`, which is a
/// public part of the signature.
pub(super) fn sample_in_ball<const TAU: usize>(c_tilde: &[u8]) -> Poly {
    let mut xof = Shake256::new().update(c_tilde).finalize_xof();

    // the first 8 bytes of the stream hold the TAU signs, one bit each
    let mut signs = [0u8; 8];
    xof.fill(&mut signs);

    let mut buf = [0u8; Shake256::BLOCK_BYTES];
    let mut pos = buf.len(); // empty, so the first read squeezes a block

    let mut f = [0u32; N];
    for (bit, i) in (N - TAU..N).enumerate() {
        // draw byte sized positions until one falls inside 0..=i, then move the
        // coefficient it holds up to i and put the new +-1 in its place. Every
        // coefficient of the ball is placed exactly once this way.
        let j = loop {
            if pos == buf.len() {
                xof.fill(&mut buf);
                pos = 0;
            }
            let j = buf[pos] as usize;
            pos += 1;
            if j <= i {
                break j;
            }
        };
        f[i] = f[j];
        // BytesToBits reads the bits of a byte from the least significant one
        f[j] = if (signs[bit / 8] >> (bit % 8)) & 1 == 1 {
            Q - 1
        } else {
            1
        };
    }
    Poly(f)
}

/// FIPS 204 Algorithm 34 `ExpandMask`, for the single polynomial that `nonce`
/// selects out of the mask vector
pub(super) fn expand_mask_poly<const GAMMA1: u32, const GAMMA1_BITS: usize>(
    rho: &[u8; 64],
    nonce: u16,
) -> Poly {
    let mut buf = [0u8; 32 * MAX_GAMMA1_BITS];
    let buf = &mut buf[..32 * GAMMA1_BITS];
    Shake256::new()
        .update(rho)
        .update(&nonce.to_le_bytes())
        .finalize_at(buf);
    Poly::signed_unpack::<GAMMA1_BITS>(buf, GAMMA1 as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{GeneratorOf, GeneratorOf2, GeneratorRaw};

    fn next_poly(generator: &mut GeneratorRaw) -> Poly {
        let mut f = [0; N];
        for c in f.iter_mut() {
            *c = group::reduce(generator.next_u64());
        }
        Poly(f)
    }

    /// Negacyclic convolution done the naive way, as a reference for the NTT
    fn schoolbook(a: &Poly, b: &Poly) -> Poly {
        let mut r = [0 as Zq; N];
        for i in 0..N {
            for j in 0..N {
                let p = mul(a.0[i], b.0[j]);
                // X^256 = -1
                if i + j < N {
                    r[i + j] = add(r[i + j], p);
                } else {
                    r[i + j - N] = sub(r[i + j - N], p);
                }
            }
        }
        Poly(r)
    }

    #[test]
    fn ntt_roundtrip() {
        for p in GeneratorOf::new(0, 8, next_poly) {
            let mut q = p;
            q.ntt();
            q.inv_ntt();
            assert_eq!(p.0, q.0);
        }
    }

    #[test]
    fn ntt_multiplication() {
        for (a, b) in GeneratorOf2::new(0, 8, next_poly) {
            let (mut na, mut nb) = (a, b);
            na.ntt();
            nb.ntt();
            let mut prod = Poly::ZERO;
            prod.mul_acc(&na, &nb);
            prod.inv_ntt();

            assert_eq!(prod.0, schoolbook(&a, &b).0);
        }
    }

    #[test]
    fn encoding_roundtrip() {
        // the plain encoding of t1 and of w1 holds BITS bits values as they are
        fn simple<const BITS: usize>(p: &Poly) {
            let mut p = *p;
            for c in p.0.iter_mut() {
                *c &= (1 << BITS) - 1;
            }
            let mut bytes = vec![0u8; 32 * BITS];
            p.simple_pack::<BITS>(&mut bytes);
            assert_eq!(Poly::simple_unpack::<BITS>(&bytes).0, p.0);
        }

        // the signed encoding of s1, s2, t0 and z covers b - (2^BITS - 1) ..= b
        fn signed<const BITS: usize>(p: &Poly, b: i32) {
            let mut p = *p;
            for c in p.0.iter_mut() {
                *c = from_centered(b - ((*c & ((1 << BITS) - 1)) as i32));
            }
            let mut bytes = vec![0u8; 32 * BITS];
            p.signed_pack::<BITS>(b, &mut bytes);
            assert_eq!(Poly::signed_unpack::<BITS>(&bytes, b).0, p.0);
        }

        for p in GeneratorOf::new(0, 4, next_poly) {
            // w1 of the two gamma2, and t1
            simple::<4>(&p);
            simple::<6>(&p);
            simple::<10>(&p);
            // s1 and s2 of the two eta, t0, and z of the two gamma1
            signed::<3>(&p, 2);
            signed::<4>(&p, 4);
            signed::<13>(&p, 1 << (D - 1));
            signed::<18>(&p, 1 << 17);
            signed::<20>(&p, 1 << 19);
        }
    }

    #[test]
    fn sample_in_ball_is_a_ball() {
        // whatever the seed, the result must hold exactly TAU coefficients and
        // every one of them must be +-1
        fn check<const TAU: usize>(seed: &[u8]) {
            let p = sample_in_ball::<TAU>(seed);
            let mut ones = 0;
            for c in p.0.iter() {
                if *c != 0 {
                    assert!(*c == 1 || *c == Q - 1, "coefficient {} is not +-1", c);
                    ones += 1;
                }
            }
            assert_eq!(ones, TAU);
        }

        let mut generator = GeneratorRaw::new(4);
        for _ in 0..4 {
            let seed = generator.bytes::<64>();
            // the lambda / 4 bytes of each parameter set
            check::<39>(&seed[..32]);
            check::<49>(&seed[..48]);
            check::<60>(&seed);
        }
    }

    #[test]
    fn rej_bounded_stays_in_range() {
        let mut generator = GeneratorRaw::new(5);
        for i in 0..4u16 {
            let rho = generator.bytes::<64>();
            assert!(rej_bounded_poly::<2>(&rho, i)
                .0
                .iter()
                .all(|c| group::norm(*c) <= 2));
            assert!(rej_bounded_poly::<4>(&rho, i)
                .0
                .iter()
                .all(|c| group::norm(*c) <= 4));
        }
    }

    #[test]
    fn rej_ntt_is_canonical() {
        // all coefficients must be canonical, and a full polynomial must be
        // produced whatever the seed
        let mut generator = GeneratorRaw::new(6);
        for _ in 0..4 {
            let rho = generator.bytes::<32>();
            let [s, r] = generator.bytes::<2>();
            let p = rej_ntt_poly(&rho, s, r);
            assert!(p.0.iter().all(|c| *c < Q));
            assert!(p.0.iter().any(|c| *c != 0));
        }
    }

    #[test]
    fn expand_mask_stays_in_range() {
        let mut generator = GeneratorRaw::new(7);
        for i in 0..4u16 {
            let rho = generator.bytes::<64>();
            let p = expand_mask_poly::<131072, 18>(&rho, i);
            assert!(p.0.iter().all(|c| group::norm(*c) <= 131072));
            let p = expand_mask_poly::<524288, 20>(&rho, i);
            assert!(p.0.iter().all(|c| group::norm(*c) <= 524288));
        }
    }

    #[test]
    fn hint_bits() {
        let mut h = Hint::ZERO;
        assert_eq!(h.count(), 0);
        for i in [0, 1, 7, 8, 100, 255] {
            assert!(!h.get(i));
            h.set(i);
            assert!(h.get(i));
        }
        assert_eq!(h.count(), 6);
        // setting a bit twice does not count it twice
        h.set(100);
        assert_eq!(h.count(), 6);
    }
}
