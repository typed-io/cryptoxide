//! Arithmetic in the ML-KEM base field `Z_q`, with `q = 3329`
//!
//! Every value is kept as its canonical representative in `0..Q`, which makes
//! all the operations here total: no coefficient bound has to be tracked by the
//! callers, at the cost of one branch free conditional correction per
//! operation. Nothing takes a data dependent branch or memory access.

/// The ML-KEM prime modulus
pub(super) const Q: u16 = 3329;

/// ML-KEM group element Z modulus q
pub type Zq = u16;

/// ML-KEM group element Z_2^D
///
/// D is assumed to be < 16
pub type Z2d = u16;

const QU: u32 = Q as u32;

/// `floor(2^32 / Q)`, the Barrett reduction multiplier
const BARRETT: u64 = 1290167;

/// Euclidean division by `Q`: returns `(v / Q, v % Q)`
///
/// `(v * BARRETT) >> 32` never exceeds `v / Q` and, for any `u32` `v`,
/// underestimates it by at most 1, so a single correction step suffices.
const fn divrem(v: u32) -> (u32, Zq) {
    let quot = ((v as u64 * BARRETT) >> 32) as u32;
    let rem = v - quot * QU; // in 0..2Q
    let t = rem.wrapping_sub(QU); // wraps around iff rem < Q
    let under = ((t as i32) >> 31) as u32; // all ones iff rem < Q
    (quot + (1 & !under), t.wrapping_add(under & QU) as u16)
}

/// `v mod Q`
pub(super) const fn reduce(v: u32) -> Zq {
    divrem(v).1
}

/// `a + b mod Q`
pub(super) const fn add(a: Zq, b: Zq) -> Zq {
    let t = ((a as u32) + (b as u32)).wrapping_sub(QU);
    let under = ((t as i32) >> 31) as u32;
    t.wrapping_add(under & QU) as u16
}

/// `a - b mod Q`
pub(super) const fn sub(a: Zq, b: Zq) -> Zq {
    let t = (a as u32).wrapping_sub(b as u32);
    let under = ((t as i32) >> 31) as u32;
    t.wrapping_add(under & QU) as u16
}

/// `a * b mod Q`
pub(super) const fn mul(a: Zq, b: Zq) -> Zq {
    reduce((a as u32) * (b as u32))
}

/// FIPS 203 `Compress_d`: scale `x` from `0..Q` down to `D` bits
///
/// `round(2^D x / Q)` is computed as `floor((2^D x + Q/2) / Q)`; the truncated
/// half of `Q/2` cannot change the result as `2^D x + Q/2` is an integer and
/// the exact tie point never is. The result is reduced modulo `2^D` because
/// coefficients close to `Q` round up to `2^D`.
pub(super) const fn compress<const D: usize>(x: Zq) -> Z2d {
    let (quot, _) = divrem(((x as u32) << D) + QU / 2);
    (quot as u16) & ((1 << D) - 1)
}

/// FIPS 203 `Decompress_d`: scale a `D` bits value back up to `0..Q`
pub(super) const fn decompress<const D: usize>(y: u16) -> Z2d {
    (((y as u32) * QU + (1 << (D - 1))) >> D) as u16
}

/// `zeta`, a primitive 256-th root of unity in `Z_q`
const ZETA: Zq = 17;

const fn pow(base: Zq, exp: u32) -> Zq {
    let mut acc = 1;
    let mut b = base;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            acc = mul(acc, b);
        }
        b = mul(b, b);
        e >>= 1;
    }
    acc
}

/// FIPS 203 `BitRev7`: reverse the 7 low bits of `i`
const fn bitrev7(i: usize) -> u32 {
    let mut r = 0;
    let mut b = 0;
    while b < 7 {
        r |= (((i as u32) >> b) & 1) << (6 - b);
        b += 1;
    }
    r
}

/// `zeta^BitRev7(i)`, the twiddle factors of the NTT butterflies
pub(super) const ZETAS: [Zq; 128] = {
    // const array from_fn is not yet const stable, replace when stable by
    // core::array::from_fn(|i| pow(ZETA, bitrev7(i))
    let mut t = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        t[i] = pow(ZETA, bitrev7(i));
        i += 1;
    }
    t
};

/// `zeta^(2 BitRev7(i) + 1)`
///
/// `X^256 + 1` factors modulo `Q` into the 128 quadratics
/// `X^2 - zeta^(2 BitRev7(i) + 1)`; those are the moduli of the degree one
/// polynomials that the base case multiplication works on.
pub(super) const GAMMAS: [Zq; 128] = {
    // const array from_fn is not yet const stable, replace when stable by
    // core::array::from_fn(|i| pow(ZETA, 2 * bitrev7(i) + 1))
    let mut t = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        t[i] = pow(ZETA, 2 * bitrev7(i) + 1);
        i += 1;
    }
    t
};

/// `128^-1 mod Q`, the final scaling factor of the inverse NTT
pub(super) const INV128: Zq = 3303;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{GeneratorOf2, GeneratorRaw};

    fn next_element(gen: &mut GeneratorRaw) -> Zq {
        reduce(gen.next_u64() as u32)
    }

    #[test]
    fn divrem_matches_division() {
        fn check(v: u32) {
            assert_eq!(divrem(v), (v / QU, (v % QU) as Zq), "divrem({})", v);
        }

        // the boundaries, then arbitrary values over the whole u32 range that
        // `reduce` claims to accept
        for v in [0, 1, 2, QU - 1, QU, QU + 1, u32::MAX - 1, u32::MAX] {
            check(v);
        }
        let mut gen = GeneratorRaw::new(0);
        for _ in 0..100_000 {
            check(gen.next_u64() as u32);
            // and the sub-range that `mul` actually produces
            check(gen.next_u64() as u32 % (QU * QU));
        }
    }

    #[test]
    fn ops() {
        fn check(a: Zq, b: Zq) {
            let (x, y) = (a as u32, b as u32);
            assert_eq!(add(a, b) as u32, (x + y) % QU);
            assert_eq!(sub(a, b) as u32, (x + QU - y) % QU);
            assert_eq!(mul(a, b) as u32, (x * y) % QU);
        }

        for a in [0 as Zq, 1, 2, 1664, 1665, Q - 1] {
            for b in [0 as Zq, 1, 3, 1664, 1665, Q - 1] {
                check(a, b);
            }
        }
        for (a, b) in GeneratorOf2::new(0, 10_000, next_element) {
            check(a, b);
        }
    }

    #[test]
    fn roots_of_unity() {
        // zeta is of order 256, so zeta^128 = -1
        assert_eq!(pow(ZETA, 128), Q - 1);
        assert_eq!(pow(ZETA, 256), 1);
        assert_eq!(ZETAS[0], 1);
        assert_eq!(ZETAS[1], pow(ZETA, 64));
        assert_eq!(GAMMAS[0], ZETA);
        for i in 0..128 {
            assert_eq!(GAMMAS[i], mul(mul(ZETAS[i], ZETAS[i]), ZETA));
        }
        assert_eq!(mul(INV128, 128), 1);
    }

    #[test]
    fn compression_roundtrip() {
        // compressing then decompressing must stay within the error bound
        // ceil(q / 2^(d+1)) of FIPS 203 section 4.2.1
        fn check<const D: usize>() {
            let bound = (QU as i32 + (1 << D)) / (1 << (D + 1));
            for x in 0..Q {
                let y = compress::<D>(x);
                assert!(y < (1 << D), "compress::<{}>({}) = {}", D, x, y);
                let z = decompress::<D>(y);
                let mut e = (z as i32 - x as i32).abs();
                if e > QU as i32 / 2 {
                    e = QU as i32 - e; // the error wraps around modulo q
                }
                assert!(e <= bound, "compress::<{}>({}) error {}", D, x, e);
            }
            // decompression alone is injective and never leaves the field
            for y in 0..(1u16 << D) {
                assert!(decompress::<D>(y) < Q);
                assert_eq!(compress::<D>(decompress::<D>(y)), y);
            }
        }
        check::<1>();
        check::<4>();
        check::<5>();
        check::<10>();
        check::<11>();
    }
}
