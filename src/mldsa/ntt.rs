//! The number theoretic transform, in the signed Montgomery domain
//!
//! `T_q` is where every polynomial product of the scheme is computed, and it is
//! the one place where this module leaves behind the canonical representatives
//! that [`super::group`] keeps everywhere else. A coefficient here is a signed
//! integer, only loosely reduced, and a product of two of them comes back
//! carrying a factor `R^-1` with `R = 2^32`.
//!
//! What that buys is the multiplication. Reducing a canonical product needs a
//! division by `q`, which even as a Barrett multiplication costs a 64 by 64
//! bit product; the Montgomery reduction below is two 32 bit products and a
//! shift, and the additions and subtractions around it need no correction step
//! at all because the result is allowed to leave `0..q`. The transform runs
//! 1024 of those butterflies per polynomial, several times per signature.
//!
//! The price is that the ranges are no longer anybody's business but this
//! module's, so each function documents what it takes and what it gives back.

use super::group::{self, center, from_centered, Zq, INV256, Q, ZETAS};
use super::poly::N;

/// `q` as the signed integer the arithmetic here works with
const QI: i32 = Q as i32;

/// `x^-1 mod 2^32`, for any odd `x`
///
/// Newton iteration on `x_{n+1} = x_n (2 - q x_n)`: an odd `q` makes the
/// initial 1 correct to one bit, and each step doubles that.
const fn inv_mod_r(x: u32) -> u32 {
    let mut inv = 1u32;
    let mut correct = 1;
    while correct < 32 {
        inv = inv.wrapping_mul(2u32.wrapping_sub(x.wrapping_mul(inv)));
        correct *= 2;
    }
    inv
}

/// `q^-1 mod 2^32`, the multiplier that clears the low half of a product
const QINV: i32 = inv_mod_r(Q) as i32;

/// `R mod q`, the Montgomery representative of one
const MONT: Zq = group::reduce(1 << 32);

/// `R^2 / 256 mod q`
///
/// [`inv_ntt`] folds this into its final scaling: the `256^-1` is the one the
/// inverse transform owes, and the `R^2` puts back both the factor `R^-1` that
/// [`mul_acc`] left in its accumulator and the one this very multiplication
/// would otherwise take out.
const F: i32 = center(group::mul(group::mul(MONT, MONT), INV256));

/// Montgomery reduction: the `r` in `-q < r < q` with `r R = a mod q`
///
/// Valid for every `|a| < 2^31 q`, which is well above the largest product any
/// caller here forms.
const fn montgomery_reduce(a: i64) -> i32 {
    // t = a q^-1 mod 2^32, so that a - t q is a multiple of 2^32
    let t = (a as i32).wrapping_mul(QINV);
    ((a - (t as i64) * (QI as i64)) >> 32) as i32
}

/// `a b R^-1 mod q`, in `-q < r < q`
const fn mul(a: i32, b: i32) -> i32 {
    montgomery_reduce((a as i64) * (b as i64))
}

/// Barrett reduction: the `r` congruent to `a` with `|r| < q`
///
/// Valid for every `|a| < 2^31 - 2^22`.
const fn reduce(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    a - t * QI
}

/// `zeta^BitRev8(k) R mod q`, the twiddle factors as this module needs them
///
/// Carrying the `R` is what makes [`mul`] by one of these a plain
/// multiplication by `zeta`: the reduction takes the factor straight back out.
/// Index 0 is never read, by either transform.
const ZETAS_MONT: [i32; 256] = {
    let mut t = [0i32; 256];
    let mut i = 0;
    while i < 256 {
        // to the Montgomery domain, then to the representative of smallest
        // magnitude, which keeps the products well inside an i64
        t[i] = center(group::mul(ZETAS[i], MONT));
        i += 1;
    }
    t
};

/// FIPS 204 Algorithm 41 `NTT`, on coefficients of `|c| <= q`
///
/// Leaves `|c| < 9q`: each of the eight levels adds at most one `q`, and
/// nothing is reduced along the way.
pub(super) fn ntt(f: &mut [i32; N]) {
    let mut k = 1;
    let mut len = 128;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS_MONT[k];
            k += 1;
            for j in start..start + len {
                let t = mul(zeta, f[j + len]);
                f[j + len] = f[j] - t;
                f[j] = f[j] + t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// FIPS 204 Algorithm 42 `NTT^-1`, on an accumulator of pointwise products
///
/// Takes the `|c| < 2^31 - 2^22` that [`mul_acc`] can reach, and gives back
/// coefficients of `|c| < q`, with the factor `R^-1` of the products removed.
pub(super) fn inv_ntt(f: &mut [i32; N]) {
    // the levels below add without reducing, and would overflow on the widest
    // accumulator, so bring everything back under q first
    for c in f.iter_mut() {
        *c = reduce(*c);
    }

    let mut k = 255;
    let mut len = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS_MONT[k];
            k -= 1;
            for j in start..start + len {
                let t = f[j];
                f[j] = t + f[j + len];
                f[j + len] = mul(zeta, f[j + len] - t);
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    // one Montgomery multiplication each, so every coefficient comes out of it
    // reduced to |c| < q whatever the levels above left behind
    for c in f.iter_mut() {
        *c = mul(F, *c);
    }
}

/// FIPS 204 Algorithm 45 `MultiplyNTT`, accumulating into `acc`
///
/// Each product carries a factor `R^-1`, which [`inv_ntt`] takes back out.
/// Over the at most 8 rows of any parameter set the accumulator stays under
/// `8q`, far inside what [`inv_ntt`] accepts.
pub(super) fn mul_acc(acc: &mut [i32; N], a: &[i32; N], b: &[i32; N]) {
    for (s, (x, y)) in acc.iter_mut().zip(a.iter().zip(b.iter())) {
        *s += mul(*x, *y);
    }
}

/// The canonical representatives of coefficients of `|c| < q`
pub(super) fn canonical(f: &[i32; N]) -> [u32; N] {
    core::array::from_fn(|i| from_centered(f[i]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{GeneratorOf, GeneratorRaw};

    /// The widest `a` [`montgomery_reduce`] documents
    const MONT_BOUND: i64 = (1i64 << 31) * QI as i64;

    /// The widest `a` [`reduce`] documents
    const REDUCE_BOUND: i32 = i32::MAX - (1 << 22);

    /// Arbitrary `a` in `-MONT_BOUND ..= MONT_BOUND - 1`
    fn next_wide(generator: &mut GeneratorRaw) -> i64 {
        (generator.next_u64() % (2 * MONT_BOUND as u64)) as i64 - MONT_BOUND
    }

    /// Arbitrary `a` in `-REDUCE_BOUND ..= REDUCE_BOUND - 1`
    ///
    /// The span is a whole u32 and the centering has to happen before the
    /// value is narrowed, or the subtraction is the one that wraps.
    fn next_narrow(generator: &mut GeneratorRaw) -> i32 {
        let bound = REDUCE_BOUND as i64;
        ((generator.next_u64() % (2 * bound as u64)) as i64 - bound) as i32
    }

    /// `a` is congruent to `r R` modulo `q`
    fn is_montgomery_of(r: i32, a: i64) {
        let lhs = (r as i128) * (1i128 << 32);
        assert_eq!(
            lhs.rem_euclid(QI as i128),
            (a as i128).rem_euclid(QI as i128),
            "montgomery_reduce({}) = {}",
            a,
            r
        );
    }

    /// The derived constants must come out as the values FIPS 204 implementations
    /// publish for them
    #[test]
    fn constants() {
        assert_eq!(Q.wrapping_mul(QINV as u32), 1);
        assert_eq!(QINV, 58728449);
        assert_eq!(MONT, 4193792);
        assert_eq!(F, 41978);
    }

    #[test]
    fn montgomery_reduce_is_exact() {
        fn check(a: i64) {
            let r = montgomery_reduce(a);
            assert!(r > -QI && r < QI, "montgomery_reduce({}) = {}", a, r);
            is_montgomery_of(r, a);
        }

        // the whole documented range, then arbitrary values inside it
        for a in [
            0,
            1,
            -1,
            QI as i64,
            -(QI as i64),
            MONT_BOUND - 1,
            -MONT_BOUND,
        ] {
            check(a);
        }
        for a in GeneratorOf::new(20, 20_000, next_wide) {
            check(a);
        }
    }

    #[test]
    fn barrett_reduce_is_exact() {
        fn check(a: i32) {
            let r = reduce(a);
            assert!(r > -QI && r < QI, "reduce({}) = {}", a, r);
            assert_eq!(
                (r as i64).rem_euclid(QI as i64),
                (a as i64).rem_euclid(QI as i64),
                "reduce({})",
                a
            );
        }

        for a in [0, 1, -1, QI, -QI, REDUCE_BOUND, -REDUCE_BOUND] {
            check(a);
        }
        for a in GeneratorOf::new(21, 20_000, next_narrow) {
            check(a);
        }
    }

    /// The twiddles must be the Montgomery images of the canonical ones
    #[test]
    fn twiddles() {
        for (i, (m, c)) in ZETAS_MONT.iter().zip(ZETAS.iter()).enumerate() {
            assert_eq!(from_centered(*m), group::mul(*c, MONT), "zeta {}", i);
        }
    }
}
