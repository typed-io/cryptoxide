//! Arithmetic in the ML-DSA base field `Z_q`, with `q = 8380417`

/// The ML-DSA prime modulus, `2^23 - 2^13 + 1`
pub(super) const Q: u32 = 8380417;

/// Number of low order bits of a public key coefficient that [`power2round`]
/// drops, the `d` of FIPS 204
pub(super) const D: usize = 13;

/// ML-DSA group element: an element of `Z_q`, held as its representative in `0..Q`
pub(super) type Zq = u32;

/// `(Q - 1) / 2`, the largest `mod±` representative
const HALF_Q: u32 = (Q - 1) / 2;

const QU: u64 = Q as u64;

/// `floor(2^64 / Q)`, the Barrett reduction multiplier
const BARRETT: u128 = (1u128 << 64) / (Q as u128);

/// Euclidean division by `Q`: returns `(v / Q, v % Q)`
///
/// `(v * BARRETT) >> 64` never exceeds `v / Q` and, for any `u64` `v`,
/// underestimates it by at most 1, so a single correction step suffices.
const fn divrem(v: u64) -> (u64, Zq) {
    let quot = (((v as u128) * BARRETT) >> 64) as u64;
    let rem = v - quot * QU; // in 0..2Q
    let t = rem.wrapping_sub(QU); // wraps around iff rem < Q
    let under = ((t as i64) >> 63) as u64; // all ones iff rem < Q
    (quot + (1 & !under), t.wrapping_add(under & QU) as u32)
}

/// `v mod Q`
pub(super) const fn reduce(v: u64) -> Zq {
    divrem(v).1
}

/// `a + b mod Q`
pub(super) const fn add(a: Zq, b: Zq) -> Zq {
    let t = (a + b).wrapping_sub(Q);
    let under = ((t as i32) >> 31) as u32;
    t.wrapping_add(under & Q)
}

/// `a - b mod Q`
pub(super) const fn sub(a: Zq, b: Zq) -> Zq {
    let t = a.wrapping_sub(b);
    let under = ((t as i32) >> 31) as u32;
    t.wrapping_add(under & Q)
}

/// `a * b mod Q`
pub(super) const fn mul(a: Zq, b: Zq) -> Zq {
    reduce((a as u64) * (b as u64))
}

/// The `mod±` representative of `a`, in `-(Q-1)/2 ..= (Q-1)/2`
///
/// This is the signed integer that FIPS 204 means whenever it writes `w mod± q`,
/// and in particular the value whose magnitude the infinity norm measures.
pub(super) const fn center(a: Zq) -> i32 {
    let over = (HALF_Q < a) as u32; // 1 iff a stands for a - Q
    (a as i32).wrapping_sub((over * Q) as i32)
}

/// The canonical representative of `v`, for any `v` in `-Q < v < Q`
pub(super) const fn from_centered(v: i32) -> Zq {
    let under = (v >> 31) as u32; // all ones iff v < 0
    (v as u32).wrapping_add(under & Q)
}

/// `|a mod± q|`, the contribution of one coefficient to an infinity norm
pub(super) const fn norm(a: Zq) -> u32 {
    center(a).unsigned_abs()
}

/// FIPS 204 Algorithm 35 `Power2Round`: split `r` into `(r1, r0)` with
/// `r = r1 2^D + r0` and `r0` the `mod± 2^D` representative
///
/// `r1` lands in `0..2^(bitlen(Q-1) - D)`, ie. it always fits the 10 bits that
/// the public key encoding gives it.
pub(super) const fn power2round(r: Zq) -> (Zq, Zq) {
    let low = r & ((1 << D) - 1);
    // mod±: a low half above 2^(D-1) belongs to the next multiple of 2^D
    let up = (low > (1 << (D - 1))) as u32;
    let r1 = (r >> D) + up;
    let r0 = (low as i32) - ((up << D) as i32);
    (r1, from_centered(r0))
}

/// FIPS 204 Algorithm 36 `Decompose`: split `r` into a high part `r1` and the
/// `mod± 2 GAMMA2` low part `r0`
///
/// `r1` is returned as a plain integer in `0..(Q-1)/(2 GAMMA2)` rather than as
/// a field element, since that is the range `w1Encode` gives it, and `r0` as
/// its signed representative in `-GAMMA2 ..= GAMMA2`.
pub(super) const fn decompose<const GAMMA2: u32>(r: Zq) -> (u32, i32) {
    let two = 2 * GAMMA2;
    let (quot, rem) = (r / two, r % two);
    // mod±: a remainder above GAMMA2 belongs to the next interval
    let up = (rem > GAMMA2) as u32;
    let r1 = quot + up;
    let r0 = (rem as i32) - ((up * two) as i32);
    // the interval just below Q is a short one, and would give r1 a value that
    // no longer fits the bits w1Encode reserves for it; the specification folds
    // it back onto the interval of zero, borrowing one from the low part.
    let last = (r1 == (Q - 1) / two) as u32;
    (r1 * (1 - last), r0 - (last as i32))
}

/// FIPS 204 Algorithm 37 `HighBits`
pub(super) const fn high_bits<const GAMMA2: u32>(r: Zq) -> u32 {
    decompose::<GAMMA2>(r).0
}

/// FIPS 204 Algorithm 38 `LowBits`
pub(super) const fn low_bits<const GAMMA2: u32>(r: Zq) -> i32 {
    decompose::<GAMMA2>(r).1
}

/// FIPS 204 Algorithm 39 `MakeHint`, given `r` and `r + z` rather than `r` and `z`
///
/// The hint records whether adding `z` to `r` carried over into the high part,
/// which is the one bit of `r` that a verifier holding only `HighBits(r + z)`
/// cannot recover on its own.
pub(super) const fn make_hint<const GAMMA2: u32>(r: Zq, r_plus_z: Zq) -> bool {
    high_bits::<GAMMA2>(r) != high_bits::<GAMMA2>(r_plus_z)
}

/// FIPS 204 Algorithm 40 `UseHint`: recover `HighBits(r + z)` from `r` and the
/// hint bit that [`make_hint`] produced for it
pub(super) const fn use_hint<const GAMMA2: u32>(hint: bool, r: Zq) -> u32 {
    let m = (Q - 1) / (2 * GAMMA2);
    let (r1, r0) = decompose::<GAMMA2>(r);
    // a set hint moves the high part one interval up or down, depending on
    // which side of its interval the low part sits, and wraps around m
    let carried = (hint as u32).wrapping_neg(); // all ones iff the hint is set
    let up = ((r0 > 0) as u32).wrapping_neg(); // all ones iff moving up
    let moved = (r1 + (up & 1) + (!up & (m - 1))) % m;
    (r1 & !carried) | (moved & carried)
}

/// `zeta`, a primitive 512-th root of unity in `Z_q`
const ZETA: Zq = 1753;

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

/// FIPS 204 Algorithm 43 `BitRev8`: reverse the 8 low bits of `i`
const fn bitrev8(i: usize) -> u32 {
    let mut r = 0;
    let mut b = 0;
    while b < 8 {
        r |= (((i as u32) >> b) & 1) << (7 - b);
        b += 1;
    }
    r
}

/// `zeta^BitRev8(k)`, the twiddle factors of the NTT butterflies
///
/// `X^256 + 1` splits into 256 distinct linear factors modulo `Q`, so unlike
/// ML-KEM the transform goes all the way down and the pointwise product of two
/// transformed polynomials is a plain coefficient wise product. Index 0 is
/// never read by either transform.
pub(super) const ZETAS: [Zq; 256] = {
    // const array from_fn is not yet const stable, replace when stable by
    // core::array::from_fn(|i| pow(ZETA, bitrev8(i))
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = pow(ZETA, bitrev8(i));
        i += 1;
    }
    t
};

/// `256^-1 mod Q`, the final scaling factor of the inverse NTT
pub(super) const INV256: Zq = 8347681;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{GeneratorOf2, GeneratorRaw};

    fn next_element(generator: &mut GeneratorRaw) -> Zq {
        reduce(generator.next_u64())
    }

    #[test]
    fn divrem_matches_division() {
        fn check(v: u64) {
            assert_eq!(divrem(v), (v / QU, (v % QU) as Zq), "divrem({})", v);
        }

        // the boundaries, then arbitrary values over the whole u64 range that
        // `reduce` claims to accept
        for v in [0, 1, 2, QU - 1, QU, QU + 1, u64::MAX - 1, u64::MAX] {
            check(v);
        }
        let mut generator = GeneratorRaw::new(0);
        for _ in 0..100_000 {
            check(generator.next_u64());
            // and the sub-range that `mul` actually produces
            check(generator.next_u64() % (QU * QU));
        }
    }

    #[test]
    fn ops() {
        fn check(a: Zq, b: Zq) {
            let (x, y) = (a as u64, b as u64);
            assert_eq!(add(a, b) as u64, (x + y) % QU);
            assert_eq!(sub(a, b) as u64, (x + QU - y) % QU);
            assert_eq!(mul(a, b) as u64, (x * y) % QU);
        }

        for a in [0 as Zq, 1, 2, HALF_Q, HALF_Q + 1, Q - 1] {
            for b in [0 as Zq, 1, 3, HALF_Q, HALF_Q + 1, Q - 1] {
                check(a, b);
            }
        }
        for (a, b) in GeneratorOf2::new(0, 10_000, next_element) {
            check(a, b);
        }
    }

    #[test]
    fn centering_roundtrip() {
        // q is odd, so the mod± representatives are symmetric around zero and
        // the fold happens right above (q-1)/2
        assert_eq!(center(HALF_Q), HALF_Q as i32);
        assert_eq!(center(HALF_Q + 1), -(HALF_Q as i32));
        assert_eq!(center(Q - 1), -1);
        assert_eq!(center(0), 0);

        for (a, _) in GeneratorOf2::new(1, 10_000, next_element) {
            let c = center(a);
            assert!(c.unsigned_abs() <= HALF_Q, "center({}) = {}", a, c);
            assert_eq!(from_centered(c), a);
            assert_eq!(norm(a), c.unsigned_abs());
        }
    }

    #[test]
    fn roots_of_unity() {
        // zeta is of order 512, so zeta^256 = -1
        assert_eq!(pow(ZETA, 256), Q - 1);
        assert_eq!(pow(ZETA, 512), 1);
        assert_eq!(ZETAS[0], 1);
        assert_eq!(ZETAS[1], pow(ZETA, 128));
        assert_eq!(mul(INV256, 256), 1);

        // the 256 twiddle factors are the 256 distinct powers zeta^0..zeta^255,
        // permuted by the bit reversal
        let mut sorted = ZETAS;
        sorted.sort_unstable();
        for w in sorted.windows(2) {
            assert_ne!(w[0], w[1]);
            assert!(w[1] < Q);
        }
    }

    #[test]
    fn power2round_reconstructs() {
        // exhaustive: every element of the field goes through this in key
        // generation, and r1 has to fit the 10 bits the public key gives it
        for r in 0..Q {
            let (r1, r0) = power2round(r);
            let low = center(r0);
            assert!(r1 < 1 << (23 - D), "power2round({}).0 = {}", r, r1);
            assert!(
                low > -(1 << (D - 1)) && low <= 1 << (D - 1),
                "power2round({}).1 = {}",
                r,
                low
            );
            assert_eq!(add(mul(r1, 1 << D), r0), r, "power2round({})", r);
        }
    }

    #[test]
    fn decompose_reconstructs() {
        fn check<const GAMMA2: u32>(r: Zq) {
            let m = (Q - 1) / (2 * GAMMA2);
            let (r1, r0) = decompose::<GAMMA2>(r);
            assert!(r1 < m, "decompose::<{}>({}).0 = {}", GAMMA2, r, r1);
            assert!(
                r0.unsigned_abs() <= GAMMA2,
                "decompose::<{}>({}).1 = {}",
                GAMMA2,
                r,
                r0
            );
            assert_eq!(
                add(mul(r1, 2 * GAMMA2), from_centered(r0)),
                r,
                "decompose::<{}>({})",
                GAMMA2,
                r
            );
            assert_eq!(high_bits::<GAMMA2>(r), r1);
            assert_eq!(low_bits::<GAMMA2>(r), r0);
        }

        // the interval boundaries, where the folding of the short top interval
        // and the mod± rounding both happen
        for r in [0, 1, 95232, 95233, 190464, 261888, 261889, Q - 1, Q - 2] {
            check::<95232>(r);
            check::<261888>(r);
        }
        let mut generator = GeneratorRaw::new(2);
        for _ in 0..50_000 {
            let r = reduce(generator.next_u64());
            check::<95232>(r);
            check::<261888>(r);
        }
    }

    #[test]
    fn hints_recover_high_bits() {
        // FIPS 204 Lemma 1: as long as z is no larger than gamma2, that single
        // hint bit is all a verifier needs to recover the high bits of r + z
        // while holding only r
        fn check<const GAMMA2: u32>(r: Zq, z: i32) {
            let rz = add(r, from_centered(z));
            let hint = make_hint::<GAMMA2>(r, rz);
            assert_eq!(
                use_hint::<GAMMA2>(hint, r),
                high_bits::<GAMMA2>(rz),
                "gamma2 {} r {} z {}",
                GAMMA2,
                r,
                z
            );
        }

        fn sample<const GAMMA2: u32>(r: Zq, rand: u64) {
            let z = (rand % (2 * GAMMA2 as u64 + 1)) as i32 - GAMMA2 as i32;
            check::<GAMMA2>(r, z);
            // and the extremes of the range the lemma covers
            check::<GAMMA2>(r, 0);
            check::<GAMMA2>(r, GAMMA2 as i32);
            check::<GAMMA2>(r, -(GAMMA2 as i32));
        }

        let mut generator = GeneratorRaw::new(3);
        for _ in 0..20_000 {
            let r = reduce(generator.next_u64());
            let rand = generator.next_u64();
            sample::<95232>(r, rand);
            sample::<261888>(r, rand);
        }
    }
}
