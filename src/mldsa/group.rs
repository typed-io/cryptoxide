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
