//! Polynomials of `R_q = Z_q[X]/(X^256 + 1)`, along with the sampling and
//! serialisation routines that ML-KEM defines on them

use super::group::{self, add, mul, reduce, sub, Zq, GAMMAS, INV128, Q, ZETAS};
use crate::hashing::shake::Shake128;

/// Number of coefficients of a polynomial of `R_q`
const N: usize = 256;

/// Size in bytes of a polynomial encoded with 12 bits coefficients
pub(super) const ENCODED12: usize = 32 * 12;

/// A polynomial of `R_q`, or an element of `T_q` once transformed by [`Poly::ntt`]
///
/// In the second case the 256 coefficients are read as 128 degree one
/// polynomials, one per quadratic factor of `X^256 + 1`.
#[derive(Clone, Copy)]
pub(super) struct Poly([Zq; N]);

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

    /// FIPS 203 Algorithm 9 `NTT`: in place number theoretic transform
    ///
    /// Maps `R_q` to `T_q`, in which the multiplication of two polynomials
    /// becomes 128 independent multiplications of degree one polynomials.
    pub(super) fn ntt(&mut self) {
        let f = &mut self.0;
        let mut i = 1;
        let mut len = 128;
        while len >= 2 {
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

    /// FIPS 203 Algorithm 10 `NTT^-1`: in place inverse of [`Poly::ntt`]
    pub(super) fn inv_ntt(&mut self) {
        let f = &mut self.0;
        let mut i = 127;
        let mut len = 2;
        while len <= 128 {
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
            *c = mul(*c, INV128);
        }
    }

    /// FIPS 203 Algorithm 11 `MultiplyNTTs`: add the product of `a` and `b`,
    /// both in `T_q`, to `self`
    ///
    /// Accumulating rather than returning the product keeps the matrix by
    /// vector products of K-PKE down to a single temporary polynomial.
    pub(super) fn mul_acc(&mut self, a: &Poly, b: &Poly) {
        for (i, gamma) in GAMMAS.iter().enumerate() {
            let (a0, a1) = (a.0[2 * i], a.0[2 * i + 1]);
            let (b0, b1) = (b.0[2 * i], b.0[2 * i + 1]);
            // (a0 + a1 X) (b0 + b1 X) modulo X^2 - gamma
            let c0 = add(mul(a0, b0), mul(mul(a1, b1), *gamma));
            let c1 = add(mul(a0, b1), mul(a1, b0));
            self.0[2 * i] = add(self.0[2 * i], c0);
            self.0[2 * i + 1] = add(self.0[2 * i + 1], c1);
        }
    }

    /// FIPS 203 Algorithm 5 `ByteEncode_d` on uncompressed coefficients
    pub(super) fn encode<const D: usize>(&self, out: &mut [u8]) {
        pack::<D>(&self.0, out)
    }

    /// FIPS 203 Algorithm 6 `ByteDecode_d` on uncompressed coefficients
    pub(super) fn decode<const D: usize>(input: &[u8]) -> Self {
        let mut f = unpack::<D>(input);
        // only the 12 bits encoding can hold values outside of the field, for
        // which the specification mandates a reduction modulo Q
        if D == 12 {
            for c in f.iter_mut() {
                *c = reduce(*c as u32);
            }
        }
        Poly(f)
    }

    /// Compress every coefficient to `D` bits then serialise, into `32 * D` bytes
    pub(super) fn compress_encode<const D: usize>(&self, out: &mut [u8]) {
        let mut t = [0u16; N];
        for (o, c) in t.iter_mut().zip(self.0.iter()) {
            *o = group::compress::<D>(*c);
        }
        pack::<D>(&t, out)
    }

    /// Inverse of [`Poly::compress_encode`], up to the compression error
    pub(super) fn decode_decompress<const D: usize>(input: &[u8]) -> Self {
        let mut f = unpack::<D>(input);
        for c in f.iter_mut() {
            *c = group::decompress::<D>(*c);
        }
        Poly(f)
    }
}

/// Concatenate the 256 coefficients as `D` bits little endian integers
fn pack<const D: usize>(f: &[u16; N], out: &mut [u8]) {
    assert_eq!(out.len(), 32 * D);
    let mut acc = 0u32;
    let mut bits = 0;
    let mut o = out.iter_mut();
    for c in f.iter() {
        acc |= (*c as u32) << bits;
        bits += D;
        while bits >= 8 {
            *o.next().unwrap() = acc as u8;
            acc >>= 8;
            bits -= 8;
        }
    }
}

/// Split `32 * D` bytes back into 256 `D` bits little endian integers
fn unpack<const D: usize>(input: &[u8]) -> [u16; N] {
    assert_eq!(input.len(), 32 * D);
    let mut f = [0u16; N];
    let mut acc = 0u32;
    let mut bits = 0;
    let mut i = input.iter();
    for c in f.iter_mut() {
        while bits < D {
            acc |= (*i.next().unwrap() as u32) << bits;
            bits += 8;
        }
        *c = (acc as u16) & ((1 << D) - 1);
        acc >>= D;
        bits -= D;
    }
    f
}

/// FIPS 203 Algorithm 7 `SampleNTT`: expand a public seed into a uniformly
/// distributed element of `T_q`
///
/// The rejection sampling loop makes the running time depend on the public seed rho
/// of the encapsulation key + matrix position.
pub(super) fn sample_ntt(rho: &[u8; 32], b0: u8, b1: u8) -> Poly {
    let mut xof = Shake128::new().update(rho).update(&[b0, b1]).finalize_xof();
    // squeeze whole blocks, each holding a round number of 3 bytes groups
    let mut buf = [0u8; Shake128::BLOCK_BYTES];

    let mut f = [0u16; N];
    let mut j = 0;
    'outer: loop {
        xof.fill(&mut buf);
        for c in buf.chunks_exact(3) {
            // two 12 bits values per 3 bytes group, each kept only if it is a
            // canonical residue
            let d0 = (c[0] as u16) | ((c[1] as u16 & 0xf) << 8);
            let d1 = ((c[1] as u16) >> 4) | ((c[2] as u16) << 4);
            if d0 < Q {
                f[j] = d0;
                j += 1;
                if j == N {
                    break 'outer;
                }
            }
            if d1 < Q {
                f[j] = d1;
                j += 1;
                if j == N {
                    break 'outer;
                }
            }
        }
    }
    Poly(f)
}

/// FIPS 203 Algorithm 8 `SamplePolyCBD_eta`: sample a polynomial whose
/// coefficients follow a centered binomial distribution
///
/// `input` is `64 * ETA` bytes of pseudo random data, `2 * ETA` bits per
/// coefficient.
pub(super) fn sample_cbd<const ETA: usize>(input: &[u8]) -> Poly {
    assert_eq!(input.len(), 64 * ETA);
    let mut f = [0u16; N];
    let mut acc = 0u32;
    let mut bits = 0;
    let mut i = input.iter();
    for c in f.iter_mut() {
        while bits < 2 * ETA {
            acc |= (*i.next().unwrap() as u32) << bits;
            bits += 8;
        }
        let sample = acc & ((1 << (2 * ETA)) - 1);
        acc >>= 2 * ETA;
        bits -= 2 * ETA;
        // difference of the hamming weights of the two halves, in -ETA..=ETA
        let x = (sample & ((1 << ETA) - 1)).count_ones() as u16;
        let y = (sample >> ETA).count_ones() as u16;
        *c = sub(x, y);
    }
    Poly(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{GeneratorOf, GeneratorOf2, GeneratorRaw};

    fn next_poly(gen: &mut GeneratorRaw) -> Poly {
        let mut f = [0; N];
        for c in f.iter_mut() {
            *c = reduce(gen.next_u64() as u32);
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
        fn check<const D: usize>(p: &Poly) {
            // an encoding of D bits can only represent D bits values
            let mut p = *p;
            for c in p.0.iter_mut() {
                *c &= (1 << D) - 1;
            }
            let mut bytes = vec![0u8; 32 * D];
            p.encode::<D>(&mut bytes);
            assert_eq!(Poly::decode::<D>(&bytes).0, p.0);
        }

        for p in GeneratorOf::new(0, 4, next_poly) {
            check::<1>(&p);
            check::<4>(&p);
            check::<5>(&p);
            check::<10>(&p);
            check::<11>(&p);

            // the 12 bits encoding covers the whole field
            let mut bytes = [0u8; ENCODED12];
            p.encode::<12>(&mut bytes);
            assert_eq!(Poly::decode::<12>(&bytes).0, p.0);
        }
    }

    #[test]
    fn cbd_distribution() {
        // eta = 2 over 4 zero bits per coefficient gives 0, over 4 set bits it
        // gives 2 - 2 = 0, and the intermediate patterns cover -2..=2
        assert!(sample_cbd::<2>(&[0u8; 128]).0.iter().all(|c| *c == 0));
        assert!(sample_cbd::<2>(&[0xffu8; 128]).0.iter().all(|c| *c == 0));
        // 0b0001: x = 1, y = 0
        assert_eq!(sample_cbd::<2>(&[0x11u8; 128]).0[0], 1);
        // 0b1000: x = 0, y = 1
        assert_eq!(sample_cbd::<2>(&[0x88u8; 128]).0[0], Q - 1);
        // eta = 3 reads 6 bits per coefficient: 0b000011 gives x = 2, y = 0
        let input = [0x03u8, 0x00, 0x00].repeat(64);
        assert_eq!(sample_cbd::<3>(&input).0[0], 2);
    }

    #[test]
    fn sample_ntt_is_canonical() {
        // all coefficients must be canonical, and a full polynomial must be
        // produced whatever the seed
        let mut gen = GeneratorRaw::new(0);
        for _ in 0..4 {
            let [b0, b1] = gen.bytes::<2>();
            let p = sample_ntt(&gen.bytes(), b0, b1);
            assert!(p.0.iter().all(|c| *c < Q));
            assert!(p.0.iter().any(|c| *c != 0));
        }
    }
}
