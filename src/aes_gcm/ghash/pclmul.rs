//! GHASH using the x86 PCLMULQDQ instruction.
//!
//! The GF(2^128) multiplication is built with carry less multiply of `pclmulqdq` (64x64 -> 128-bit)
//! available under the `pclmulqdq` x86 target feature.
//!
//! `pclmulqdq` multiplies in the plain little-endian polynomial order, where
//! the bit at position `p` of a register is the coefficient of `x^p`, while GCM
//! numbers the bits of a block from the left. Reversing the bits within each
//! byte (and leaving the byte order alone) maps one to the other, which also
//! makes the reducing polynomial small: below `x^128` it is just
//! `x^7 + x^2 + x + 1`.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// Number of blocks multiplied per reduction, and hence the number of
/// precomputed powers of H.
///
/// Set similarly to the aarch64 backend
const WIDE: usize = 8;

/// Low half of the GCM reducing polynomial x^128 + x^7 + x^2 + x + 1.
///
/// In the normalized bit order of this module the part below
/// x^128 is simply the constant `x^7 + x^2 + x + 1` = 0x87 = 0b1000_0111.
const R: u64 = 0b1000_0111;

/// Reverse the bits of every byte of `v`.
///
/// The GCM bit order puts the coefficient of x^0 in the most significant bit
/// of the first byte, whereas a little-endian register has it in bit 0 of the
/// first byte once every byte is bit-reversed. `pshufb` doubles as a 16-entry
/// lookup table, so the two nibbles are reversed separately and put back
/// together.
#[inline]
unsafe fn bitrev_bytes(v: __m128i) -> __m128i {
    // table[i] = reverse of the 4 bits of i
    let table = _mm_setr_epi8(
        0x0, 0x8, 0x4, 0xc, 0x2, 0xa, 0x6, 0xe, 0x1, 0x9, 0x5, 0xd, 0x3, 0xb, 0x7, 0xf,
    );
    let nibbles = _mm_set1_epi8(0x0f);
    let lo = _mm_and_si128(v, nibbles);
    let hi = _mm_and_si128(_mm_srli_epi16(v, 4), nibbles);
    let rev_lo = _mm_shuffle_epi8(table, lo);
    let rev_hi = _mm_shuffle_epi8(table, hi);
    _mm_or_si128(_mm_slli_epi16(rev_lo, 4), rev_hi)
}

/// Load a block and normalize it to the polynomial bit order.
///
/// `block` must be exactly one block long.
#[inline]
unsafe fn load(block: &[u8]) -> __m128i {
    debug_assert_eq!(block.len(), 16);
    bitrev_bytes(_mm_loadu_si128(block.as_ptr().cast()))
}

/// Convert a normalized element back to its 16-byte GCM representation.
#[inline]
unsafe fn store(v: __m128i) -> [u8; 16] {
    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr().cast(), bitrev_bytes(v));
    out
}

/// Exchange the two 64-bit halves of a vector.
#[inline]
unsafe fn swap64(a: __m128i) -> __m128i {
    _mm_shuffle_epi32(a, 0b01_00_11_10)
}

/// Carry-less multiply of the low halves of `a` and `b`.
#[inline]
unsafe fn clmul_low(a: __m128i, b: __m128i) -> __m128i {
    _mm_clmulepi64_si128(a, b, 0x00)
}

/// Carry-less multiply of the high halves of `a` and `b`.
#[inline]
unsafe fn clmul_high(a: __m128i, b: __m128i) -> __m128i {
    _mm_clmulepi64_si128(a, b, 0x11)
}

/// Unreduced 256-bit carry-less product, as three 128-bit partial sums.
///
/// The product is `lo + mid * x^64 + hi * x^128`. Keeping it in this split form
/// lets several products be accumulated with plain XORs before a single
/// reduction.
struct Product {
    lo: __m128i,
    mid: __m128i,
    hi: __m128i,
}

impl Product {
    /// Add another unreduced product (XOR, addition in GF(2)).
    #[inline]
    unsafe fn add(&mut self, other: &Product) {
        self.lo = _mm_xor_si128(self.lo, other.lo);
        self.mid = _mm_xor_si128(self.mid, other.mid);
        self.hi = _mm_xor_si128(self.hi, other.hi);
    }
}

/// Carry-less 128x128 -> 256-bit multiply, `b_swapped` being `swap64(b)`.
#[inline]
unsafe fn clmul128(a: __m128i, b: __m128i, b_swapped: __m128i) -> Product {
    // lo  = a_lo * b_lo
    // mid = a_lo * b_hi + a_hi * b_lo
    // hi  = a_hi * b_hi
    let lo = clmul_low(a, b);
    let mid = _mm_xor_si128(clmul_low(a, b_swapped), clmul_high(a, b_swapped));
    let hi = clmul_high(a, b);
    Product { lo, mid, hi }
}

/// Reduce an unreduced 256-bit product modulo x^128 + x^7 + x^2 + x + 1.
///
/// Writing the product as `[h1:h0:l1:l0]` in 64-bit words, the two high words
/// are folded back down using x^128 = R and x^192 = x^64 * R. `h1 * R` reaches
/// degree 70, so shifting it up by 64 bits overflows x^128 by 7 bits, which
/// need one final (tiny) fold of their own.
#[inline]
unsafe fn reduce(p: &Product) -> __m128i {
    // Fold the middle partial product into the 256-bit value [hi:lo].
    let lo = _mm_xor_si128(p.lo, _mm_slli_si128(p.mid, 8));
    let hi = _mm_xor_si128(p.hi, _mm_srli_si128(p.mid, 8));

    // R in both halves, so that it can be the operand of a low or a high
    // carry-less multiply alike.
    let rv = _mm_set1_epi64x(R as i64);
    // h0 * x^128 = h0 * R, of degree at most 70: no overflow.
    let a = clmul_low(hi, rv);
    // h1 * x^192 = (h1 * R) * x^64, the shift dropping the 7 top bits of h1 * R.
    let b = clmul_high(hi, rv);
    // Those dropped bits stand for b_high * x^128 = b_high * R, of degree at
    // most 13.
    let c = clmul_high(b, rv);

    _mm_xor_si128(_mm_xor_si128(lo, a), _mm_xor_si128(_mm_slli_si128(b, 8), c))
}

/// Multiply two normalized field elements.
#[inline]
unsafe fn gmul(a: __m128i, b: __m128i) -> __m128i {
    reduce(&clmul128(a, b, swap64(b)))
}

/// GHASH hash key: the powers of H needed by the aggregated reduction.
#[derive(Clone)]
pub(super) struct Key {
    /// powers of H
    powers: [__m128i; WIDE],
    /// same as powers but with the two halves exchanged
    swapped: [__m128i; WIDE],
}

impl Key {
    /// Precompute H^1 .. H^WIDE from the 16-byte hash key H.
    pub(super) fn new(h: &[u8; 16]) -> Self {
        let h1 = unsafe { load(h) };
        let mut powers = [h1; WIDE];
        for i in (0..WIDE - 1).rev() {
            powers[i] = unsafe { gmul(powers[i + 1], h1) };
        }
        let swapped = core::array::from_fn(|i| unsafe { swap64(powers[i]) });
        Key { powers, swapped }
    }
}

/// GHASH accumulator X_i, held in normalized bit order.
#[derive(Clone, Copy)]
pub(super) struct State {
    x: __m128i,
}

impl State {
    /// The initial GHASH state X_0 = 0.
    pub(super) fn zero() -> Self {
        State {
            x: unsafe { _mm_setzero_si128() },
        }
    }

    /// Absorb complete blocks: `state = (state XOR block) * H` for each block.
    ///
    /// `blocks` length must be a multiple of 16.
    pub(super) fn update(&mut self, key: &Key, blocks: &[u8]) {
        debug_assert_eq!(blocks.len() % 16, 0);
        unsafe {
            let mut groups = blocks.chunks_exact(16 * WIDE);
            for group in &mut groups {
                self.x = absorb(self.x, key, group, 0);
            }
            // 1 to WIDE-1 blocks may be left: absorb them with the matching
            // tail of the powers, so they also cost a single reduction.
            let remainder = groups.remainder();
            if !remainder.is_empty() {
                self.x = absorb(self.x, key, remainder, WIDE - remainder.len() / 16);
            }
        }
    }

    /// Serialize the accumulator to its 16-byte big-endian representation.
    pub(super) fn to_bytes(&self) -> [u8; 16] {
        unsafe { store(self.x) }
    }
}

/// Absorb 1 to [`WIDE`] blocks with a single reduction.
///
/// The blocks are multiplied by `key.powers[first..]`, so `first` must be
/// `WIDE - blocks.len() / 16`: the last block gets H^1, the one before it H^2,
/// and so on, which is Horner's rule evaluated in one pass.
#[inline]
unsafe fn absorb(x: __m128i, key: &Key, blocks: &[u8], first: usize) -> __m128i {
    debug_assert_eq!(blocks.len() % 16, 0);
    debug_assert_eq!(first + blocks.len() / 16, WIDE);

    let powers = &key.powers[first..];
    let swapped = &key.swapped[first..];

    let mut blocks = blocks.chunks_exact(16);
    // The running state only enters through the first block.
    let head = blocks.next().unwrap();
    let mut acc = clmul128(_mm_xor_si128(load(head), x), powers[0], swapped[0]);
    for (block, (&p, &ps)) in blocks.zip(powers[1..].iter().zip(&swapped[1..])) {
        acc.add(&clmul128(load(block), p, ps));
    }
    reduce(&acc)
}
