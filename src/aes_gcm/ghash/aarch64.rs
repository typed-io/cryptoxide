//! GHASH using the ARMv8 Cryptography Extensions.
//!
//! The GF(2^128) multiplication is built out of `pmull`/`pmull2` (64x64 ->
//! 128-bit carry-less multiply), available under the `aes` aarch64 target
//! feature

use core::arch::aarch64::*;

/// Number of blocks multiplied per reduction, and hence the number of
/// precomputed powers of H.
///
/// 4 is a tradeoff between computing too much for small message and not enough
/// for large messages
const WIDE: usize = 4;

/// Low half of the GCM reducing polynomial x^128 + x^7 + x^2 + x + 1.
///
/// In the normalized bit order of this module the part below
/// x^128 is simply the constant `x^7 + x^2 + x + 1` = 0x87 = 0b1000_0111.
const R: u64 = 0b1000_0111;

/// Load a block and normalize it to the polynomial bit order.
///
/// `block` must be exactly one block long.
#[inline]
unsafe fn load(block: &[u8]) -> uint8x16_t {
    debug_assert_eq!(block.len(), 16);
    vrbitq_u8(vld1q_u8(block.as_ptr()))
}

/// Convert a normalized element back to its 16-byte GCM representation.
#[inline]
unsafe fn store(v: uint8x16_t) -> [u8; 16] {
    let mut out = [0u8; 16];
    vst1q_u8(out.as_mut_ptr(), vrbitq_u8(v));
    out
}

/// Exchange the two 64-bit halves of a vector.
#[inline]
unsafe fn swap64(a: uint8x16_t) -> uint8x16_t {
    vextq_u8(a, a, 8)
}

/// Carry-less multiply of the low halves of `a` and `b` (`pmull`).
#[inline]
unsafe fn clmul_low(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    vreinterpretq_u8_p128(vmull_p64(
        vgetq_lane_u64(vreinterpretq_u64_u8(a), 0),
        vgetq_lane_u64(vreinterpretq_u64_u8(b), 0),
    ))
}

/// Carry-less multiply of the high halves of `a` and `b` (`pmull2`).
#[inline]
unsafe fn clmul_high(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    vreinterpretq_u8_p128(vmull_high_p64(
        vreinterpretq_p64_u8(a),
        vreinterpretq_p64_u8(b),
    ))
}

/// Unreduced 256-bit carry-less product, as three 128-bit partial sums.
///
/// The product is `lo + mid * x^64 + hi * x^128`. Keeping it in this split form
/// lets several products be accumulated with plain XORs before a single
/// reduction.
struct Product {
    lo: uint8x16_t,
    mid: uint8x16_t,
    hi: uint8x16_t,
}

impl Product {
    /// Add another unreduced product (XOR, addition in GF(2)).
    #[inline]
    unsafe fn add(&mut self, other: &Product) {
        self.lo = veorq_u8(self.lo, other.lo);
        self.mid = veorq_u8(self.mid, other.mid);
        self.hi = veorq_u8(self.hi, other.hi);
    }
}

/// Carry-less 128x128 -> 256-bit multiply, `b_swapped` being `swap64(b)`.
#[inline]
unsafe fn clmul128(a: uint8x16_t, b: uint8x16_t, b_swapped: uint8x16_t) -> Product {
    // lo  = a_lo * b_lo
    // mid = a_lo * b_hi + a_hi * b_lo
    // hi  = a_hi * b_hi
    let lo = clmul_low(a, b);
    let mid = veorq_u8(clmul_low(a, b_swapped), clmul_high(a, b_swapped));
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
unsafe fn reduce(p: &Product) -> uint8x16_t {
    let zero = vdupq_n_u8(0);
    // Fold the middle partial product into the 256-bit value [hi:lo].
    let lo = veorq_u8(p.lo, vextq_u8(zero, p.mid, 8));
    let hi = veorq_u8(p.hi, vextq_u8(p.mid, zero, 8));

    // R in both halves, so that it can be the operand of `pmull` and `pmull2` alike.
    let rv = vreinterpretq_u8_u64(vdupq_n_u64(R));
    // h0 * x^128 = h0 * R, of degree at most 70: no overflow.
    let a = clmul_low(hi, rv);
    // h1 * x^192 = (h1 * R) * x^64, the shift dropping the 7 top bits of h1 * R.
    let b = clmul_high(hi, rv);
    let b_high = vgetq_lane_u64(vreinterpretq_u64_u8(b), 1);
    // Those dropped bits stand for b_high * x^128 = b_high * R, of degree at most 13.
    let c = vreinterpretq_u8_p128(vmull_p64(b_high, R));

    veorq_u8(veorq_u8(lo, a), veorq_u8(vextq_u8(zero, b, 8), c))
}

/// Multiply two normalized field elements.
#[inline]
unsafe fn gmul(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    reduce(&clmul128(a, b, swap64(b)))
}

/// GHASH hash key: the powers of H needed by the aggregated reduction.
#[derive(Clone)]
pub(super) struct Key {
    /// powers of H
    powers: [uint8x16_t; WIDE],
    /// same as powers but with the two halves exchanged
    swapped: [uint8x16_t; WIDE],
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
    x: uint8x16_t,
}

impl State {
    /// The initial GHASH state X_0 = 0.
    pub(super) fn zero() -> Self {
        State {
            x: unsafe { vdupq_n_u8(0) },
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
unsafe fn absorb(x: uint8x16_t, key: &Key, blocks: &[u8], first: usize) -> uint8x16_t {
    debug_assert_eq!(blocks.len() % 16, 0);
    debug_assert_eq!(first + blocks.len() / 16, WIDE);

    let powers = &key.powers[first..];
    let swapped = &key.swapped[first..];

    let mut blocks = blocks.chunks_exact(16);
    // The running state only enters through the first block.
    let head = blocks.next().expect("at least one block");
    let mut acc = clmul128(veorq_u8(load(head), x), powers[0], swapped[0]);
    for (block, (&p, &ps)) in blocks.zip(powers[1..].iter().zip(&swapped[1..])) {
        acc.add(&clmul128(load(block), p, ps));
    }
    reduce(&acc)
}

#[cfg(test)]
mod tests {
    use super::super::reference;
    use super::*;

    /// H = AES_0([0; 16]), from NIST SP 800-38D test case 1.
    const H: [u8; 16] = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b,
        0x2e,
    ];

    /// GHASH of `data` (a whole number of blocks) with the portable backend.
    fn reference_ghash(h: &[u8; 16], data: &[u8]) -> [u8; 16] {
        let mut state = reference::State::zero();
        state.update(&reference::Key::new(h), data);
        state.to_bytes()
    }

    /// Check `gmul` on its own: (0 XOR H) * H = H^2.
    #[test]
    fn square_matches_reference() {
        let squared = unsafe {
            let h = load(&H);
            store(gmul(h, h))
        };
        assert_eq!(squared, reference_ghash(&H, &H));
    }

    /// Every block count from zero up to five full groups plus a partial one,
    /// cross-checked against the portable backend.
    #[test]
    fn matches_reference() {
        // Deterministic pseudo-random bytes (xorshift64).
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed >> 32) as u8
        };

        for nblocks in 0..(5 * WIDE + 3) {
            let h: [u8; 16] = core::array::from_fn(|_| next());
            let mut data = vec![0u8; nblocks * 16];
            data.iter_mut().for_each(|b| *b = next());

            let mut got = State::zero();
            got.update(&Key::new(&h), &data);

            assert_eq!(
                got.to_bytes(),
                reference_ghash(&h, &data),
                "mismatch on {nblocks} blocks"
            );
        }
    }
}
