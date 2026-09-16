//! SHA256 compression using the x86 SHA extensions (SHA-NI).
//!
//! Reference: "Intel SHA Extensions - New Instructions Supporting the Secure
//! Hashing Algorithm", S. Gulley et al.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::reference::K32;

/// The compression state, in the register layout `sha256rnds2` works on.
///
/// `sha256rnds2` does not take the state as the usual A..H sequence: its first
/// operand holds `[H, G, D, C]` and its second one `[F, E, B, A]` (from the low
/// 32-bit lane up). `load`/`store` convert between that and the `[u32; 8]`
/// engine state
struct State {
    /// `[F, E, B, A]`, called ABEF in Intel's description
    abef: __m128i,
    /// `[H, G, D, C]`, called CDGH in Intel's description
    cdgh: __m128i,
}

impl State {
    #[inline]
    unsafe fn load(state: &[u32; 8]) -> Self {
        let abcd = _mm_loadu_si128(state.as_ptr() as *const __m128i);
        let efgh = _mm_loadu_si128(state.as_ptr().add(4) as *const __m128i);
        // [B, A, D, C] and [H, G, F, E]
        let cdab = _mm_shuffle_epi32(abcd, 0xb1);
        let hgfe = _mm_shuffle_epi32(efgh, 0x1b);
        Self {
            abef: _mm_alignr_epi8(cdab, hgfe, 8),
            cdgh: _mm_blend_epi16(hgfe, cdab, 0xf0),
        }
    }

    #[inline]
    unsafe fn store(&self, state: &mut [u32; 8]) {
        // [A, B, E, F] and [G, H, C, D]
        let abef = _mm_shuffle_epi32(self.abef, 0x1b);
        let ghcd = _mm_shuffle_epi32(self.cdgh, 0xb1);
        let abcd = _mm_blend_epi16(abef, ghcd, 0xf0);
        let efgh = _mm_alignr_epi8(ghcd, abef, 8);
        _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, abcd);
        _mm_storeu_si128(state.as_mut_ptr().add(4) as *mut __m128i, efgh);
    }
}

pub(crate) fn digest_block(state: &mut [u32; 8], block: &[u8]) {
    if block.is_empty() {
        return;
    }
    unsafe { digest_blocks(state, block) }
}

#[inline]
unsafe fn digest_blocks(state: &mut [u32; 8], block: &[u8]) {
    /// the four round constants K[i..i+4], in ascending lanes
    macro_rules! k {
        ($i:expr) => {
            _mm_set_epi32(
                K32[$i + 3] as i32,
                K32[$i + 2] as i32,
                K32[$i + 1] as i32,
                K32[$i] as i32,
            )
        };
    }

    // reverse the bytes of each 32-bit word, turning the big-endian message
    // words of a 16 bytes chunk into native order
    let bswap_mask: __m128i = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);

    let State { mut abef, mut cdgh } = State::load(state);

    let mut data = block.as_ptr();
    let mut len = block.len();

    while len >= 64 {
        let abef_prev = abef;
        let cdgh_prev = cdgh;

        /// the 4 rounds `i .. i+4`, given `W[i..i+4] + K[i..i+4]` in the low lanes
        macro_rules! rounds4 {
            ($wk:expr) => {{
                let wk = $wk;
                cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);
                // rounds i+2 and i+3 read the two upper words of W+K
                abef = _mm_sha256rnds2_epu32(abef, cdgh, _mm_shuffle_epi32(wk, 0x0e));
            }};
        }

        /// load the message words `W[i..i+4]` from the block at byte offset `$o`
        macro_rules! load {
            ($o:expr) => {
                _mm_shuffle_epi8(_mm_loadu_si128(data.add($o) as *const __m128i), bswap_mask)
            };
        }

        /// the 4 rounds `i .. i+4` interleaved with the schedule work of the group:
        ///
        /// * `$cur` holds `W[i..i+4]`, `$prev` holds `W[i-4..i]`
        /// * `$next` holds the `W[k-16] + sigma0(W[k-15])` half of `W[i+4..i+8]`,
        ///   left there by the `sha256msg1` of two groups earlier, and is completed
        ///   here with the `W[k-7]` and `sigma1(W[k-2])` terms
        /// * `$prev` is then advanced to the `sigma0` half of `W[i+8..i+12]`
        macro_rules! sched4 {
            ($i:expr, $cur:ident, $next:ident, $prev:ident) => {
                let wk = _mm_add_epi32($cur, k!($i));
                cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);
                // [W[i-3], W[i-2], W[i-1], W[i]], the W[k-7] terms
                $next = _mm_add_epi32($next, _mm_alignr_epi8($cur, $prev, 4));
                $next = _mm_sha256msg2_epu32($next, $cur);
                abef = _mm_sha256rnds2_epu32(abef, cdgh, _mm_shuffle_epi32(wk, 0x0e));
                $prev = _mm_sha256msg1_epu32($prev, $cur);
            };
        }

        /// `sched4` without the `sha256msg1` step, for the last groups whose
        /// `sigma0` output would only ever feed the non-existent `W[64..]`
        macro_rules! sched4_tail {
            ($i:expr, $cur:ident, $next:ident, $prev:ident) => {
                let wk = _mm_add_epi32($cur, k!($i));
                cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);
                $next = _mm_add_epi32($next, _mm_alignr_epi8($cur, $prev, 4));
                $next = _mm_sha256msg2_epu32($next, $cur);
                abef = _mm_sha256rnds2_epu32(abef, cdgh, _mm_shuffle_epi32(wk, 0x0e));
            };
        }

        // rounds 0-15 take their message words straight from the block, and start
        // the sigma0 chain as soon as the word they need is available
        let mut m0 = load!(0);
        rounds4!(_mm_add_epi32(m0, k!(0)));
        let mut m1 = load!(16);
        rounds4!(_mm_add_epi32(m1, k!(4)));
        m0 = _mm_sha256msg1_epu32(m0, m1);
        let mut m2 = load!(32);
        rounds4!(_mm_add_epi32(m2, k!(8)));
        m1 = _mm_sha256msg1_epu32(m1, m2);
        let mut m3 = load!(48);

        // rounds 16-63 get their message words from the rotating schedule
        sched4!(12, m3, m0, m2);
        sched4!(16, m0, m1, m3);
        sched4!(20, m1, m2, m0);
        sched4!(24, m2, m3, m1);
        sched4!(28, m3, m0, m2);
        sched4!(32, m0, m1, m3);
        sched4!(36, m1, m2, m0);
        sched4!(40, m2, m3, m1);
        sched4!(44, m3, m0, m2);
        sched4!(48, m0, m1, m3);
        sched4_tail!(52, m1, m2, m0);
        sched4_tail!(56, m2, m3, m1);
        rounds4!(_mm_add_epi32(m3, k!(60)));

        abef = _mm_add_epi32(abef, abef_prev);
        cdgh = _mm_add_epi32(cdgh, cdgh_prev);

        data = data.add(64);
        len -= 64;
    }

    State { abef, cdgh }.store(state)
}
