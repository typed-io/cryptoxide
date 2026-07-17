//! aarch64 hardware accelerated SHA-1 compression function.
//!
//! This uses the ARMv8 SHA-1 crypto extension intrinsics (`SHA1C`, `SHA1P`,
//! `SHA1M`, `SHA1H`, `SHA1SU0`, `SHA1SU1`), which are gated in Rust behind the
//! `sha2` target feature. The module is only compiled when that feature is
//! enabled at compile time, so the intrinsics can be called directly.

use core::arch::aarch64::*;

use super::STATE_LEN;

const K0: u32 = 0x5A827999;
const K1: u32 = 0x6ED9EBA1;
const K2: u32 = 0x8F1BBCDC;
const K3: u32 = 0xCA62C1D6;

/// Process one or more 64-bytes block with the SHA-1 algorithm.
///
/// `block` length must be a multiple of 64 bytes.
pub(super) fn digest_block(state: &mut [u32; STATE_LEN], block: &[u8]) {
    assert_eq!(block.len() % 64, 0);
    unsafe {
        let k0 = vdupq_n_u32(K0);
        let k1 = vdupq_n_u32(K1);
        let k2 = vdupq_n_u32(K2);
        let k3 = vdupq_n_u32(K3);

        // Load the abcd part of the state; e is kept in a scalar.
        let mut abcd = vld1q_u32(state.as_ptr());
        let mut e0 = state[4];

        let mut length = block.len();
        let mut block = block.as_ptr();
        while length != 0 {
            // Save the state for the final block mixing.
            let abcd_saved = abcd;
            let e0_saved = e0;

            // Load the 64-bytes block and byte-swap each word to big-endian.
            let mut msg0 = vld1q_u32(block.offset(0) as *const u32);
            let mut msg1 = vld1q_u32(block.offset(16) as *const u32);
            let mut msg2 = vld1q_u32(block.offset(32) as *const u32);
            let mut msg3 = vld1q_u32(block.offset(48) as *const u32);

            msg0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg0)));
            msg1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg1)));
            msg2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg2)));
            msg3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg3)));

            let mut tmp0 = vaddq_u32(msg0, k0);
            let mut tmp1 = vaddq_u32(msg1, k0);

            // Rounds 0-3
            let e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1cq_u32(abcd, e0, tmp0);
            tmp0 = vaddq_u32(msg2, k0);
            msg0 = vsha1su0q_u32(msg0, msg1, msg2);

            // Rounds 4-7
            e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1cq_u32(abcd, e1, tmp1);
            tmp1 = vaddq_u32(msg3, k0);
            msg0 = vsha1su1q_u32(msg0, msg3);
            msg1 = vsha1su0q_u32(msg1, msg2, msg3);

            // Rounds 8-11
            let e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1cq_u32(abcd, e0, tmp0);
            tmp0 = vaddq_u32(msg0, k0);
            msg1 = vsha1su1q_u32(msg1, msg0);
            msg2 = vsha1su0q_u32(msg2, msg3, msg0);

            // Rounds 12-15
            e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1cq_u32(abcd, e1, tmp1);
            tmp1 = vaddq_u32(msg1, k1);
            msg2 = vsha1su1q_u32(msg2, msg1);
            msg3 = vsha1su0q_u32(msg3, msg0, msg1);

            // Rounds 16-19
            let e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1cq_u32(abcd, e0, tmp0);
            tmp0 = vaddq_u32(msg2, k1);
            msg3 = vsha1su1q_u32(msg3, msg2);
            msg0 = vsha1su0q_u32(msg0, msg1, msg2);

            // Rounds 20-23
            e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1pq_u32(abcd, e1, tmp1);
            tmp1 = vaddq_u32(msg3, k1);
            msg0 = vsha1su1q_u32(msg0, msg3);
            msg1 = vsha1su0q_u32(msg1, msg2, msg3);

            // Rounds 24-27
            let e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1pq_u32(abcd, e0, tmp0);
            tmp0 = vaddq_u32(msg0, k1);
            msg1 = vsha1su1q_u32(msg1, msg0);
            msg2 = vsha1su0q_u32(msg2, msg3, msg0);

            // Rounds 28-31
            e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1pq_u32(abcd, e1, tmp1);
            tmp1 = vaddq_u32(msg1, k1);
            msg2 = vsha1su1q_u32(msg2, msg1);
            msg3 = vsha1su0q_u32(msg3, msg0, msg1);

            // Rounds 32-35
            let e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1pq_u32(abcd, e0, tmp0);
            tmp0 = vaddq_u32(msg2, k2);
            msg3 = vsha1su1q_u32(msg3, msg2);
            msg0 = vsha1su0q_u32(msg0, msg1, msg2);

            // Rounds 36-39
            e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1pq_u32(abcd, e1, tmp1);
            tmp1 = vaddq_u32(msg3, k2);
            msg0 = vsha1su1q_u32(msg0, msg3);
            msg1 = vsha1su0q_u32(msg1, msg2, msg3);

            // Rounds 40-43
            let e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1mq_u32(abcd, e0, tmp0);
            tmp0 = vaddq_u32(msg0, k2);
            msg1 = vsha1su1q_u32(msg1, msg0);
            msg2 = vsha1su0q_u32(msg2, msg3, msg0);

            // Rounds 44-47
            e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1mq_u32(abcd, e1, tmp1);
            tmp1 = vaddq_u32(msg1, k2);
            msg2 = vsha1su1q_u32(msg2, msg1);
            msg3 = vsha1su0q_u32(msg3, msg0, msg1);

            // Rounds 48-51
            let e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1mq_u32(abcd, e0, tmp0);
            tmp0 = vaddq_u32(msg2, k2);
            msg3 = vsha1su1q_u32(msg3, msg2);
            msg0 = vsha1su0q_u32(msg0, msg1, msg2);

            // Rounds 52-55
            e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1mq_u32(abcd, e1, tmp1);
            tmp1 = vaddq_u32(msg3, k3);
            msg0 = vsha1su1q_u32(msg0, msg3);
            msg1 = vsha1su0q_u32(msg1, msg2, msg3);

            // Rounds 56-59
            let e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1mq_u32(abcd, e0, tmp0);
            tmp0 = vaddq_u32(msg0, k3);
            msg1 = vsha1su1q_u32(msg1, msg0);
            msg2 = vsha1su0q_u32(msg2, msg3, msg0);

            // Rounds 60-63
            e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1pq_u32(abcd, e1, tmp1);
            tmp1 = vaddq_u32(msg1, k3);
            msg2 = vsha1su1q_u32(msg2, msg1);
            msg3 = vsha1su0q_u32(msg3, msg0, msg1);

            // Rounds 64-67
            let e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1pq_u32(abcd, e0, tmp0);
            tmp0 = vaddq_u32(msg2, k3);
            msg3 = vsha1su1q_u32(msg3, msg2);
            msg0 = vsha1su0q_u32(msg0, msg1, msg2);

            // Rounds 68-71
            e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1pq_u32(abcd, e1, tmp1);
            tmp1 = vaddq_u32(msg3, k3);
            msg0 = vsha1su1q_u32(msg0, msg3);

            // Rounds 72-75
            let e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1pq_u32(abcd, e0, tmp0);

            // Rounds 76-79
            e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
            abcd = vsha1pq_u32(abcd, e1, tmp1);

            // Add this block's hash to the state.
            e0 = e0.wrapping_add(e0_saved);
            abcd = vaddq_u32(abcd_saved, abcd);

            block = block.offset(64);
            length -= 64;
        }

        // Store the state back.
        vst1q_u32(state.as_mut_ptr(), abcd);
        state[4] = e0;
    }
}
