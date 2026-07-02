//! SHA-512 block compression using the ARMv8.2 SHA-512 crypto extensions
//! (`sha512h`, `sha512h2`, `sha512su0`, `sha512su1`), gated on the `sha3`
//! target feature. Round sequence adapted from mbedtls / RustCrypto's `sha2`.

use core::arch::aarch64::*;

use super::reference::K64;

// `data` length must be a multiple of 128 (the SHA-512 block size).
pub(crate) fn digest_block(state: &mut [u64; 8], data: &[u8]) {
    assert!(data.len() % 128 == 0);
    unsafe {
        // Load state into 2-lane vectors (native little-endian order).
        let mut ab = vld1q_u64(state.as_ptr().add(0));
        let mut cd = vld1q_u64(state.as_ptr().add(2));
        let mut ef = vld1q_u64(state.as_ptr().add(4));
        let mut gh = vld1q_u64(state.as_ptr().add(6));

        let mut length = data.len();
        let mut block = data.as_ptr();
        while length != 0 {
            // Keep the original state to add back at the end.
            let ab_orig = ab;
            let cd_orig = cd;
            let ef_orig = ef;
            let gh_orig = gh;

            // Load the 128-byte block, byte-swapping each 64-bit word (SHA-512
            // is big-endian).
            let mut s0 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block.add(0))));
            let mut s1 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block.add(16))));
            let mut s2 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block.add(32))));
            let mut s3 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block.add(48))));
            let mut s4 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block.add(64))));
            let mut s5 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block.add(80))));
            let mut s6 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block.add(96))));
            let mut s7 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block.add(112))));

            let mut initial_sum;
            let mut sum;
            let mut intermed;

            // Rounds 0 and 1
            initial_sum = vaddq_u64(s0, vld1q_u64(K64.as_ptr().add(0)));
            sum = vaddq_u64(vextq_u64::<1>(initial_sum, initial_sum), gh);
            intermed = vsha512hq_u64(sum, vextq_u64::<1>(ef, gh), vextq_u64::<1>(cd, ef));
            gh = vsha512h2q_u64(intermed, cd, ab);
            cd = vaddq_u64(cd, intermed);

            // Rounds 2 and 3
            initial_sum = vaddq_u64(s1, vld1q_u64(K64.as_ptr().add(2)));
            sum = vaddq_u64(vextq_u64::<1>(initial_sum, initial_sum), ef);
            intermed = vsha512hq_u64(sum, vextq_u64::<1>(cd, ef), vextq_u64::<1>(ab, cd));
            ef = vsha512h2q_u64(intermed, ab, gh);
            ab = vaddq_u64(ab, intermed);

            // Rounds 4 and 5
            initial_sum = vaddq_u64(s2, vld1q_u64(K64.as_ptr().add(4)));
            sum = vaddq_u64(vextq_u64::<1>(initial_sum, initial_sum), cd);
            intermed = vsha512hq_u64(sum, vextq_u64::<1>(ab, cd), vextq_u64::<1>(gh, ab));
            cd = vsha512h2q_u64(intermed, gh, ef);
            gh = vaddq_u64(gh, intermed);

            // Rounds 6 and 7
            initial_sum = vaddq_u64(s3, vld1q_u64(K64.as_ptr().add(6)));
            sum = vaddq_u64(vextq_u64::<1>(initial_sum, initial_sum), ab);
            intermed = vsha512hq_u64(sum, vextq_u64::<1>(gh, ab), vextq_u64::<1>(ef, gh));
            ab = vsha512h2q_u64(intermed, ef, cd);
            ef = vaddq_u64(ef, intermed);

            // Rounds 8 and 9
            initial_sum = vaddq_u64(s4, vld1q_u64(K64.as_ptr().add(8)));
            sum = vaddq_u64(vextq_u64::<1>(initial_sum, initial_sum), gh);
            intermed = vsha512hq_u64(sum, vextq_u64::<1>(ef, gh), vextq_u64::<1>(cd, ef));
            gh = vsha512h2q_u64(intermed, cd, ab);
            cd = vaddq_u64(cd, intermed);

            // Rounds 10 and 11
            initial_sum = vaddq_u64(s5, vld1q_u64(K64.as_ptr().add(10)));
            sum = vaddq_u64(vextq_u64::<1>(initial_sum, initial_sum), ef);
            intermed = vsha512hq_u64(sum, vextq_u64::<1>(cd, ef), vextq_u64::<1>(ab, cd));
            ef = vsha512h2q_u64(intermed, ab, gh);
            ab = vaddq_u64(ab, intermed);

            // Rounds 12 and 13
            initial_sum = vaddq_u64(s6, vld1q_u64(K64.as_ptr().add(12)));
            sum = vaddq_u64(vextq_u64::<1>(initial_sum, initial_sum), cd);
            intermed = vsha512hq_u64(sum, vextq_u64::<1>(ab, cd), vextq_u64::<1>(gh, ab));
            cd = vsha512h2q_u64(intermed, gh, ef);
            gh = vaddq_u64(gh, intermed);

            // Rounds 14 and 15
            initial_sum = vaddq_u64(s7, vld1q_u64(K64.as_ptr().add(14)));
            sum = vaddq_u64(vextq_u64::<1>(initial_sum, initial_sum), ab);
            intermed = vsha512hq_u64(sum, vextq_u64::<1>(gh, ab), vextq_u64::<1>(ef, gh));
            ab = vsha512h2q_u64(intermed, ef, cd);
            ef = vaddq_u64(ef, intermed);

            let mut t = 16;
            while t < 80 {
                // Rounds t and t + 1
                s0 = vsha512su1q_u64(vsha512su0q_u64(s0, s1), s7, vextq_u64::<1>(s4, s5));
                initial_sum = vaddq_u64(s0, vld1q_u64(K64.as_ptr().add(t)));
                sum = vaddq_u64(vextq_u64::<1>(initial_sum, initial_sum), gh);
                intermed = vsha512hq_u64(sum, vextq_u64::<1>(ef, gh), vextq_u64::<1>(cd, ef));
                gh = vsha512h2q_u64(intermed, cd, ab);
                cd = vaddq_u64(cd, intermed);

                // Rounds t + 2 and t + 3
                s1 = vsha512su1q_u64(vsha512su0q_u64(s1, s2), s0, vextq_u64::<1>(s5, s6));
                initial_sum = vaddq_u64(s1, vld1q_u64(K64.as_ptr().add(t + 2)));
                sum = vaddq_u64(vextq_u64::<1>(initial_sum, initial_sum), ef);
                intermed = vsha512hq_u64(sum, vextq_u64::<1>(cd, ef), vextq_u64::<1>(ab, cd));
                ef = vsha512h2q_u64(intermed, ab, gh);
                ab = vaddq_u64(ab, intermed);

                // Rounds t + 4 and t + 5
                s2 = vsha512su1q_u64(vsha512su0q_u64(s2, s3), s1, vextq_u64::<1>(s6, s7));
                initial_sum = vaddq_u64(s2, vld1q_u64(K64.as_ptr().add(t + 4)));
                sum = vaddq_u64(vextq_u64::<1>(initial_sum, initial_sum), cd);
                intermed = vsha512hq_u64(sum, vextq_u64::<1>(ab, cd), vextq_u64::<1>(gh, ab));
                cd = vsha512h2q_u64(intermed, gh, ef);
                gh = vaddq_u64(gh, intermed);

                // Rounds t + 6 and t + 7
                s3 = vsha512su1q_u64(vsha512su0q_u64(s3, s4), s2, vextq_u64::<1>(s7, s0));
                initial_sum = vaddq_u64(s3, vld1q_u64(K64.as_ptr().add(t + 6)));
                sum = vaddq_u64(vextq_u64::<1>(initial_sum, initial_sum), ab);
                intermed = vsha512hq_u64(sum, vextq_u64::<1>(gh, ab), vextq_u64::<1>(ef, gh));
                ab = vsha512h2q_u64(intermed, ef, cd);
                ef = vaddq_u64(ef, intermed);

                // Rounds t + 8 and t + 9
                s4 = vsha512su1q_u64(vsha512su0q_u64(s4, s5), s3, vextq_u64::<1>(s0, s1));
                initial_sum = vaddq_u64(s4, vld1q_u64(K64.as_ptr().add(t + 8)));
                sum = vaddq_u64(vextq_u64::<1>(initial_sum, initial_sum), gh);
                intermed = vsha512hq_u64(sum, vextq_u64::<1>(ef, gh), vextq_u64::<1>(cd, ef));
                gh = vsha512h2q_u64(intermed, cd, ab);
                cd = vaddq_u64(cd, intermed);

                // Rounds t + 10 and t + 11
                s5 = vsha512su1q_u64(vsha512su0q_u64(s5, s6), s4, vextq_u64::<1>(s1, s2));
                initial_sum = vaddq_u64(s5, vld1q_u64(K64.as_ptr().add(t + 10)));
                sum = vaddq_u64(vextq_u64::<1>(initial_sum, initial_sum), ef);
                intermed = vsha512hq_u64(sum, vextq_u64::<1>(cd, ef), vextq_u64::<1>(ab, cd));
                ef = vsha512h2q_u64(intermed, ab, gh);
                ab = vaddq_u64(ab, intermed);

                // Rounds t + 12 and t + 13
                s6 = vsha512su1q_u64(vsha512su0q_u64(s6, s7), s5, vextq_u64::<1>(s2, s3));
                initial_sum = vaddq_u64(s6, vld1q_u64(K64.as_ptr().add(t + 12)));
                sum = vaddq_u64(vextq_u64::<1>(initial_sum, initial_sum), cd);
                intermed = vsha512hq_u64(sum, vextq_u64::<1>(ab, cd), vextq_u64::<1>(gh, ab));
                cd = vsha512h2q_u64(intermed, gh, ef);
                gh = vaddq_u64(gh, intermed);

                // Rounds t + 14 and t + 15
                s7 = vsha512su1q_u64(vsha512su0q_u64(s7, s0), s6, vextq_u64::<1>(s3, s4));
                initial_sum = vaddq_u64(s7, vld1q_u64(K64.as_ptr().add(t + 14)));
                sum = vaddq_u64(vextq_u64::<1>(initial_sum, initial_sum), ab);
                intermed = vsha512hq_u64(sum, vextq_u64::<1>(gh, ab), vextq_u64::<1>(ef, gh));
                ab = vsha512h2q_u64(intermed, ef, cd);
                ef = vaddq_u64(ef, intermed);

                t += 16;
            }

            // Add the block's result back to the running state.
            ab = vaddq_u64(ab, ab_orig);
            cd = vaddq_u64(cd, cd_orig);
            ef = vaddq_u64(ef, ef_orig);
            gh = vaddq_u64(gh, gh_orig);

            block = block.add(128);
            length -= 128;
        }

        vst1q_u64(state.as_mut_ptr().add(0), ab);
        vst1q_u64(state.as_mut_ptr().add(2), cd);
        vst1q_u64(state.as_mut_ptr().add(4), ef);
        vst1q_u64(state.as_mut_ptr().add(6), gh);
    }
}
