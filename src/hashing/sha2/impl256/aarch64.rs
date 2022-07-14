use core::arch::aarch64::*;

use super::reference;

const K: [u32; 64] = reference::K32;

// block has to be a multiple of 64
pub(crate) fn digest_block(state: &mut [u32; 8], block: &[u8]) {
    assert!(block.len() % 64 == 0);
    unsafe {
        let mut tmp;
        let mut tmp_state;

        // Load state from native representation
        let mut state0 = vld1q_u32(state.as_ptr().offset(0));
        let mut state1 = vld1q_u32(state.as_ptr().offset(4));

        let mut length = block.len();

        let mut block = block.as_ptr();
        while length != 0 {
            // Save state for end mixing
            let previous_state0 = state0;
            let previous_state1 = state1;

            // Load 64-bytes block and swap endianess
            let mut block0 = vld1q_u32(block.offset(0) as *const u32);
            let mut block1 = vld1q_u32(block.offset(16) as *const u32);
            let mut block2 = vld1q_u32(block.offset(32) as *const u32);
            let mut block3 = vld1q_u32(block.offset(48) as *const u32);

            block0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(block0)));
            block1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(block1)));
            block2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(block2)));
            block3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(block3)));

            // handle 4 rounds, from $round to $round+3
            macro_rules! rounds4 {
                (mix, $round:literal, $b0:ident, $b1:ident, $b2:ident, $b3:ident) => {
                    tmp = vaddq_u32($b0, vld1q_u32(&K[$round]));
                    $b0 = vsha256su0q_u32($b0, $b1);
                    tmp_state = state0; // copy previous state for the h2q
                    state0 = vsha256hq_u32(state0, state1, tmp);
                    state1 = vsha256h2q_u32(state1, tmp_state, tmp);
                    $b0 = vsha256su1q_u32($b0, $b2, $b3);
                };
                (end, $round:literal, $b:ident) => {
                    tmp = vaddq_u32($b, vld1q_u32(&K[$round]));
                    tmp_state = state0; // copy previous state for the h2q
                    state0 = vsha256hq_u32(state0, state1, tmp);
                    state1 = vsha256h2q_u32(state1, tmp_state, tmp);
                };
            }

            rounds4!(mix, 0, block0, block1, block2, block3);
            rounds4!(mix, 4, block1, block2, block3, block0);
            rounds4!(mix, 8, block2, block3, block0, block1);
            rounds4!(mix, 12, block3, block0, block1, block2);
            rounds4!(mix, 16, block0, block1, block2, block3);
            rounds4!(mix, 20, block1, block2, block3, block0);
            rounds4!(mix, 24, block2, block3, block0, block1);
            rounds4!(mix, 28, block3, block0, block1, block2);
            rounds4!(mix, 32, block0, block1, block2, block3);
            rounds4!(mix, 36, block1, block2, block3, block0);
            rounds4!(mix, 40, block2, block3, block0, block1);
            rounds4!(mix, 44, block3, block0, block1, block2);
            rounds4!(end, 48, block0);
            rounds4!(end, 52, block1);
            rounds4!(end, 56, block2);
            rounds4!(end, 60, block3);

            // mix previous and new state
            state0 = vaddq_u32(state0, previous_state0);
            state1 = vaddq_u32(state1, previous_state1);

            block = block.offset(64);
            length -= 64;
        }

        // Store simd state back into state
        vst1q_u32(state.as_mut_ptr().offset(0), state0);
        vst1q_u32(state.as_mut_ptr().offset(4), state1);
    }
}
