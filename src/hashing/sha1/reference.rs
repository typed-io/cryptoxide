//! Portable software implementation of the SHA-1 compression function.
//!
//! This is a straightforward scalar implementation of the algorithm as
//! described in FIPS 180-4, valid on every architecture. Hardware accelerated
//! backends (see the sibling modules) fall back to this implementation when
//! the relevant CPU features are not available at compile time.

use crate::cryptoutil::read_u32v_be;

use super::STATE_LEN;

const K0: u32 = 0x5A827999;
const K1: u32 = 0x6ED9EBA1;
const K2: u32 = 0x8F1BBCDC;
const K3: u32 = 0xCA62C1D6;

fn digest_block_u32(state: &mut [u32; STATE_LEN], block: &[u32; 16]) {
    // Expand the 16 words of the block into the 80 words message schedule.
    let mut w = [0u32; 80];
    w[..16].copy_from_slice(block);
    for t in 16..80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];

    macro_rules! round {
        ($f:expr, $k:expr, $t:expr) => {{
            let tmp = a
                .rotate_left(5)
                .wrapping_add($f)
                .wrapping_add(e)
                .wrapping_add($k)
                .wrapping_add(w[$t]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }};
    }

    // Rounds 0..20 : Choose
    for t in 0..20 {
        round!(d ^ (b & (c ^ d)), K0, t);
    }
    // Rounds 20..40 : Parity
    for t in 20..40 {
        round!(b ^ c ^ d, K1, t);
    }
    // Rounds 40..60 : Majority
    for t in 40..60 {
        round!((b & c) | (b & d) | (c & d), K2, t);
    }
    // Rounds 60..80 : Parity
    for t in 60..80 {
        round!(b ^ c ^ d, K3, t);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

/// Process one or more 64-bytes block with the SHA-1 algorithm.
///
/// `block` length must be a multiple of 64 bytes.
pub(super) fn digest_block(state: &mut [u32; STATE_LEN], block: &[u8]) {
    assert_eq!(block.len() % 64, 0);
    let mut w = [0u32; 16];
    let mut i = 0;
    while i < block.len() {
        read_u32v_be(&mut w, &block[i..i + 64]);
        digest_block_u32(state, &w);
        i += 64;
    }
}
