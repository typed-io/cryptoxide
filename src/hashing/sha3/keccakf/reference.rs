//! Portable reference implementation of the Keccak-f[1600] permutation.
//!
//! Code based on Keccak-compact64.c from the reference implementation.

use crate::cryptoutil::{read_u64v_le, write_u64v_le};

use super::{NROUNDS, RC};

const ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
const PIL: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];
const M5: [usize; 10] = [0, 1, 2, 3, 4, 0, 1, 2, 3, 4];

#[allow(clippy::needless_range_loop)]
pub(super) fn keccak_f(state: &mut [u8; super::super::B]) {
    let mut s: [u64; 25] = [0; 25];
    let mut t: [u64; 1] = [0; 1];
    let mut c: [u64; 5] = [0; 5];

    read_u64v_le(&mut s, state);

    for round in 0..NROUNDS {
        // Theta
        for x in 0..5 {
            c[x] = s[x] ^ s[5 + x] ^ s[10 + x] ^ s[15 + x] ^ s[20 + x];
        }
        for x in 0..5 {
            t[0] = c[M5[x + 4]] ^ c[M5[x + 1]].rotate_left(1);
            for y in 0..5 {
                s[y * 5 + x] ^= t[0];
            }
        }

        // Rho Pi
        t[0] = s[1];
        for x in 0..24 {
            c[0] = s[PIL[x]];
            s[PIL[x]] = t[0].rotate_left(ROTC[x]);
            t[0] = c[0];
        }

        // Chi
        for y in 0..5 {
            for x in 0..5 {
                c[x] = s[y * 5 + x];
            }
            for x in 0..5 {
                s[y * 5 + x] = c[x] ^ (!c[M5[x + 1]] & c[M5[x + 2]]);
            }
        }

        // Iota
        s[0] ^= RC[round];
    }

    write_u64v_le(state, &s);
}
