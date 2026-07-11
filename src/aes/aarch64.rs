//! AES block cipher using the ARMv8 Cryptography Extensions.
//!
//! Uses the AES instructions available under the `aes` aarch64 target feature:
//! `vaese`/`vaesmc` for encryption and `vaesd`/`vaesimc` for decryption. The
//! round keys are expanded once at construction time using the standard
//! Rijndael key schedule; the S-box needed by the schedule is applied with a
//! single-round `vaese` against an all-zero key.
//!
//! This module is only compiled when the `aes` target feature is enabled at
//! compile time, so the intrinsics can be used from plain `unsafe` blocks
//! without per-function `#[target_feature]` gating.

use core::arch::aarch64::*;
use core::mem;

/// AES-128 round keys: the 11 encryption and 11 decryption round keys, already
/// in vector form ready to be fed to the AES instructions.
#[derive(Clone)]
pub(super) struct RoundKeys128 {
    enc: [uint8x16_t; 11],
    dec: [uint8x16_t; 11],
}

/// AES-256 round keys: the 15 encryption and 15 decryption round keys, already
/// in vector form ready to be fed to the AES instructions.
#[derive(Clone)]
pub(super) struct RoundKeys256 {
    enc: [uint8x16_t; 15],
    dec: [uint8x16_t; 15],
}

impl Drop for RoundKeys128 {
    fn drop(&mut self) {
        unsafe {
            let zero = vdupq_n_u8(0);
            self.enc = [zero; 11];
            self.dec = [zero; 11];
        }
    }
}

impl Drop for RoundKeys256 {
    fn drop(&mut self) {
        unsafe {
            let zero = vdupq_n_u8(0);
            self.enc = [zero; 15];
            self.dec = [zero; 15];
        }
    }
}

/// AES round constants (Rcon), one per key-schedule iteration.
const ROUND_CONSTS: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// SubBytes for a single 32-bit word, used by the key schedule.
///
/// The word is broadcast into all four columns of an AES state and run through
/// a single `vaese` round with an all-zero key. Since every column is
/// identical, ShiftRows leaves column 0 unchanged, so lane 0 of the result is
/// exactly `SubBytes(word)`.
#[inline]
unsafe fn sub_word(input: u32) -> u32 {
    let input = vreinterpretq_u8_u32(vdupq_n_u32(input));
    let sub = vaeseq_u8(input, vdupq_n_u8(0));
    vgetq_lane_u32(vreinterpretq_u32_u8(sub), 0)
}

/// Standard Rijndael key expansion into `N` encryption round keys.
///
/// `L` is the key length in bytes (16 for AES-128, 32 for AES-256) and `N` is
/// the number of round keys (11 for AES-128, 15 for AES-256).
unsafe fn expand_key_encryption<const L: usize, const N: usize>(key: &[u8; L]) -> [uint8x16_t; N] {
    /// There are 4 AES words (columns) in a block.
    const BLOCK_WORDS: usize = 4;
    /// An AES (Rijndael) word is always 32 bits / 4 bytes.
    const WORD_SIZE: usize = 4;

    let mut keys: [uint8x16_t; N] = mem::zeroed();

    // The round keys are laid out as native-endian 32-bit columns; casting the
    // 16-byte-aligned key array to `*mut u32` is sound.
    let cols_ptr: *mut u32 = keys.as_mut_ptr().cast();
    let columns = core::slice::from_raw_parts_mut(cols_ptr, N * BLOCK_WORDS);

    for (i, chunk) in key.chunks_exact(WORD_SIZE).enumerate() {
        columns[i] = u32::from_ne_bytes(chunk.try_into().unwrap());
    }

    // `Nk`: number of columns in the cipher key.
    let nk = L / WORD_SIZE;
    for i in nk..(N * BLOCK_WORDS) {
        let mut word = columns[i - 1];
        if i % nk == 0 {
            word = sub_word(word).rotate_right(8) ^ ROUND_CONSTS[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            word = sub_word(word);
        }
        columns[i] = columns[i - nk] ^ word;
    }

    keys
}

/// Derive the `N` decryption round keys from the encryption round keys.
///
/// This is the reverse of the encryption keys, with InvMixColumns applied to
/// all but the first and last, matching the equivalent inverse cipher.
unsafe fn expand_key_decryption<const N: usize>(keys: &[uint8x16_t; N]) -> [uint8x16_t; N] {
    let mut inv: [uint8x16_t; N] = mem::zeroed();
    inv[0] = keys[N - 1];
    for i in 1..(N - 1) {
        inv[i] = vaesimcq_u8(keys[N - 1 - i]);
    }
    inv[N - 1] = keys[0];
    inv
}

pub(super) fn key_schedule128(key: &[u8; 16]) -> RoundKeys128 {
    unsafe {
        let enc = expand_key_encryption::<16, 11>(key);
        let dec = expand_key_decryption::<11>(&enc);
        RoundKeys128 { enc, dec }
    }
}

pub(super) fn encrypt128(rkeys: &RoundKeys128, block: &[u8; 16]) -> [u8; 16] {
    unsafe {
        let mut b = vld1q_u8(block.as_ptr());
        // Rounds 1..=9: AddRoundKey + SubBytes + ShiftRows, then MixColumns.
        for &key in &rkeys.enc[..9] {
            b = vaeseq_u8(b, key);
            b = vaesmcq_u8(b);
        }
        // Round 10: no MixColumns, followed by the final AddRoundKey.
        b = vaeseq_u8(b, rkeys.enc[9]);
        b = veorq_u8(b, rkeys.enc[10]);

        let mut out = [0u8; 16];
        vst1q_u8(out.as_mut_ptr(), b);
        out
    }
}

pub(super) fn decrypt128(rkeys: &RoundKeys128, block: &[u8; 16]) -> [u8; 16] {
    unsafe {
        let mut b = vld1q_u8(block.as_ptr());
        // Rounds 1..=9: AddRoundKey + InvShiftRows + InvSubBytes, then InvMixColumns.
        for &key in &rkeys.dec[..9] {
            b = vaesdq_u8(b, key);
            b = vaesimcq_u8(b);
        }
        // Round 10: no InvMixColumns, followed by the final AddRoundKey.
        b = vaesdq_u8(b, rkeys.dec[9]);
        b = veorq_u8(b, rkeys.dec[10]);

        let mut out = [0u8; 16];
        vst1q_u8(out.as_mut_ptr(), b);
        out
    }
}

pub(super) fn key_schedule256(key: &[u8; 32]) -> RoundKeys256 {
    unsafe {
        let enc = expand_key_encryption::<32, 15>(key);
        let dec = expand_key_decryption::<15>(&enc);
        RoundKeys256 { enc, dec }
    }
}

pub(super) fn encrypt256(rkeys: &RoundKeys256, block: &[u8; 16]) -> [u8; 16] {
    unsafe {
        let mut b = vld1q_u8(block.as_ptr());
        // Rounds 1..=13: AddRoundKey + SubBytes + ShiftRows, then MixColumns.
        for &key in &rkeys.enc[..13] {
            b = vaeseq_u8(b, key);
            b = vaesmcq_u8(b);
        }
        // Round 14: no MixColumns, followed by the final AddRoundKey.
        b = vaeseq_u8(b, rkeys.enc[13]);
        b = veorq_u8(b, rkeys.enc[14]);

        let mut out = [0u8; 16];
        vst1q_u8(out.as_mut_ptr(), b);
        out
    }
}

pub(super) fn decrypt256(rkeys: &RoundKeys256, block: &[u8; 16]) -> [u8; 16] {
    unsafe {
        let mut b = vld1q_u8(block.as_ptr());
        // Rounds 1..=13: AddRoundKey + InvShiftRows + InvSubBytes, then InvMixColumns.
        for &key in &rkeys.dec[..13] {
            b = vaesdq_u8(b, key);
            b = vaesimcq_u8(b);
        }
        // Round 14: no InvMixColumns, followed by the final AddRoundKey.
        b = vaesdq_u8(b, rkeys.dec[13]);
        b = veorq_u8(b, rkeys.dec[14]);

        let mut out = [0u8; 16];
        vst1q_u8(out.as_mut_ptr(), b);
        out
    }
}
