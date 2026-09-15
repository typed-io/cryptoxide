//! AES block cipher using the x86 AES-NI instructions.
//!
//! This module is only compiled when the `aes` target feature is enabled at
//! compile time

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// Number of encrypt/decrypt blocks processed together.
///
/// `aesenc` has a several-cycle latency but is pipelined, so processing
/// independent blocks in lockstep hides that latency
pub(super) const PARALLEL_BLOCKS: usize = 8;

/// AES-128 round keys: the 11 encryption and 11 decryption round keys
#[derive(Clone)]
pub(super) struct RoundKeys128 {
    enc: [__m128i; 11],
    dec: [__m128i; 11],
}

/// AES-256 round keys: the 15 encryption and 15 decryption round keys
#[derive(Clone)]
pub(super) struct RoundKeys256 {
    enc: [__m128i; 15],
    dec: [__m128i; 15],
}

impl Drop for RoundKeys128 {
    fn drop(&mut self) {
        unsafe {
            let zero = _mm_setzero_si128();
            self.enc = [zero; 11];
            self.dec = [zero; 11];
        }
    }
}

impl Drop for RoundKeys256 {
    fn drop(&mut self) {
        unsafe {
            let zero = _mm_setzero_si128();
            self.enc = [zero; 15];
            self.dec = [zero; 15];
        }
    }
}

/// AES round constants (Rcon), one per key-schedule iteration.
const ROUND_CONSTS: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// SubBytes for a single 32-bit word, used by the key schedule.
///
/// The word is broadcast into all four columns of an AES state and `aeskeygenassist`
/// is used with a zero round constant; it applies `SubBytes` to the second 32-bit
/// lane, which is the broadcast word, and leaves the result in lane 0.
#[inline]
unsafe fn sub_word(input: u32) -> u32 {
    let input = _mm_set1_epi32(input as i32);
    let sub = _mm_aeskeygenassist_si128(input, 0);
    _mm_cvtsi128_si32(sub) as u32
}

/// Standard Rijndael key expansion into `N` encryption round keys.
///
/// `L` is the key length in bytes (16 for AES-128, 32 for AES-256) and `N` is
/// the number of round keys (11 for AES-128, 15 for AES-256).
unsafe fn expand_key_encryption<const L: usize, const N: usize>(key: &[u8; L]) -> [__m128i; N] {
    /// There are 4 AES words (columns) in a block.
    const BLOCK_WORDS: usize = 4;
    /// An AES (Rijndael) word is always 32 bits / 4 bytes.
    const WORD_SIZE: usize = 4;

    let mut keys: [__m128i; N] = [_mm_setzero_si128(); N];

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
unsafe fn expand_key_decryption<const N: usize>(keys: &[__m128i; N]) -> [__m128i; N] {
    let mut inv: [__m128i; N] = [_mm_setzero_si128(); N];
    inv[0] = keys[N - 1];
    for i in 1..(N - 1) {
        inv[i] = _mm_aesimc_si128(keys[N - 1 - i]);
    }
    inv[N - 1] = keys[0];
    inv
}

/// Load `B` blocks into vector registers.
#[inline(always)]
unsafe fn load_blocks<const B: usize>(blocks: &[[u8; 16]; B]) -> [__m128i; B] {
    core::array::from_fn(|i| _mm_loadu_si128(blocks[i].as_ptr().cast()))
}

/// Store `B` blocks back out of vector registers.
#[inline(always)]
unsafe fn store_blocks<const B: usize>(blocks: &[__m128i; B]) -> [[u8; 16]; B] {
    let mut out = [[0u8; 16]; B];
    for (out, b) in out.iter_mut().zip(blocks.iter()) {
        _mm_storeu_si128(out.as_mut_ptr().cast(), *b);
    }
    out
}

/// Encrypt exactly `B` blocks with the `N` given encryption round keys.
#[inline(always)]
unsafe fn encrypt_n<const N: usize, const B: usize>(
    keys: &[__m128i; N],
    blocks: &[[u8; 16]; B],
) -> [[u8; 16]; B] {
    let mut b = load_blocks(blocks);

    // Initial AddRoundKey.
    for v in b.iter_mut() {
        *v = _mm_xor_si128(*v, keys[0]);
    }
    // All rounds but the last: ShiftRows + SubBytes + MixColumns + AddRoundKey.
    for &key in &keys[1..N - 1] {
        for v in b.iter_mut() {
            *v = _mm_aesenc_si128(*v, key);
        }
    }
    // Last round: no MixColumns, followed by the final AddRoundKey.
    for v in b.iter_mut() {
        *v = _mm_aesenclast_si128(*v, keys[N - 1]);
    }

    store_blocks(&b)
}

/// Decrypt exactly `B` blocks with the `N` given decryption round keys.
#[inline(always)]
unsafe fn decrypt_n<const N: usize, const B: usize>(
    keys: &[__m128i; N],
    blocks: &[[u8; 16]; B],
) -> [[u8; 16]; B] {
    let mut b = load_blocks(blocks);

    // Initial AddRoundKey.
    for v in b.iter_mut() {
        *v = _mm_xor_si128(*v, keys[0]);
    }
    // All rounds but the last: InvShiftRows + InvSubBytes + InvMixColumns + AddRoundKey.
    for &key in &keys[1..N - 1] {
        for v in b.iter_mut() {
            *v = _mm_aesdec_si128(*v, key);
        }
    }
    // Last round: no InvMixColumns, followed by the final AddRoundKey.
    for v in b.iter_mut() {
        *v = _mm_aesdeclast_si128(*v, keys[N - 1]);
    }

    store_blocks(&b)
}

pub(super) fn key_schedule128(key: &[u8; 16]) -> RoundKeys128 {
    unsafe {
        let enc = expand_key_encryption::<16, 11>(key);
        let dec = expand_key_decryption::<11>(&enc);
        RoundKeys128 { enc, dec }
    }
}

pub(super) fn encrypt128(rkeys: &RoundKeys128, block: &[u8; 16]) -> [u8; 16] {
    unsafe { encrypt_n(&rkeys.enc, &[*block])[0] }
}

pub(super) fn encrypt128_blocks(
    rkeys: &RoundKeys128,
    blocks: &[[u8; 16]; PARALLEL_BLOCKS],
) -> [[u8; 16]; PARALLEL_BLOCKS] {
    unsafe { encrypt_n(&rkeys.enc, blocks) }
}

pub(super) fn decrypt128(rkeys: &RoundKeys128, block: &[u8; 16]) -> [u8; 16] {
    unsafe { decrypt_n(&rkeys.dec, &[*block])[0] }
}

pub(super) fn decrypt128_blocks(
    rkeys: &RoundKeys128,
    blocks: &[[u8; 16]; PARALLEL_BLOCKS],
) -> [[u8; 16]; PARALLEL_BLOCKS] {
    unsafe { decrypt_n(&rkeys.dec, blocks) }
}

pub(super) fn key_schedule256(key: &[u8; 32]) -> RoundKeys256 {
    unsafe {
        let enc = expand_key_encryption::<32, 15>(key);
        let dec = expand_key_decryption::<15>(&enc);
        RoundKeys256 { enc, dec }
    }
}

pub(super) fn encrypt256(rkeys: &RoundKeys256, block: &[u8; 16]) -> [u8; 16] {
    unsafe { encrypt_n(&rkeys.enc, &[*block])[0] }
}

pub(super) fn encrypt256_blocks(
    rkeys: &RoundKeys256,
    blocks: &[[u8; 16]; PARALLEL_BLOCKS],
) -> [[u8; 16]; PARALLEL_BLOCKS] {
    unsafe { encrypt_n(&rkeys.enc, blocks) }
}

pub(super) fn decrypt256(rkeys: &RoundKeys256, block: &[u8; 16]) -> [u8; 16] {
    unsafe { decrypt_n(&rkeys.dec, &[*block])[0] }
}

pub(super) fn decrypt256_blocks(
    rkeys: &RoundKeys256,
    blocks: &[[u8; 16]; PARALLEL_BLOCKS],
) -> [[u8; 16]; PARALLEL_BLOCKS] {
    unsafe { decrypt_n(&rkeys.dec, blocks) }
}
