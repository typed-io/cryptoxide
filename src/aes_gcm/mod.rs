//! AES-GCM authenticated encryption.
//!
//! AES-GCM (Galois/Counter Mode) is an authenticated encryption with associated data (AEAD)
//! cipher defined in [NIST SP 800-38D][1].
//!
//! This module provides 2 interfaces:
//!
//! * the one shot interface [`AesGcm128`] and [`AesGcm256`]
//! * the incremental interfaces, using [`Context`], [`ContextEncryption`] and [`ContextDecryption`]
//!
//! The incremental interfaces should be used when you are streaming data or
//! need more control over memory usage, as the one-shot interface expects
//! one single call with slices parameter.
//!
//! # Examples
//!
//! Encrypting using the one-shot interface:
//!
//! ```
//! use cryptoxide::aes_gcm::AesGcm256;
//!
//! let key = [0x01u8; 32];
//! let nonce = [0x02u8; 12];
//! let aad = b"additional data";
//! let plaintext = b"hello world!";
//! let mut ciphertext = [0u8; 12];
//! let mut tag = cryptoxide::aes_gcm::Tag([0u8; 16]);
//!
//! let cipher = AesGcm256::new(&key);
//! cipher.encrypt(&nonce, aad, plaintext, &mut ciphertext, &mut tag);
//! ```
//!
//! Encrypting using the incremental interfaces:
//!
//! ```
//! use cryptoxide::aes_gcm;
//!
//! let key = [0x01u8; 16];
//! let nonce = [0x02u8; 12];
//!
//! let mut ctx = aes_gcm::Context::new128(&key, &nonce);
//!
//! ctx.add_data(b"authenticated");
//! ctx.add_data(b"data");
//!
//! let mut encrypted = [0u8; 10];
//! let mut ctx = ctx.to_encryption();
//!
//! ctx.encrypt(b"hello", &mut encrypted[0..5]);
//! ctx.encrypt(b"world", &mut encrypted[5..10]);
//!
//! let tag = ctx.finalize();
//! ```
//!
//! [1]: https://csrc.nist.gov/publications/detail/sp/800-38d/final

use crate::{
    aes::{Aes128, Aes256, BLOCK_BYTES, PARALLEL_BLOCKS},
    constant_time::{Choice, CtEqual},
};

mod ctr;
mod ghash;

use ctr::{make_j0, Ctr};
use ghash::GHash;

/// The block encryption AES-GCM needs: the CTR keystream and the tag.
///
/// Implemented for the concrete ciphers used by the one-shot interfaces and for
/// the [`Cipher`] enum used by the incremental ones, so that the counter mode
/// reaches `encrypt_blocks` without a virtual call in either case.
trait BlockEncryptor {
    /// Encrypt a single block.
    fn encrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES];

    /// Encrypt [`PARALLEL_BLOCKS`] independent blocks at once.
    fn encrypt_blocks(
        &self,
        blocks: &[[u8; BLOCK_BYTES]; PARALLEL_BLOCKS],
    ) -> [[u8; BLOCK_BYTES]; PARALLEL_BLOCKS];
}

impl BlockEncryptor for Aes128 {
    fn encrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        Aes128::encrypt_block(self, block)
    }
    fn encrypt_blocks(
        &self,
        blocks: &[[u8; BLOCK_BYTES]; PARALLEL_BLOCKS],
    ) -> [[u8; BLOCK_BYTES]; PARALLEL_BLOCKS] {
        Aes128::encrypt_blocks(self, blocks)
    }
}

impl BlockEncryptor for Aes256 {
    fn encrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        Aes256::encrypt_block(self, block)
    }
    fn encrypt_blocks(
        &self,
        blocks: &[[u8; BLOCK_BYTES]; PARALLEL_BLOCKS],
    ) -> [[u8; BLOCK_BYTES]; PARALLEL_BLOCKS] {
        Aes256::encrypt_blocks(self, blocks)
    }
}

/// AES-GCM authentication tag.
///
/// Contains the 16-byte authentication tag produced by AES-GCM encryption
/// or expected during decryption. Tag comparison uses constant-time
/// equality via the [`CtEqual`] trait to prevent timing side channels.
#[derive(Debug, Clone)]
pub struct Tag(pub [u8; 16]);

impl CtEqual for &Tag {
    fn ct_eq(self, other: Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
    fn ct_ne(self, b: Self) -> Choice {
        self.ct_eq(b).negate()
    }
}

impl PartialEq for Tag {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).is_true()
    }
}

impl Eq for Tag {}

impl AsRef<[u8; 16]> for Tag {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl AsMut<[u8; 16]> for Tag {
    fn as_mut(&mut self) -> &mut [u8; 16] {
        &mut self.0
    }
}

/// Result of AES-GCM decryption -- indicates whether the authentication tag matched.
///
/// The caller **must** check this result before using the decrypted output.
/// A [`DecryptionResult::MisMatch`] means the ciphertext or AAD was tampered with
/// (or the wrong key/nonce was used), and the output should be discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptionResult {
    /// The tag matched: the data has been verified as authentic.
    Match,
    /// The tag did not match: the data may have been tampered with.
    MisMatch,
}

/// Compute the authentication tag from GHASH output and J0.
///
/// `tag = AES_K(J0) XOR ghash_output`
fn compute_tag<C: BlockEncryptor>(cipher: &C, j0: &[u8; BLOCK_BYTES], ghash_out: &[u8; 16]) -> Tag {
    let encrypted_j0 = cipher.encrypt_block(j0);
    let mut tag_bytes = [0u8; 16];
    for i in 0..16 {
        tag_bytes[i] = encrypted_j0[i] ^ ghash_out[i];
    }
    Tag(tag_bytes)
}

/// AES-128-GCM authenticated encryption cipher.
///
/// Combines AES-128 in counter mode with GHASH authentication.
/// The key is expanded once at construction time and can be reused
/// for multiple encrypt/decrypt operations with different nonces.
///
/// # Security Warning
///
/// **Never reuse a nonce with the same key.** AES-GCM security completely
/// breaks down if a (key, nonce) pair is used more than once.
pub struct AesGcm128 {
    cipher: Aes128,
    h: [u8; 16],
}

impl AesGcm128 {
    /// Create a new AES-128-GCM cipher from a 128-bit key.
    ///
    /// Performs AES key schedule expansion and precomputes the hash key
    /// `H = AES_K([0; 16])`.
    pub fn new(key: &[u8; 16]) -> Self {
        let cipher = Aes128::new(key);
        let h = cipher.encrypt_block(&[0u8; BLOCK_BYTES]);
        AesGcm128 { cipher, h }
    }

    /// Encrypt plaintext with associated data in a single call.
    ///
    /// # Arguments
    ///
    /// * `nonce` - 96-bit nonce (must never be reused with the same key)
    /// * `aad` - Additional authenticated data (authenticated but not encrypted)
    /// * `input` - Plaintext to encrypt
    /// * `output` - Buffer for ciphertext (must be same length as `input`)
    /// * `tag` - Output authentication tag
    ///
    /// # Panics
    ///
    /// Panics if `input.len() != output.len()`.
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
        tag: &mut Tag,
    ) {
        assert_eq!(input.len(), output.len());
        let j0 = make_j0(nonce);

        // CTR encrypt starting from inc32(J0)
        let mut ctr = Ctr::new(&j0);
        ctr.process(&self.cipher, input, output);

        // GHASH over AAD || pad || ciphertext || pad || length block
        let mut gh = GHash::new(&self.h);
        gh.update(aad);
        gh.pad();
        gh.update(output);
        let ghash_out = gh.finalize(aad.len() as u64, output.len() as u64);

        // Tag = AES_K(J0) XOR GHASH
        *tag = compute_tag(&self.cipher, &j0, &ghash_out);
    }

    /// Decrypt ciphertext and verify the authentication tag in a single call.
    ///
    /// # Arguments
    ///
    /// * `nonce` - 96-bit nonce used during encryption
    /// * `aad` - Additional authenticated data used during encryption
    /// * `input` - Ciphertext to decrypt
    /// * `output` - Buffer for plaintext (must be same length as `input`)
    /// * `tag` - Expected authentication tag
    ///
    /// # Returns
    ///
    /// [`DecryptionResult::Match`] if the tag is valid and `output` contains
    /// the plaintext. [`DecryptionResult::MisMatch`] if the tag does not match,
    /// in which case the output should be discarded.
    ///
    /// # Panics
    ///
    /// Panics if `input.len() != output.len()`.
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
        tag: &Tag,
    ) -> DecryptionResult {
        assert_eq!(input.len(), output.len());
        let j0 = make_j0(nonce);

        // Compute expected tag from ciphertext (input)
        let mut gh = GHash::new(&self.h);
        gh.update(aad);
        gh.pad();
        gh.update(input);
        let ghash_out = gh.finalize(aad.len() as u64, input.len() as u64);
        let expected = compute_tag(&self.cipher, &j0, &ghash_out);

        // Constant-time tag comparison
        if &expected == tag {
            // Tag matches: decrypt
            let mut ctr = Ctr::new(&j0);
            ctr.process(&self.cipher, input, output);
            DecryptionResult::Match
        } else {
            DecryptionResult::MisMatch
        }
    }
}

impl Drop for AesGcm128 {
    fn drop(&mut self) {
        self.h = [0u8; 16];
    }
}

/// AES-256-GCM authenticated encryption cipher.
///
/// Combines AES-256 in counter mode with GHASH authentication.
/// The key is expanded once at construction time and can be reused
/// for multiple encrypt/decrypt operations with different nonces.
///
/// # Security Warning
///
/// **Never reuse a nonce with the same key.** AES-GCM security completely
/// breaks down if a (key, nonce) pair is used more than once.
pub struct AesGcm256 {
    cipher: Aes256,
    h: [u8; 16],
}

impl AesGcm256 {
    /// Create a new AES-256-GCM cipher from a 256-bit key.
    ///
    /// Performs AES key schedule expansion and precomputes the hash key
    /// `H = AES_K([0;16])`.
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes256::new(key);
        let h = cipher.encrypt_block(&[0u8; 16]);
        AesGcm256 { cipher, h }
    }

    /// Encrypt plaintext with associated data in a single call.
    ///
    /// # Arguments
    ///
    /// * `nonce` - 96-bit nonce (must never be reused with the same key)
    /// * `aad` - Additional authenticated data (authenticated but not encrypted)
    /// * `input` - Plaintext to encrypt
    /// * `output` - Buffer for ciphertext (must be same length as `input`)
    /// * `tag` - Output authentication tag
    ///
    /// # Panics
    ///
    /// Panics if `input.len() != output.len()`.
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
        tag: &mut Tag,
    ) {
        assert_eq!(input.len(), output.len());
        let j0 = make_j0(nonce);

        // CTR encrypt starting from inc32(J0)
        let mut ctr = Ctr::new(&j0);
        ctr.process(&self.cipher, input, output);

        // GHASH over AAD || pad || ciphertext || pad || length block
        let mut gh = GHash::new(&self.h);
        gh.update(aad);
        gh.pad();
        gh.update(output);
        let ghash_out = gh.finalize(aad.len() as u64, output.len() as u64);

        // Tag = AES_K(J0) XOR GHASH
        *tag = compute_tag(&self.cipher, &j0, &ghash_out);
    }

    /// Decrypt ciphertext and verify the authentication tag in a single call.
    ///
    /// # Arguments
    ///
    /// * `nonce` - 96-bit nonce used during encryption
    /// * `aad` - Additional authenticated data used during encryption
    /// * `input` - Ciphertext to decrypt
    /// * `output` - Buffer for plaintext (must be same length as `input`)
    /// * `tag` - Expected authentication tag
    ///
    /// # Returns
    ///
    /// [`DecryptionResult::Match`] if the tag is valid and `output` contains
    /// the plaintext. [`DecryptionResult::MisMatch`] if the tag does not match,
    /// in which case the output should be discarded.
    ///
    /// # Panics
    ///
    /// Panics if `input.len() != output.len()`.
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
        tag: &Tag,
    ) -> DecryptionResult {
        assert_eq!(input.len(), output.len());
        let j0 = make_j0(nonce);

        // Compute expected tag from ciphertext (input)
        let mut gh = GHash::new(&self.h);
        gh.update(aad);
        gh.pad();
        gh.update(input);
        let ghash_out = gh.finalize(aad.len() as u64, input.len() as u64);
        let expected = compute_tag(&self.cipher, &j0, &ghash_out);

        // Constant-time tag comparison
        if &expected == tag {
            let mut ctr = Ctr::new(&j0);
            ctr.process(&self.cipher, input, output);
            DecryptionResult::Match
        } else {
            DecryptionResult::MisMatch
        }
    }
}

impl Drop for AesGcm256 {
    fn drop(&mut self) {
        self.h = [0u8; 16];
    }
}

enum Cipher {
    /// AES-128 cipher
    Aes128(Aes128),
    /// AES-256 cipher
    Aes256(Aes256),
}

impl BlockEncryptor for Cipher {
    fn encrypt_block(&self, input: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        match self {
            Cipher::Aes128(c) => c.encrypt_block(input),
            Cipher::Aes256(c) => c.encrypt_block(input),
        }
    }

    fn encrypt_blocks(
        &self,
        blocks: &[[u8; BLOCK_BYTES]; PARALLEL_BLOCKS],
    ) -> [[u8; BLOCK_BYTES]; PARALLEL_BLOCKS] {
        match self {
            Cipher::Aes128(c) => c.encrypt_blocks(blocks),
            Cipher::Aes256(c) => c.encrypt_blocks(blocks),
        }
    }
}

/// Apply the counter mode to `data` in place.
///
/// `Ctr::process` needs distinct input and output, so the data goes through a
/// stack buffer, one full group of blocks at a time to keep the multi-block
/// cipher path in use. CTR is symmetric, so this serves both directions; only
/// the order relative to GHASH differs, and that is up to the caller.
fn process_mut(ctr: &mut Ctr, cipher: &Cipher, data: &mut [u8]) {
    let mut tmp = [0u8; BLOCK_BYTES * PARALLEL_BLOCKS];
    for chunk in data.chunks_mut(tmp.len()) {
        let tmp = &mut tmp[..chunk.len()];
        ctr.process(cipher, chunk, tmp);
        chunk.copy_from_slice(tmp);
    }
}

/// AES-GCM incremental context -- add authenticated data before transitioning to encryption or decryption.
///
/// Created via AES128 based [`Context::new128`] or AES256 based [`Context::new256`].
///
/// Feed authenticated data (AAD) with [`Context::add_data`], then call
/// [`Context::to_encryption`] or [`Context::to_decryption`] to transition
/// to the ciphered data processing phase.
///
/// # Examples
///
/// ```
/// use cryptoxide::aes_gcm;
///
/// let key = [0u8; 16];
/// let nonce = [0u8; 12];
/// let mut ctx = aes_gcm::Context::new128(&key, &nonce);
/// ctx.add_data(b"authenticated data");
/// let enc_ctx = ctx.to_encryption();
/// ```
pub struct Context {
    ghash: GHash,
    ctr: Ctr,
    cipher: Cipher,
    j0: [u8; 16],
    aad_len: u64,
}

impl Context {
    /// Create a new AES-GCM incremental context backed by AES128 using the specified key and nonce
    pub fn new128(key: &[u8; 16], nonce: &[u8; 12]) -> Self {
        let j0 = make_j0(nonce);
        let cipher = Aes128::new(key);
        let h = cipher.encrypt_block(&[0u8; BLOCK_BYTES]);
        Context {
            ghash: GHash::new(&h),
            ctr: Ctr::new(&j0),
            cipher: Cipher::Aes128(cipher),
            j0,
            aad_len: 0,
        }
    }

    /// Create a new AES-GCM incremental context backed by AES256 using the specified key and nonce
    pub fn new256(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let j0 = make_j0(nonce);
        let cipher = Aes256::new(key);
        let h = cipher.encrypt_block(&[0u8; 16]);
        Context {
            ghash: GHash::new(&h),
            ctr: Ctr::new(&j0),
            cipher: Cipher::Aes256(cipher),
            j0,
            aad_len: 0,
        }
    }

    /// Add authenticated data (AAD) to the context.
    ///
    /// This can be called multiple times to incrementally feed AAD.
    /// All AAD must be added before transitioning to encryption or decryption.
    pub fn add_data(&mut self, aad: &[u8]) {
        self.ghash.update(aad);
        self.aad_len += aad.len() as u64;
    }

    /// Finish the AAD phase and transition to encryption.
    ///
    /// After calling this method, use [`ContextEncryption::encrypt`] to
    /// encrypt data incrementally, then [`ContextEncryption::finalize`]
    /// to obtain the authentication tag.
    pub fn to_encryption(mut self) -> ContextEncryption {
        self.ghash.pad();
        ContextEncryption {
            ghash: self.ghash,
            ctr: self.ctr,
            cipher: self.cipher,
            j0: self.j0,
            aad_len: self.aad_len,
            ct_len: 0,
        }
    }

    /// Finish the AAD phase and transition to decryption.
    ///
    /// After calling this method, use [`ContextDecryption::decrypt`] to
    /// decrypt data incrementally, then [`ContextDecryption::finalize`]
    /// to verify the authentication tag.
    pub fn to_decryption(mut self) -> ContextDecryption {
        self.ghash.pad();
        ContextDecryption {
            ghash: self.ghash,
            ctr: self.ctr,
            cipher: self.cipher,
            j0: self.j0,
            aad_len: self.aad_len,
            ct_len: 0,
        }
    }
}

/// AES-GCM incremental encryption context.
///
/// Obtained by calling [`Context::to_encryption`]. Encrypts data incrementally
/// and accumulates the authentication state. Call [`ContextEncryption::finalize`]
/// to produce the authentication tag.
pub struct ContextEncryption {
    ghash: GHash,
    ctr: Ctr,
    cipher: Cipher,
    j0: [u8; 16],
    aad_len: u64,
    ct_len: u64,
}

impl ContextEncryption {
    /// Encrypt the input slice to the output slice.
    ///
    /// The ciphertext written to `output` is also fed into GHASH for
    /// authentication. This can be called multiple times.
    ///
    /// # Panics
    ///
    /// Panics if `input.len() != output.len()`.
    pub fn encrypt(&mut self, input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), output.len());
        self.ctr.process(&self.cipher, input, output);
        // Feed ciphertext to GHASH
        self.ghash.update(output);
        self.ct_len += output.len() as u64;
    }

    /// Encrypt data in place.
    ///
    /// The buffer is encrypted and the resulting ciphertext is fed into
    /// GHASH for authentication. This can be called multiple times.
    pub fn encrypt_mut(&mut self, data: &mut [u8]) {
        process_mut(&mut self.ctr, &self.cipher, data);
        // Feed ciphertext to GHASH
        self.ghash.update(data);
        self.ct_len += data.len() as u64;
    }

    /// Finalize the encryption context and return the authentication tag.
    ///
    /// Completes the GHASH computation with the length block and encrypts
    /// the result with AES(J0) to produce the final tag.
    #[must_use]
    pub fn finalize(self) -> Tag {
        let ghash_out = self.ghash.finalize(self.aad_len, self.ct_len);
        compute_tag(&self.cipher, &self.j0, &ghash_out)
    }
}

/// AES-GCM incremental decryption context.
///
/// Obtained by calling [`Context::to_decryption`]. Decrypts data incrementally
/// and accumulates the authentication state. Call [`ContextDecryption::finalize`]
/// to verify the authentication tag.
pub struct ContextDecryption {
    ghash: GHash,
    ctr: Ctr,
    cipher: Cipher,
    j0: [u8; 16],
    aad_len: u64,
    ct_len: u64,
}

impl ContextDecryption {
    /// Decrypt the input slice to the output slice.
    ///
    /// The input (ciphertext) is fed into GHASH **before** CTR decryption,
    /// ensuring authentication is computed over ciphertext, not plaintext
    /// (encrypt-then-MAC order).
    ///
    /// # Panics
    ///
    /// Panics if `input.len() != output.len()`.
    pub fn decrypt(&mut self, input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), output.len());
        // Feed ciphertext to GHASH FIRST (before decryption)
        self.ghash.update(input);
        self.ct_len += input.len() as u64;
        // Then CTR decrypt
        self.ctr.process(&self.cipher, input, output);
    }

    /// Decrypt data in place.
    ///
    /// The original ciphertext is fed into GHASH before being decrypted.
    /// A copy of the ciphertext is made internally to preserve the
    /// authentication input.
    pub fn decrypt_mut(&mut self, data: &mut [u8]) {
        // Feed ciphertext to GHASH FIRST
        self.ghash.update(data);
        self.ct_len += data.len() as u64;
        // Then CTR decrypt in place
        process_mut(&mut self.ctr, &self.cipher, data);
    }

    /// Finalize the decryption context and verify the authentication tag.
    ///
    /// Computes the expected tag and compares it with the provided tag
    /// using constant-time comparison. Returns [`DecryptionResult::Match`]
    /// if the tag is valid, [`DecryptionResult::MisMatch`] otherwise.
    #[must_use = "if the result is not checked, the encrypted data is not authenticated"]
    pub fn finalize(self, expected_tag: &Tag) -> DecryptionResult {
        let ghash_out = self.ghash.finalize(self.aad_len, self.ct_len);
        let computed = compute_tag(&self.cipher, &self.j0, &ghash_out);
        if &computed == expected_tag {
            DecryptionResult::Match
        } else {
            DecryptionResult::MisMatch
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NIST SP 800-38D Test Case 1: AES-128-GCM, empty plaintext, empty AAD
    #[test]
    fn test_aes128_gcm_nist_test_case_1() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let cipher = AesGcm128::new(&key);

        let mut tag = Tag([0u8; 16]);
        cipher.encrypt(&nonce, &[], &[], &mut [], &mut tag);

        let expected_tag: [u8; 16] = [
            0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
            0x45, 0x5a,
        ];
        assert_eq!(tag.0, expected_tag, "NIST Test Case 1 tag mismatch");
    }

    // NIST SP 800-38D Test Case 2: AES-128-GCM, 16-byte plaintext, empty AAD
    #[test]
    fn test_aes128_gcm_nist_test_case_2() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = [0u8; 16];
        let cipher = AesGcm128::new(&key);

        let mut ciphertext = [0u8; 16];
        let mut tag = Tag([0u8; 16]);
        cipher.encrypt(&nonce, &[], &plaintext, &mut ciphertext, &mut tag);

        let expected_ct: [u8; 16] = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78,
        ];
        let expected_tag: [u8; 16] = [
            0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
            0xbd, 0xdf,
        ];
        assert_eq!(
            ciphertext, expected_ct,
            "NIST Test Case 2 ciphertext mismatch"
        );
        assert_eq!(tag.0, expected_tag, "NIST Test Case 2 tag mismatch");
    }

    const KEY128_TEST_VECTOR: [u8; 16] = [
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83,
        0x08,
    ];
    const KEY256_TEST_VECTOR: [u8; 32] = [
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83,
        0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
        0x83, 0x08,
    ];
    const NONCE_TEST_VECTOR: [u8; 12] = [
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
    ];
    const AAD_TEST_VECTOR: [u8; 20] = [
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
        0xef, 0xab, 0xad, 0xda, 0xd2,
    ];

    // NIST SP 800-38D Test Case 3: AES-128-GCM, 64-byte plaintext, empty AAD
    #[test]
    fn test_aes128_gcm_nist_test_case_3() {
        let key = KEY128_TEST_VECTOR;
        let nonce = NONCE_TEST_VECTOR;
        let plaintext: [u8; 64] = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55,
        ];
        let cipher = AesGcm128::new(&key);
        let mut ciphertext = [0u8; 64];
        let mut tag = Tag([0u8; 16]);
        cipher.encrypt(&nonce, &[], &plaintext, &mut ciphertext, &mut tag);

        let expected_ct: [u8; 64] = [
            0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0,
            0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23,
            0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f,
            0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
            0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f, 0x59, 0x85,
        ];
        let expected_tag: [u8; 16] = [
            0x4d, 0x5c, 0x2a, 0xf3, 0x27, 0xcd, 0x64, 0xa6, 0x2c, 0xf3, 0x5a, 0xbd, 0x2b, 0xa6,
            0xfa, 0xb4,
        ];
        assert_eq!(
            &ciphertext[..],
            &expected_ct[..],
            "NIST Test Case 3 ciphertext mismatch"
        );
        assert_eq!(tag.0, expected_tag, "NIST Test Case 3 tag mismatch");
    }

    // NIST SP 800-38D Test Case 4: AES-128-GCM, 60-byte plaintext, 20-byte AAD
    #[test]
    fn test_aes128_gcm_nist_test_case_4() {
        let key = KEY128_TEST_VECTOR;
        let nonce = NONCE_TEST_VECTOR;
        let plaintext: [u8; 60] = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39,
        ];
        let aad: [u8; 20] = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
            0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2,
        ];
        let cipher = AesGcm128::new(&key);
        let mut ciphertext = [0u8; 60];
        let mut tag = Tag([0u8; 16]);
        cipher.encrypt(&nonce, &aad, &plaintext, &mut ciphertext, &mut tag);

        let expected_ct: [u8; 60] = [
            0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0,
            0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23,
            0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f,
            0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
            0x3d, 0x58, 0xe0, 0x91,
        ];
        let expected_tag: [u8; 16] = [
            0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12,
            0x1a, 0x47,
        ];
        assert_eq!(
            &ciphertext[..],
            &expected_ct[..],
            "NIST Test Case 4 ciphertext mismatch"
        );
        assert_eq!(tag.0, expected_tag, "NIST Test Case 4 tag mismatch");
    }

    // Decrypt round-trip test
    #[test]
    fn test_aes128_gcm_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let aad = b"some aad";
        let plaintext = b"Hello, AES-GCM world!";
        let cipher = AesGcm128::new(&key);

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = Tag([0u8; 16]);
        cipher.encrypt(&nonce, aad, plaintext, &mut ct, &mut tag);

        let mut pt = vec![0u8; plaintext.len()];
        let result = cipher.decrypt(&nonce, aad, &ct, &mut pt, &tag);
        assert_eq!(result, DecryptionResult::Match);
        assert_eq!(&pt[..], &plaintext[..]);
    }

    // Tampered ciphertext should produce MisMatch
    #[test]
    fn test_aes128_gcm_tampered_ciphertext() {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret message";
        let cipher = AesGcm128::new(&key);

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = Tag([0u8; 16]);
        cipher.encrypt(&nonce, &[], plaintext, &mut ct, &mut tag);

        // Tamper with ciphertext
        ct[0] ^= 0x01;

        let mut pt = vec![0u8; plaintext.len()];
        let result = cipher.decrypt(&nonce, &[], &ct, &mut pt, &tag);
        assert_eq!(result, DecryptionResult::MisMatch);
    }

    // AES-256-GCM basic round-trip
    #[test]
    fn test_aes256_gcm_encrypt_decrypt_roundtrip() {
        let key = [0xab; 32];
        let nonce = [0xcd; 12];
        let aad = b"aes-256-gcm aad";
        let plaintext = b"AES-256-GCM test data";
        let cipher = AesGcm256::new(&key);

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = Tag([0u8; 16]);
        cipher.encrypt(&nonce, aad, plaintext, &mut ct, &mut tag);

        let mut pt = vec![0u8; plaintext.len()];
        let result = cipher.decrypt(&nonce, aad, &ct, &mut pt, &tag);
        assert_eq!(result, DecryptionResult::Match);
        assert_eq!(&pt[..], &plaintext[..]);
    }

    // Incremental API round-trip
    #[test]
    fn test_incremental_encrypt_decrypt() {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];

        // Encrypt incrementally
        let mut ctx = Context::new128(&key, &nonce);
        ctx.add_data(b"aad1");
        ctx.add_data(b"aad2");
        let mut enc_ctx = ctx.to_encryption();
        let mut ct = [0u8; 11];
        enc_ctx.encrypt(b"hello", &mut ct[..5]);
        enc_ctx.encrypt(b" world", &mut ct[5..11]);
        let tag = enc_ctx.finalize();

        // Decrypt incrementally
        let mut ctx2 = Context::new128(&key, &nonce);
        ctx2.add_data(b"aad1");
        ctx2.add_data(b"aad2");
        let mut dec_ctx = ctx2.to_decryption();
        let mut pt = [0u8; 11];
        dec_ctx.decrypt(&ct[..5], &mut pt[..5]);
        dec_ctx.decrypt(&ct[5..], &mut pt[5..]);
        let result = dec_ctx.finalize(&tag);
        assert_eq!(result, DecryptionResult::Match);
        assert_eq!(&pt[..], b"hello world");
    }

    // Incremental matches one-shot
    #[test]
    fn test_incremental_matches_oneshot() {
        let key = [0x99u8; 16];
        let nonce = [0x11u8; 12];
        let aad = b"test aad";
        let plaintext = b"incremental vs oneshot";

        // One-shot
        let mut ct_oneshot = vec![0u8; plaintext.len()];
        let mut tag_oneshot = Tag([0u8; 16]);
        let cipher = AesGcm128::new(&key);
        cipher.encrypt(&nonce, aad, plaintext, &mut ct_oneshot, &mut tag_oneshot);

        // Incremental
        let mut ctx = Context::new128(&key, &nonce);
        ctx.add_data(aad);
        let mut enc_ctx = ctx.to_encryption();
        let mut ct_inc = vec![0u8; plaintext.len()];
        enc_ctx.encrypt(plaintext, &mut ct_inc);
        let tag_inc = enc_ctx.finalize();

        assert_eq!(
            ct_oneshot, ct_inc,
            "Ciphertext should match between one-shot and incremental"
        );
        assert_eq!(
            tag_oneshot, tag_inc,
            "Tag should match between one-shot and incremental"
        );
    }

    /// The in-place interface must agree with the copying one, whatever the
    /// chunking: `process_mut` goes through a fixed-size stack buffer, so the
    /// chunk boundaries it introduces must not shift the keystream.
    #[test]
    fn test_in_place_matches_oneshot() {
        let key = [0x77u8; 16];
        let nonce = [0x33u8; 12];
        let aad = b"in place aad";
        let plaintext: [u8; 293] = core::array::from_fn(|i| ((i * 13 + 7) & 0xff) as u8);

        // Reference: one-shot encrypt into a separate output buffer.
        let cipher = AesGcm128::new(&key);
        let mut expected_ct = [0u8; 293];
        let mut expected_tag = Tag([0u8; 16]);
        cipher.encrypt(&nonce, aad, &plaintext, &mut expected_ct, &mut expected_tag);

        for chunk in [1, 15, 16, 17, 63, 64, 65, 293] {
            let mut ctx = Context::new128(&key, &nonce);
            ctx.add_data(aad);
            let mut enc = ctx.to_encryption();
            let mut data = plaintext;
            for part in data.chunks_mut(chunk) {
                enc.encrypt_mut(part);
            }
            let tag = enc.finalize();
            assert_eq!(data, expected_ct, "ciphertext, {chunk}-byte chunks");
            assert_eq!(tag, expected_tag, "tag, {chunk}-byte chunks");

            // And decrypting it in place gives the plaintext back.
            let mut ctx = Context::new128(&key, &nonce);
            ctx.add_data(aad);
            let mut dec = ctx.to_decryption();
            for part in data.chunks_mut(chunk) {
                dec.decrypt_mut(part);
            }
            assert_eq!(dec.finalize(&tag), DecryptionResult::Match);
            assert_eq!(data, plaintext, "plaintext, {chunk}-byte chunks");
        }
    }

    /// Every message length across the multi-block, single-block and partial
    /// paths of the counter mode has to round-trip and to match the incremental
    /// interface byte for byte.
    #[test]
    fn test_all_lengths_round_trip() {
        let key = [0x24u8; 32];
        let nonce = [0x68u8; 12];
        let cipher = AesGcm256::new(&key);

        let mut plaintext = [0u8; 8 * 16 + 3];
        plaintext
            .iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b = (i * 31 + 17) as u8);

        for len in 0..plaintext.len() {
            let plaintext = &plaintext[..len];
            let mut ct = vec![0u8; len];
            let mut tag = Tag([0u8; 16]);
            cipher.encrypt(&nonce, &[], plaintext, &mut ct, &mut tag);

            let mut ctx = Context::new256(&key, &nonce).to_encryption();
            let mut ct_incr = vec![0u8; len];
            ctx.encrypt(plaintext, &mut ct_incr);
            assert_eq!(ct, ct_incr, "incremental ciphertext at {len} bytes");
            assert_eq!(ctx.finalize(), tag, "incremental tag at {len} bytes");

            let mut recovered = vec![0u8; len];
            let result = cipher.decrypt(&nonce, &[], &ct, &mut recovered, &tag);
            assert_eq!(result, DecryptionResult::Match, "at {len} bytes");
            assert_eq!(&recovered[..], plaintext, "at {len} bytes");
        }
    }

    // ============================================================
    // AES-256-GCM NIST SP 800-38D Test Vector

    // NIST SP 800-38D Test Case 14 (AES-256-GCM): 60-byte plaintext with 20-byte AAD
    #[test]
    fn test_aes256_gcm_with_aad() {
        let key = KEY256_TEST_VECTOR;
        let nonce = NONCE_TEST_VECTOR;
        let pt = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39,
        ];
        let aad = AAD_TEST_VECTOR;
        let expected_ct = [
            0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84,
            0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd,
            0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0,
            0x8b, 0x10, 0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
            0xbc, 0xc9, 0xf6, 0x62,
        ];
        let expected_tag = [
            0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d,
            0x55, 0x1b,
        ];

        let key_arr: [u8; 32] = key.try_into().unwrap();
        let nonce_arr: [u8; 12] = nonce.try_into().unwrap();
        let cipher = AesGcm256::new(&key_arr);

        let mut ct = vec![0u8; pt.len()];
        let mut tag = Tag([0u8; 16]);
        cipher.encrypt(&nonce_arr, &aad, &pt, &mut ct, &mut tag);

        assert_eq!(
            &ct[..],
            &expected_ct[..],
            "AES-256-GCM Test Case 14 ciphertext mismatch"
        );
        assert_eq!(
            &tag.0[..],
            &expected_tag[..],
            "AES-256-GCM Test Case 14 tag mismatch"
        );

        // Decrypt and verify
        let mut recovered = vec![0u8; pt.len()];
        let result = cipher.decrypt(&nonce_arr, &aad, &ct, &mut recovered, &tag);
        assert_eq!(result, DecryptionResult::Match);
        assert_eq!(&recovered[..], &pt[..]);
    }

    // ============================================================
    // Additional authentication verification tests
    // ============================================================

    #[test]
    fn test_tampered_tag_rejected() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let pt = [0u8; 16];
        let cipher = AesGcm128::new(&key);

        let mut ct = [0u8; 16];
        let mut tag = Tag([0u8; 16]);
        cipher.encrypt(&nonce, &[], &pt, &mut ct, &mut tag);

        // Tamper with tag
        let bad_tag = Tag({
            let mut t = tag.0;
            t[0] ^= 0x01;
            t
        });
        let mut recovered = [0u8; 16];
        let result = cipher.decrypt(&nonce, &[], &ct, &mut recovered, &bad_tag);
        assert_eq!(result, DecryptionResult::MisMatch);
    }

    #[test]
    fn test_wrong_key_rejected() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let pt = [0u8; 16];
        let cipher = AesGcm128::new(&key);

        let mut ct = [0u8; 16];
        let mut tag = Tag([0u8; 16]);
        cipher.encrypt(&nonce, &[], &pt, &mut ct, &mut tag);

        // Decrypt with different key
        let wrong_key = [1u8; 16];
        let wrong_cipher = AesGcm128::new(&wrong_key);
        let mut recovered = [0u8; 16];
        let result = wrong_cipher.decrypt(&nonce, &[], &ct, &mut recovered, &tag);
        assert_eq!(result, DecryptionResult::MisMatch);
    }

    // ============================================================
    // NIST test vector hex-string format acceptance criteria tests
    // ============================================================

    // Verify Test Case 1 tag: 58e2fccefa7e3061367f1d57a4e7455a
    #[test]
    fn test_aes128_gcm_empty() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let cipher = AesGcm128::new(&key);

        let mut ct = [];
        let mut tag = Tag([0u8; 16]);
        cipher.encrypt(&nonce, &[], &[], &mut ct, &mut tag);

        let expected_tag = [
            0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
            0x45, 0x5a,
        ];
        assert_eq!(&tag.0[..], &expected_tag[..]);
    }

    // Verify Test Case 2 with decrypt round-trip
    #[test]
    fn test_aes128_gcm_16byte() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let pt = [0u8; 16];
        let cipher = AesGcm128::new(&key);

        let mut ct = [0u8; 16];
        let mut tag = Tag([0u8; 16]);
        cipher.encrypt(&nonce, &[], &pt, &mut ct, &mut tag);

        let expected_ct = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78,
        ];
        let expected_tag = [
            0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
            0xbd, 0xdf,
        ];
        assert_eq!(&ct[..], &expected_ct[..]);
        assert_eq!(&tag.0[..], &expected_tag[..]);

        // Decrypt and verify
        let mut recovered = [0u8; 16];
        let result = cipher.decrypt(&nonce, &[], &ct, &mut recovered, &tag);
        assert_eq!(result, DecryptionResult::Match);
        assert_eq!(&recovered[..], &pt[..]);
    }

    // Verify Test Case 4 tag: 5bc94fbc3221a5db94fae95ae7121a47
    #[test]
    fn test_aes128_gcm_with_aad() {
        let key = KEY128_TEST_VECTOR;
        let nonce = NONCE_TEST_VECTOR;
        let pt = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39,
        ];
        let aad = AAD_TEST_VECTOR;
        let expected_ct = [
            0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0,
            0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23,
            0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f,
            0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
            0x3d, 0x58, 0xe0, 0x91,
        ];
        let expected_tag = [
            0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12,
            0x1a, 0x47,
        ];

        let key_arr: [u8; 16] = key.try_into().unwrap();
        let nonce_arr: [u8; 12] = nonce.try_into().unwrap();
        let cipher = AesGcm128::new(&key_arr);

        let mut ct = vec![0u8; pt.len()];
        let mut tag = Tag([0u8; 16]);
        cipher.encrypt(&nonce_arr, &aad, &pt, &mut ct, &mut tag);

        assert_eq!(&ct[..], &expected_ct[..]);
        assert_eq!(&tag.0[..], &expected_tag[..]);

        // Decrypt and verify
        let mut recovered = vec![0u8; pt.len()];
        let result = cipher.decrypt(&nonce_arr, &aad, &ct, &mut recovered, &tag);
        assert_eq!(result, DecryptionResult::Match);
        assert_eq!(&recovered[..], &pt[..]);
    }

    // ============================================================
    // Incremental vs one-shot with NIST vectors
    // ============================================================

    #[test]
    fn test_incremental_matches_oneshot_nist() {
        let key = KEY128_TEST_VECTOR;
        let nonce = NONCE_TEST_VECTOR;
        let pt = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39,
        ];
        let aad = AAD_TEST_VECTOR;

        let key_arr: [u8; 16] = key.try_into().unwrap();
        let nonce_arr: [u8; 12] = nonce.try_into().unwrap();

        // One-shot encrypt
        let mut ct_oneshot = vec![0u8; pt.len()];
        let mut tag_oneshot = Tag([0u8; 16]);
        let cipher = AesGcm128::new(&key_arr);
        cipher.encrypt(&nonce_arr, &aad, &pt, &mut ct_oneshot, &mut tag_oneshot);

        // Incremental encrypt (split AAD and plaintext into chunks)
        let mut ctx = Context::new128(&key_arr, &nonce_arr);
        ctx.add_data(&aad[..10]);
        ctx.add_data(&aad[10..]);
        let mut enc = ctx.to_encryption();
        let mut ct_incr = vec![0u8; pt.len()];
        enc.encrypt(&pt[..20], &mut ct_incr[..20]);
        enc.encrypt(&pt[20..], &mut ct_incr[20..]);
        let tag_incr = enc.finalize();

        assert_eq!(&ct_oneshot[..], &ct_incr[..]);
        assert_eq!(tag_oneshot, tag_incr);

        // Incremental decrypt
        let mut ctx = Context::new128(&key_arr, &nonce_arr);
        ctx.add_data(&aad);
        let mut dec = ctx.to_decryption();
        let mut pt_incr = vec![0u8; pt.len()];
        dec.decrypt(&ct_oneshot[..30], &mut pt_incr[..30]);
        dec.decrypt(&ct_oneshot[30..], &mut pt_incr[30..]);
        let result = dec.finalize(&tag_oneshot);
        assert_eq!(result, DecryptionResult::Match);
        assert_eq!(&pt_incr[..], &pt[..]);
    }
}

#[cfg(all(test, feature = "with-bench"))]
mod bench {
    use super::*;
    use test::Bencher;

    fn bench_encrypt(bh: &mut Bencher, size: usize) {
        let key = [1u8; 16];
        let nonce = [2u8; 12];
        let cipher = AesGcm128::new(&key);
        let input = vec![3u8; size];
        let mut output = vec![0u8; size];
        let mut tag = Tag([0u8; 16]);
        bh.iter(|| {
            cipher.encrypt(&nonce, &[], &input, &mut output, &mut tag);
        });
        bh.bytes = size as u64;
    }

    #[bench]
    pub fn aes128_gcm_encrypt_64(bh: &mut Bencher) {
        bench_encrypt(bh, 64);
    }

    #[bench]
    pub fn aes128_gcm_encrypt_256(bh: &mut Bencher) {
        bench_encrypt(bh, 256);
    }

    #[bench]
    pub fn aes128_gcm_encrypt_1k(bh: &mut Bencher) {
        bench_encrypt(bh, 1024);
    }

    #[bench]
    pub fn aes128_gcm_encrypt_64k(bh: &mut Bencher) {
        bench_encrypt(bh, 65536);
    }
}
