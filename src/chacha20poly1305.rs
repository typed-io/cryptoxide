//! ChaCha20Poly1305 is an authenticated symmetric stream cipher based on chacha20 and poly1305.
//!
//! the specification of chacha20poly1305 is available at [RFC8439][1] and it follows general principle related to [AEAD][2].
//!
//! This module provides 2 interfaces:
//!
//! * the one shot interface [`ChaCha20Poly1305`]
//! * the incremental interfaces, using [`Context`], [`ContextEncryption`] and [`ContextDecryption`]
//!
//! The incremental interfaces should be used when you are streaming data or that
//! you need more control over the memory usage, as the one-shot interface
//! expects one single call with slices parameter.
//!
//! # Examples
//!
//! Encrypting using the one-shot interface:
//!
//! ```
//! use cryptoxide::chacha20poly1305::ChaCha20Poly1305;
//!
//! let key : [u8; 16] = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
//! let nonce : [u8; 8] = [1,2,3,4,5,6,7,8];
//! let aad : [u8; 0] = [];
//! let input : &[u8; 12] = b"hello world!";
//! let mut out : [u8; 12+16] = [0u8; 12+16];
//! let mut tag : [u8; 16] = [0u8; 16];
//!
//! // create a new cipher
//! let mut cipher = ChaCha20Poly1305::new(&key, &nonce, &aad);
//!
//! // encrypt the msg and append the tag at the end
//! cipher.encrypt(input, &mut out[0..12], &mut tag);
//! out[12..].copy_from_slice(&tag);
//! ```
//!
//! Encrypting using the incremental interfaces:
//!
//! ```
//! use cryptoxide::chacha20poly1305::Context;
//!
//! let key : [u8; 16] = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
//! let nonce : [u8; 8] = [1,2,3,4,5,6,7,8];
//! let mut context = Context::<20>::new(&key, &nonce);
//!
//! // Add incrementally 2 slices of data
//! context.add_data(b"authenticated");
//! context.add_data(b"data");
//!
//! let mut encrypted_input = [0u8; 10+16];
//! let mut context = context.to_encryption();
//!
//! // Encrypt incrementally 2 slices and append the encrypted data to the output buffer
//! context.encrypt(b"hello", &mut encrypted_input[0..5]);
//! context.encrypt(b"world", &mut encrypted_input[5..10]);
//!
//! // Finalize the context, and append the tag to the end of the output buffer
//! let tag = context.finalize();
//! encrypted_input[10..26].copy_from_slice(&tag.0);
//! ```
//!
//! [1]: https://tools.ietf.org/html/rfc8439
//! [2]: https://en.wikipedia.org/wiki/Authenticated_encryption

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::chacha20::ChaCha;
use crate::constant_time::{Choice, CtEqual};
use crate::cryptoutil::write_u64_le;
use crate::mac::Mac;
use crate::poly1305::Poly1305;

/// Chacha20Poly1305 Incremental Context for Authenticated Data (AAD)
///
/// The initial context set the key and nonce, and the authenticated data (if any),
/// then it needs to converted either to a [`ContextEncryption`] or [`ContextDecryption`]
/// using the [`Context::to_encryption`] or [`Context::to_decryption`] methods (respectively).
///
/// ```
/// use cryptoxide::chacha20poly1305::Context;
///
/// let key : [u8; 16] = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
/// let nonce : [u8; 8] = [1,2,3,4,5,6,7,8];
/// let mut context = Context::<20>::new(&key, &nonce);
///
/// // Add incrementally 2 slices of data
/// context.add_data(b"authenticated");
/// context.add_data(b"data");
///
/// let mut encrypted_input = [0u8; 10+16];
/// let mut context = context.to_encryption();
///
/// // Encrypt incrementally 2 slices and append the encrypted data to the output buffer
/// context.encrypt(b"hello", &mut encrypted_input[0..5]);
/// context.encrypt(b"world", &mut encrypted_input[5..10]);
///
/// // Finalize the context, and append the tag to the end of the output buffer
/// let tag = context.finalize();
/// encrypted_input[10..26].copy_from_slice(&tag.0);
/// ```
#[derive(Clone)]
pub struct Context<const ROUNDS: usize> {
    cipher: ChaCha<ROUNDS>,
    mac: Poly1305,
    aad_len: u64,
    data_len: u64,
}

/// ChaCha20Poly1305 Incremental Context for encryption
#[derive(Clone)]
pub struct ContextEncryption<const ROUNDS: usize>(Context<ROUNDS>);

/// ChaCha20Poly1305 Incremental Context for decryption
#[derive(Clone)]
pub struct ContextDecryption<const ROUNDS: usize>(Context<ROUNDS>);

/// ChaCha20Poly1305 Authenticated Tag (128 bits)
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

impl<const ROUNDS: usize> Context<ROUNDS> {
    /// Create a new context given the key and nonce.
    ///
    /// ```
    /// use cryptoxide::chacha20poly1305::Context;
    ///
    /// let key : [u8; 16] = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
    /// let nonce : [u8; 8] = [1,2,3,4,5,6,7,8];
    /// let context = Context::<20>::new(&key, &nonce);
    /// ```
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        assert!(key.len() == 16 || key.len() == 32);
        assert!(nonce.len() == 8 || nonce.len() == 12);
        let mut cipher = ChaCha::new(key, nonce);
        let mut mac_key = [0u8; 64];
        let zero_key = [0u8; 64];
        cipher.process(&zero_key, &mut mac_key);

        let mac = Poly1305::new(&mac_key[..32]);
        Context {
            cipher: cipher,
            mac: mac,
            aad_len: 0,
            data_len: 0,
        }
    }

    fn add_encrypted(&mut self, encrypted: &[u8]) {
        self.mac.input(encrypted);
        self.data_len += encrypted.len() as u64;
    }

    /// Add Authenticated Data to the MAC Context
    ///
    /// This can be called multiple times
    pub fn add_data(&mut self, aad: &[u8]) {
        self.aad_len += aad.len() as u64;
        self.mac.input(aad);
    }

    /// Finish authenticated part and move to the encryption phase
    pub fn to_encryption(mut self) -> ContextEncryption<ROUNDS> {
        pad16(&mut self.mac, self.aad_len);
        ContextEncryption(self)
    }

    /// Finish authenticated part and move to the decryption phase
    pub fn to_decryption(mut self) -> ContextDecryption<ROUNDS> {
        pad16(&mut self.mac, self.aad_len);
        ContextDecryption(self)
    }
}

fn finalize_raw<const ROUNDS: usize>(inner: &mut Context<ROUNDS>) -> [u8; 16] {
    let mut len_buf = [0u8; 16];
    pad16(&mut inner.mac, inner.data_len);
    write_u64_le(&mut len_buf[0..8], inner.aad_len);
    write_u64_le(&mut len_buf[8..16], inner.data_len);
    inner.mac.input(&len_buf);
    inner.mac.raw_result(&mut len_buf);
    len_buf
}

impl<const ROUNDS: usize> ContextEncryption<ROUNDS> {
    /// Encrypt input in place
    pub fn encrypt_mut(&mut self, buf: &mut [u8]) {
        self.0.cipher.process_mut(buf);
        self.0.add_encrypted(buf);
    }

    /// Encrypt the input slice to the output slice
    ///
    /// The number of bytes written to the output is
    /// equal to the number of bytes as input.
    ///
    /// Panics:
    ///     if input and output are of different size
    pub fn encrypt(&mut self, input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), output.len());
        self.0.cipher.process(input, output);
        self.0.add_encrypted(output);
    }

    /// Finalize the encryption context and return the tag
    #[must_use]
    pub fn finalize(mut self) -> Tag {
        let tag = finalize_raw(&mut self.0);
        Tag(tag)
    }
}

/// Whether or not, the decryption was succesful related to the expected tag
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptionResult {
    Match,
    MisMatch,
}

impl<const ROUNDS: usize> ContextDecryption<ROUNDS> {
    /// Decrypt input in place
    pub fn decrypt_mut(&mut self, buf: &mut [u8]) {
        self.0.add_encrypted(buf);
        self.0.cipher.process_mut(buf);
    }

    /// Decrypt the input to the output slice
    ///
    /// Panics:
    ///     if input and output are of different size
    pub fn decrypt(&mut self, input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), output.len());
        self.0.add_encrypted(input);
        self.0.cipher.process(input, output);
    }

    /// Finalize the decryption context and check that the tag match the expected value
    ///
    #[must_use = "if the result is not checked, then the data will not be verified against tempering"]
    pub fn finalize(mut self, expected_tag: &Tag) -> DecryptionResult {
        let got_tag = Tag(finalize_raw(&mut self.0));
        if &got_tag == expected_tag {
            DecryptionResult::Match
        } else {
            DecryptionResult::MisMatch
        }
    }
}

/// A ChaCha20+Poly1305 Context
#[derive(Clone)]
pub struct ChaChaPoly1305<const ROUNDS: usize> {
    finished: bool,
    context: Context<ROUNDS>,
}

fn pad16(mac: &mut Poly1305, len: u64) {
    if (len % 16) != 0 {
        let padding = [0u8; 15];
        let sz = 16 - (len % 16) as usize;
        mac.input(&padding[0..sz]);
    }
}

pub type ChaCha20Poly1305 = ChaChaPoly1305<20>;

impl<const ROUNDS: usize> ChaChaPoly1305<ROUNDS> {
    /// Create a new ChaCha20Poly1305
    ///
    /// * key needs to be 16 or 32 bytes
    /// * nonce needs to be 8 or 12 bytes
    ///
    pub fn new(key: &[u8], nonce: &[u8], aad: &[u8]) -> Self {
        let mut context = Context::new(key, nonce);
        context.add_data(aad);
        ChaChaPoly1305 {
            context: context,
            finished: false,
        }
    }

    /// Encrypt input buffer to output buffer, and write an authenticated tag to out_tag.
    ///
    /// Output buffer need to be the same size as the input buffer
    /// Out_tag mutable slice need to 16 bytes exactly.
    ///
    /// Example: Encrypt a simple "hello world" message with chacha20poly1305 AEAD
    /// using a 64 bits nonce and a 128 bits keys, and arrange the output data
    /// in the format : ENCRYPTED_MSG | AEAD_TAG
    ///
    /// ```
    /// use cryptoxide::chacha20poly1305::ChaCha20Poly1305;
    ///
    /// let key : [u8; 16] = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
    /// let nonce : [u8; 8] = [1,2,3,4,5,6,7,8];
    /// let aad : [u8; 0] = [];
    /// let input : &[u8; 12] = b"hello world!";
    /// let mut out : [u8; 12+16] = [0u8; 12+16];
    /// let mut tag : [u8; 16] = [0u8; 16];
    ///
    /// // create a new cipher
    /// let mut cipher = ChaCha20Poly1305::new(&key, &nonce, &aad);
    ///
    /// // encrypt the msg and append the tag at the end
    /// cipher.encrypt(input, &mut out[0..12], &mut tag);
    /// out[12..].copy_from_slice(&tag);
    /// ```
    pub fn encrypt(&mut self, input: &[u8], output: &mut [u8], out_tag: &mut [u8]) {
        assert!(input.len() == output.len());
        assert!(!self.finished);
        assert!(out_tag.len() == 16);

        self.finished = true;

        let mut ctx = self.context.clone().to_encryption();
        ctx.encrypt(input, output);

        let Tag(tag) = ctx.finalize();
        out_tag.copy_from_slice(&tag[..])
    }

    /// Decrypt the input to the output buffer
    ///
    /// if the calculated tag during decryption doesn't match
    /// the tag in parameter, then the function return False
    ///
    /// Example: Decrypt a simple message with chacha20poly1305 AEAD
    /// using a 64 bits nonce and a 128 bits keys where the first 12 bytes
    /// are the encrypted message and the tag is the last 16 bytes. if the
    /// cipher message has been tempered, a panic is raised (in the example):
    ///
    /// ```
    /// use cryptoxide::chacha20poly1305::ChaCha20Poly1305;
    ///
    /// let key : [u8; 16] = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
    /// let nonce : [u8; 8] = [1,2,3,4,5,6,7,8];
    /// let aad : [u8; 0] = [];
    /// let ae_msg : [u8; 12+16] = [98, 155, 81, 205, 163, 244, 162, 254, 57, 96, 183,
    ///                             101, 167, 88, 238, 184, 17, 109, 89, 185, 72, 150,
    ///                             97, 95, 149, 82, 179, 220];
    /// let mut decrypt_msg : [u8; 12] = [0u8; 12];
    ///
    /// // create a new cipher
    /// let mut cipher = ChaCha20Poly1305::new(&key, &nonce, &aad);
    ///
    /// // encrypt the msg and append the tag at the end
    /// if !cipher.decrypt(&ae_msg[0..12], &mut decrypt_msg, &ae_msg[12..]) {
    ///     panic!("encrypted message has been tempered")
    /// }
    /// assert_eq!(&decrypt_msg, b"hello world!");
    ///
    /// ```
    pub fn decrypt(&mut self, input: &[u8], output: &mut [u8], tag: &[u8]) -> bool {
        assert!(tag.len() == 16);
        assert!(input.len() == output.len());
        assert!(!self.finished);

        self.finished = true;

        let mut tag_data = [0u8; 16];
        tag_data.copy_from_slice(tag);

        let mut ctx = self.context.clone().to_decryption();

        ctx.decrypt(input, output);
        ctx.finalize(&Tag(tag_data)) == DecryptionResult::Match
    }
}

#[cfg(test)]
mod test {
    use super::ChaCha20Poly1305;

    struct TestVector {
        key: [u8; 32],
        nonce: &'static [u8],
        tag: [u8; 16],
        plain_text: &'static [u8],
        cipher_text: &'static [u8],
        aad: &'static [u8],
    }

    fn test_vector(v: &TestVector) {
        let mut tag = [0u8; 16];
        let mut ciphertext = vec![0u8; v.cipher_text.len()];

        let mut context = ChaCha20Poly1305::new(&v.key, &v.nonce, &v.aad);
        let mut dcontext = context.clone();

        // test encryption
        context.encrypt(&v.plain_text, &mut ciphertext, &mut tag[..]);

        assert_eq!(&ciphertext[..], &v.cipher_text[..]);
        assert_eq!(&tag[..], &v.tag[..]);

        // test decryption
        let mut output = vec![0u8; v.plain_text.len()];
        assert_eq!(dcontext.decrypt(&ciphertext, &mut output, &v.tag[..]), true);

        assert_eq!(&output[..], &v.plain_text[..]);
    }

    #[test]
    fn test_vectors() {
        let tests = [
            // RFC 7539 section 2.8.2.
            TestVector {
                key: [
                    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c,
                    0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
                    0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
                ],
                nonce: &[
                    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                ],
                plain_text: &[
                    0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65,
                    0x6e, 0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68,
                    0x65, 0x20, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39,
                    0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64,
                    0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, 0x6e,
                    0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f,
                    0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c,
                    0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
                    0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69, 0x74, 0x2e,
                ],
                aad: &[
                    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
                ],
                cipher_text: &[
                    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53,
                    0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2,
                    0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67,
                    0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a,
                    0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92,
                    0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09,
                    0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80,
                    0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
                    0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
                ],
                tag: [
                    0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0,
                    0x60, 0x06, 0x91,
                ],
            },
            // RFC 7539 section A.5.
            TestVector {
                key: [
                    0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04,
                    0xf6, 0xb5, 0xf0, 0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca,
                    0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
                ],
                nonce: &[
                    0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                ],
                tag: [
                    0xee, 0xad, 0x9d, 0x67, 0x89, 0x0c, 0xbb, 0x22, 0x39, 0x23, 0x36, 0xfe, 0xa1,
                    0x85, 0x1f, 0x38,
                ],
                plain_text: &[
                    0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2d, 0x44, 0x72, 0x61, 0x66,
                    0x74, 0x73, 0x20, 0x61, 0x72, 0x65, 0x20, 0x64, 0x72, 0x61, 0x66, 0x74, 0x20,
                    0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x20, 0x76, 0x61, 0x6c,
                    0x69, 0x64, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x61, 0x20, 0x6d, 0x61, 0x78, 0x69,
                    0x6d, 0x75, 0x6d, 0x20, 0x6f, 0x66, 0x20, 0x73, 0x69, 0x78, 0x20, 0x6d, 0x6f,
                    0x6e, 0x74, 0x68, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x6d, 0x61, 0x79, 0x20,
                    0x62, 0x65, 0x20, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x2c, 0x20, 0x72,
                    0x65, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x64, 0x2c, 0x20, 0x6f, 0x72, 0x20, 0x6f,
                    0x62, 0x73, 0x6f, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x6f,
                    0x74, 0x68, 0x65, 0x72, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74,
                    0x73, 0x20, 0x61, 0x74, 0x20, 0x61, 0x6e, 0x79, 0x20, 0x74, 0x69, 0x6d, 0x65,
                    0x2e, 0x20, 0x49, 0x74, 0x20, 0x69, 0x73, 0x20, 0x69, 0x6e, 0x61, 0x70, 0x70,
                    0x72, 0x6f, 0x70, 0x72, 0x69, 0x61, 0x74, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x75,
                    0x73, 0x65, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2d, 0x44,
                    0x72, 0x61, 0x66, 0x74, 0x73, 0x20, 0x61, 0x73, 0x20, 0x72, 0x65, 0x66, 0x65,
                    0x72, 0x65, 0x6e, 0x63, 0x65, 0x20, 0x6d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61,
                    0x6c, 0x20, 0x6f, 0x72, 0x20, 0x74, 0x6f, 0x20, 0x63, 0x69, 0x74, 0x65, 0x20,
                    0x74, 0x68, 0x65, 0x6d, 0x20, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x74, 0x68,
                    0x61, 0x6e, 0x20, 0x61, 0x73, 0x20, 0x2f, 0xe2, 0x80, 0x9c, 0x77, 0x6f, 0x72,
                    0x6b, 0x20, 0x69, 0x6e, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73,
                    0x2e, 0x2f, 0xe2, 0x80, 0x9d,
                ],
                cipher_text: &[
                    0x64, 0xa0, 0x86, 0x15, 0x75, 0x86, 0x1a, 0xf4, 0x60, 0xf0, 0x62, 0xc7, 0x9b,
                    0xe6, 0x43, 0xbd, 0x5e, 0x80, 0x5c, 0xfd, 0x34, 0x5c, 0xf3, 0x89, 0xf1, 0x08,
                    0x67, 0x0a, 0xc7, 0x6c, 0x8c, 0xb2, 0x4c, 0x6c, 0xfc, 0x18, 0x75, 0x5d, 0x43,
                    0xee, 0xa0, 0x9e, 0xe9, 0x4e, 0x38, 0x2d, 0x26, 0xb0, 0xbd, 0xb7, 0xb7, 0x3c,
                    0x32, 0x1b, 0x01, 0x00, 0xd4, 0xf0, 0x3b, 0x7f, 0x35, 0x58, 0x94, 0xcf, 0x33,
                    0x2f, 0x83, 0x0e, 0x71, 0x0b, 0x97, 0xce, 0x98, 0xc8, 0xa8, 0x4a, 0xbd, 0x0b,
                    0x94, 0x81, 0x14, 0xad, 0x17, 0x6e, 0x00, 0x8d, 0x33, 0xbd, 0x60, 0xf9, 0x82,
                    0xb1, 0xff, 0x37, 0xc8, 0x55, 0x97, 0x97, 0xa0, 0x6e, 0xf4, 0xf0, 0xef, 0x61,
                    0xc1, 0x86, 0x32, 0x4e, 0x2b, 0x35, 0x06, 0x38, 0x36, 0x06, 0x90, 0x7b, 0x6a,
                    0x7c, 0x02, 0xb0, 0xf9, 0xf6, 0x15, 0x7b, 0x53, 0xc8, 0x67, 0xe4, 0xb9, 0x16,
                    0x6c, 0x76, 0x7b, 0x80, 0x4d, 0x46, 0xa5, 0x9b, 0x52, 0x16, 0xcd, 0xe7, 0xa4,
                    0xe9, 0x90, 0x40, 0xc5, 0xa4, 0x04, 0x33, 0x22, 0x5e, 0xe2, 0x82, 0xa1, 0xb0,
                    0xa0, 0x6c, 0x52, 0x3e, 0xaf, 0x45, 0x34, 0xd7, 0xf8, 0x3f, 0xa1, 0x15, 0x5b,
                    0x00, 0x47, 0x71, 0x8c, 0xbc, 0x54, 0x6a, 0x0d, 0x07, 0x2b, 0x04, 0xb3, 0x56,
                    0x4e, 0xea, 0x1b, 0x42, 0x22, 0x73, 0xf5, 0x48, 0x27, 0x1a, 0x0b, 0xb2, 0x31,
                    0x60, 0x53, 0xfa, 0x76, 0x99, 0x19, 0x55, 0xeb, 0xd6, 0x31, 0x59, 0x43, 0x4e,
                    0xce, 0xbb, 0x4e, 0x46, 0x6d, 0xae, 0x5a, 0x10, 0x73, 0xa6, 0x72, 0x76, 0x27,
                    0x09, 0x7a, 0x10, 0x49, 0xe6, 0x17, 0xd9, 0x1d, 0x36, 0x10, 0x94, 0xfa, 0x68,
                    0xf0, 0xff, 0x77, 0x98, 0x71, 0x30, 0x30, 0x5b, 0xea, 0xba, 0x2e, 0xda, 0x04,
                    0xdf, 0x99, 0x7b, 0x71, 0x4d, 0x6c, 0x6f, 0x2c, 0x29, 0xa6, 0xad, 0x5c, 0xb4,
                    0x02, 0x2b, 0x02, 0x70, 0x9b,
                ],
                aad: &[
                    0xf3, 0x33, 0x88, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x91,
                ],
            },
        ];
        for tv in tests.iter() {
            test_vector(&tv)
        }
    }
}

#[cfg(all(test, feature = "with-bench"))]
mod bench {
    use super::ChaCha20Poly1305;
    use test::Bencher;

    #[bench]
    pub fn chacha20poly1305_10(bh: &mut Bencher) {
        let input = [1u8; 10];
        let aad = [3u8; 10];
        bh.iter(|| {
            let mut cipher = ChaCha20Poly1305::new(&[0; 32], &[0; 8], &aad);
            let mut decipher = ChaCha20Poly1305::new(&[0; 32], &[0; 8], &aad);

            let mut output = [0u8; 10];
            let mut tag = [0u8; 16];
            let mut output2 = [0u8; 10];
            cipher.encrypt(&input, &mut output, &mut tag);
            decipher.decrypt(&output, &mut output2, &tag);
        });
        bh.bytes = 10u64;
    }

    #[bench]
    pub fn chacha20poly1305_1k(bh: &mut Bencher) {
        let input = [1u8; 1024];
        let aad = [3u8; 1024];
        bh.iter(|| {
            let mut cipher = ChaCha20Poly1305::new(&[0; 32], &[0; 8], &aad);
            let mut decipher = ChaCha20Poly1305::new(&[0; 32], &[0; 8], &aad);

            let mut output = [0u8; 1024];
            let mut tag = [0u8; 16];
            let mut output2 = [0u8; 1024];

            cipher.encrypt(&input, &mut output, &mut tag);
            decipher.decrypt(&output, &mut output2, &tag);
        });
        bh.bytes = 1024u64;
    }

    #[bench]
    pub fn chacha20poly1305_64k(bh: &mut Bencher) {
        let input = [1u8; 65536];
        let aad = [3u8; 65536];
        bh.iter(|| {
            let mut cipher = ChaCha20Poly1305::new(&[0; 32], &[0; 8], &aad);
            let mut decipher = ChaCha20Poly1305::new(&[0; 32], &[0; 8], &aad);

            let mut output = [0u8; 65536];
            let mut tag = [0u8; 16];
            let mut output2 = [0u8; 65536];

            cipher.encrypt(&input, &mut output, &mut tag);
            decipher.decrypt(&output, &mut output2, &tag);
        });
        bh.bytes = 65536u64;
    }
}
