//! AES Block Cipher
//!
//! AES-128 and AES-256 implementation providing single-block encrypt and
//! decrypt operations.
//!
//! The backend is selected at compile time:
//!
//! * On aarch64 with the `aes` target feature, the ARMv8 Cryptography
//!   Extensions (hardware AES instructions) are used.
//! * Otherwise, a portable, constant-time software implementation using the
//!   fixsliced bitslice technique (Adomnicai & Peyrin, 2020) is used.
//!
//! # Note on use
//!
//! AES block cipher should be used with either some kind of block modes or as part
//! of another construction. it is not recommeded to use as is, and should always
//! be part of a high level construct (e.g. AES-GCM, AES-CTR).
//!
//! AES192 is omitted from this implementation, if need arise, submit a PR.
//!
//! # Example
//!
//! ```
//! use cryptoxide::aes::Aes128;
//!
//! let key = [0u8; 16];
//! let cipher = Aes128::new(&key);
//! let plaintext = [0u8; 16];
//! let ciphertext = cipher.encrypt_block(&plaintext);
//! let recovered = cipher.decrypt_block(&ciphertext);
//! assert_eq!(plaintext, recovered);
//! ```

// Hardware backend: ARMv8 Cryptography Extensions.
#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
mod aarch64;
#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
use aarch64 as backend;

// Software backend: portable constant-time fixslice implementation.
#[cfg(not(all(target_arch = "aarch64", target_feature = "aes")))]
mod reference;
#[cfg(not(all(target_arch = "aarch64", target_feature = "aes")))]
use reference as backend;

/// AES-128 block cipher with pre-expanded round keys.
///
/// Created from a 128-bit key via [`Aes128::new`]. The key schedule is
/// computed once at construction time, making subsequent encrypt/decrypt
/// operations fast.
///
/// The expanded round keys are stored in a backend-specific format and are
/// used for both encryption and decryption.
#[derive(Clone)]
pub struct Aes128 {
    round_keys: backend::RoundKeys128,
}

impl Aes128 {
    /// Create a new AES-128 cipher from a 128-bit key.
    ///
    /// Performs key schedule expansion at construction time.
    /// The resulting cipher can be reused for multiple encrypt/decrypt operations.
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            round_keys: backend::key_schedule128(key),
        }
    }

    /// Encrypt a single 128-bit block.
    pub fn encrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        backend::encrypt128(&self.round_keys, input)
    }

    /// Decrypt a single 128-bit block.
    pub fn decrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        backend::decrypt128(&self.round_keys, input)
    }
}

/// AES-256 block cipher with pre-expanded round keys.
///
/// Created from a 256-bit key via [`Aes256::new`]. The key schedule is
/// computed once at construction time, making subsequent encrypt/decrypt
/// operations fast.
///
/// The expanded round keys are stored in a backend-specific format and are
/// used for both encryption and decryption.
#[derive(Clone)]
pub struct Aes256 {
    round_keys: backend::RoundKeys256,
}

impl Aes256 {
    /// Create a new AES-256 cipher from a 256-bit key.
    ///
    /// Performs key schedule expansion at construction time.
    /// The resulting cipher can be reused for multiple encrypt/decrypt operations.
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            round_keys: backend::key_schedule256(key),
        }
    }

    /// Encrypt a single 128-bit block.
    pub fn encrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        backend::encrypt256(&self.round_keys, input)
    }

    /// Decrypt a single 128-bit block.
    pub fn decrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        backend::decrypt256(&self.round_keys, input)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // NIST FIPS 197 Appendix C.1 -- AES-128
    #[test]
    fn test_aes128_fips197_appendix_c() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected_ct: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];
        let cipher = Aes128::new(&key);
        let ct = cipher.encrypt_block(&plaintext);
        assert_eq!(ct, expected_ct, "AES-128 encrypt failed (FIPS 197 C.1)");
        let pt = cipher.decrypt_block(&expected_ct);
        assert_eq!(pt, plaintext, "AES-128 decrypt failed (FIPS 197 C.1)");
    }

    // NIST FIPS 197 Appendix C.3 -- AES-256
    #[test]
    fn test_aes256_fips197_appendix_c() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected_ct: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];
        let cipher = Aes256::new(&key);
        let ct = cipher.encrypt_block(&plaintext);
        assert_eq!(ct, expected_ct, "AES-256 encrypt failed (FIPS 197 C.3)");
        let pt = cipher.decrypt_block(&expected_ct);
        assert_eq!(pt, plaintext, "AES-256 decrypt failed (FIPS 197 C.3)");
    }

    // NIST Known Answer Test -- zero key, zero plaintext
    #[test]
    fn test_aes128_zero_key_zero_plaintext() {
        let key = [0u8; 16];
        let plaintext = [0u8; 16];
        let expected_ct: [u8; 16] = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let cipher = Aes128::new(&key);
        let ct = cipher.encrypt_block(&plaintext);
        assert_eq!(ct, expected_ct, "AES-128 zero-key KAT failed");
        let pt = cipher.decrypt_block(&ct);
        assert_eq!(pt, plaintext, "AES-128 zero-key decrypt round-trip failed");
    }

    #[test]
    fn test_aes256_zero_key_zero_plaintext() {
        let key = [0u8; 32];
        let plaintext = [0u8; 16];
        let expected_ct: [u8; 16] = [
            0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84,
            0x20, 0x87,
        ];
        let cipher = Aes256::new(&key);
        let ct = cipher.encrypt_block(&plaintext);
        assert_eq!(ct, expected_ct, "AES-256 zero-key KAT failed");
        let pt = cipher.decrypt_block(&ct);
        assert_eq!(pt, plaintext, "AES-256 zero-key decrypt round-trip failed");
    }

    // Round-trip: encrypt then decrypt, and decrypt then encrypt
    #[test]
    fn test_aes128_round_trip() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let plaintext: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let cipher = Aes128::new(&key);
        let ct = cipher.encrypt_block(&plaintext);
        let recovered = cipher.decrypt_block(&ct);
        assert_eq!(recovered, plaintext, "AES-128 round-trip failed");
        let ct2 = cipher.encrypt_block(&recovered);
        assert_eq!(ct2, ct, "AES-128 reverse round-trip failed");
    }

    #[test]
    fn test_aes256_round_trip() {
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let plaintext: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let cipher = Aes256::new(&key);
        let ct = cipher.encrypt_block(&plaintext);
        let recovered = cipher.decrypt_block(&ct);
        assert_eq!(recovered, plaintext, "AES-256 round-trip failed");
        let ct2 = cipher.encrypt_block(&recovered);
        assert_eq!(ct2, ct, "AES-256 reverse round-trip failed");
    }
}
