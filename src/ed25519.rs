//! ED25519 Signature Scheme
//!
//! # Examples
//!
//! Creating a signature, and verifying the signature:
//!
//! ```
//! use cryptoxide::ed25519;
//!
//! let message = "messages".as_bytes();
//! let secret_key = [0u8;32]; // private key only for example !
//! let (keypair, public) = ed25519::keypair(&secret_key);
//! let signature = ed25519::signature(message, &keypair);
//! let verified = ed25519::verify(message, &public, &signature);
//! assert!(verified);
//! ```
//!
//! The signature is 64 bytes composed of `R || S` where R is 32 bytes
//! and S is 32 bytes also.
//!
//! * [RFC8032](https://www.rfc-editor.org/rfc/rfc8032.txt)
//!

use crate::constant_time::CtEqual;
use crate::curve25519::{curve25519, scalar, Fe, Ge, GePartial, Scalar};
use crate::hashing::sha2::Sha512;
use core::convert::TryFrom;

#[deprecated(since = "0.4.0", note = "use `PRIVATE_KEY_LENGTH`")]
pub const SEED_LENGTH: usize = 32;
pub const PRIVATE_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const KEYPAIR_LENGTH: usize = PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH;
pub const EXTENDED_KEY_LENGTH: usize = 64;
pub const SIGNATURE_LENGTH: usize = 64;

// clamp the scalar by:
// 1. clearing the 3 lower bits,
// 2. clearing the highest bit
// 3. setting the second highest bit
fn clamp_scalar(scalar: &mut [u8]) {
    scalar[0] &= 0b1111_1000;
    scalar[31] &= 0b0011_1111;
    scalar[31] |= 0b0100_0000;
}

/// Create the extended secret format by hashing the 32 bytes private key with SHA512
/// and tweaking the first 32 bytes as a scalar using the clamp mechanism in `clamp_scalar`
///
/// SCALAR(32bytes) | RANDOM(32bytes) = CLAMP(SHA512(private_key))
fn extended_secret(private_key: &[u8; PRIVATE_KEY_LENGTH]) -> [u8; EXTENDED_KEY_LENGTH] {
    let mut hash_output = Sha512::new().update(private_key).finalize();
    clamp_scalar(&mut hash_output);
    hash_output
}

/// Extract the private key of a keypair
pub fn keypair_private(keypair: &[u8; KEYPAIR_LENGTH]) -> &[u8; PRIVATE_KEY_LENGTH] {
    <&[u8; PRIVATE_KEY_LENGTH]>::try_from(&keypair[0..PRIVATE_KEY_LENGTH]).unwrap()
}

/// Extract the public key of a keypair
pub fn keypair_public(keypair: &[u8; KEYPAIR_LENGTH]) -> &[u8; PUBLIC_KEY_LENGTH] {
    <&[u8; PUBLIC_KEY_LENGTH]>::try_from(&keypair[32..64]).unwrap()
}

/// Extract the scalar part (first 32 bytes) from the extended key
fn extended_scalar(extended_secret: &[u8; EXTENDED_KEY_LENGTH]) -> Scalar {
    Scalar::from_bytes(<&[u8; 32]>::try_from(&extended_secret[0..32]).unwrap())
}

/// Extract the scalar part (first 32 bytes) from the extended key
fn extended_scalar_bytes(extended_secret: &[u8; EXTENDED_KEY_LENGTH]) -> &[u8; 32] {
    <&[u8; 32]>::try_from(&extended_secret[0..32]).unwrap()
}

/// generate the public key associated with an extended secret key
pub fn extended_to_public(extended_secret: &[u8; EXTENDED_KEY_LENGTH]) -> [u8; PUBLIC_KEY_LENGTH] {
    let a = Ge::scalarmult_base(&extended_scalar(extended_secret));
    a.to_bytes()
}

/// keypair of secret key and public key
///
/// Given the secret key, it calculate the associated public key and
/// it returns a convenient keypair array containing both the secret and public key
pub fn keypair(
    secret_key: &[u8; PRIVATE_KEY_LENGTH],
) -> ([u8; KEYPAIR_LENGTH], [u8; PUBLIC_KEY_LENGTH]) {
    let extended_secret = extended_secret(secret_key);
    let public_key = extended_to_public(&extended_secret);

    // overwrite extended secret buffer to be KEYPAIR = SECRET_KEY | PUBLIC_KEY
    let mut output = extended_secret;
    output[0..32].copy_from_slice(secret_key);
    output[32..64].copy_from_slice(&public_key);

    (output, public_key)
}

/// Generate the nonce which is a scalar out of the extended_secret random part and the message itself
/// using SHA512 and scalar_reduction
fn signature_nonce(extended_secret: &[u8; EXTENDED_KEY_LENGTH], message: &[u8]) -> Scalar {
    let hash_output = Sha512::new()
        .update(&extended_secret[32..64])
        .update(message)
        .finalize();
    Scalar::reduce_from_wide_bytes(&hash_output)
}

/// Generate a signature for the given message using a normal ED25519 secret key
pub fn signature(message: &[u8], keypair: &[u8; KEYPAIR_LENGTH]) -> [u8; SIGNATURE_LENGTH] {
    let private_key = keypair_private(&keypair);
    let public_key = keypair_public(&keypair);
    let az = extended_secret(private_key);

    let nonce = signature_nonce(&az, message);

    let r = Ge::scalarmult_base(&nonce);

    let mut signature = [0; SIGNATURE_LENGTH];
    signature[0..32].copy_from_slice(&r.to_bytes());
    signature[32..64].copy_from_slice(public_key);

    {
        let hram = Sha512::new().update(&signature).update(message).finalize();
        let hram = Scalar::reduce_from_wide_bytes(&hram);
        let r = scalar::muladd(&hram, &extended_scalar(&az), &nonce);
        signature[32..64].copy_from_slice(&r.to_bytes())
    }

    signature
}

/// Generate a signature for the given message using an extended ED25519 secret key
pub fn signature_extended(
    message: &[u8],
    extended_secret: &[u8; EXTENDED_KEY_LENGTH],
) -> [u8; SIGNATURE_LENGTH] {
    let public_key = extended_to_public(extended_secret);
    let nonce = signature_nonce(extended_secret, message);

    let r = Ge::scalarmult_base(&nonce);

    let mut signature = [0; SIGNATURE_LENGTH];
    signature[0..32].copy_from_slice(&r.to_bytes());
    signature[32..64].copy_from_slice(&public_key);

    {
        let hram = Sha512::new().update(&signature).update(message).finalize();
        let hram = Scalar::reduce_from_wide_bytes(&hram);
        let r = scalar::muladd(&hram, &extended_scalar(extended_secret), &nonce);
        signature[32..64].copy_from_slice(&r.to_bytes())
    }

    signature
}

/// Verify that a signature is valid for a given message for an associated public key
pub fn verify(
    message: &[u8],
    public_key: &[u8; PUBLIC_KEY_LENGTH],
    signature: &[u8; SIGNATURE_LENGTH],
) -> bool {
    let signature_left = <&[u8; 32]>::try_from(&signature[0..32]).unwrap();
    let signature_right = <&[u8; 32]>::try_from(&signature[32..64]).unwrap();

    let a = match Ge::from_bytes(public_key) {
        Some(g) => g,
        None => {
            return false;
        }
    };

    let signature_scalar = match Scalar::from_bytes_canonical(signature_right) {
        None => return false,
        Some(s) => s,
    };

    // reject all-0 public keys
    let mut d = 0;
    for pk_byte in public_key.iter() {
        d |= *pk_byte;
    }
    if d == 0 {
        return false;
    }

    let hash = Sha512::new()
        .update(signature_left)
        .update(public_key)
        .update(message)
        .finalize();
    let a_scalar = Scalar::reduce_from_wide_bytes(&hash);

    let r = GePartial::double_scalarmult_vartime(&a_scalar, a, &signature_scalar);
    let rcheck = r.to_bytes();

    CtEqual::ct_eq(&rcheck, signature_left).into()
}

/// Curve25519 DH (Diffie Hellman) between a curve25519 public key and a ED25519 keypair key
pub fn exchange(public_key: &[u8; 32], private_key: &[u8; PRIVATE_KEY_LENGTH]) -> [u8; 32] {
    let ed_y = Fe::from_bytes(&public_key);
    // Produce public key in Montgomery form.
    let mont_x = edwards_to_montgomery_x(&ed_y);

    // Produce private key from seed component (bytes 0 to 32)
    // of the Ed25519 extended private key (64 bytes).
    let extended_secret = extended_secret(private_key);
    let shared_mont_x = curve25519(extended_scalar_bytes(&extended_secret), &mont_x.to_bytes());

    shared_mont_x
}

fn edwards_to_montgomery_x(ed_y: &Fe) -> Fe {
    let ed_z = &Fe::ONE;
    let temp_x = ed_z + ed_y;
    let temp_z = ed_z - ed_y;
    let temp_z_inv = temp_z.invert();

    let mont_x = &temp_x * &temp_z_inv;

    mont_x
}

#[cfg(test)]
mod tests {
    use super::{exchange, keypair, signature, verify};
    use crate::curve25519::{curve25519, curve25519_base};
    use crate::digest::Digest;
    use crate::sha2::Sha512;
    use core::convert::TryFrom;

    fn do_keypair_case(seed: [u8; 32], expected_secret: [u8; 64], expected_public: [u8; 32]) {
        let (actual_secret, actual_public) = keypair(&seed);
        assert_eq!(actual_secret, expected_secret);
        assert_eq!(actual_public, expected_public);
    }

    #[test]
    fn keypair_cases() {
        do_keypair_case(
            [
                0x26, 0x27, 0xf6, 0x85, 0x97, 0x15, 0xad, 0x1d, 0xd2, 0x94, 0xdd, 0xc4, 0x76, 0x19,
                0x39, 0x31, 0xf1, 0xad, 0xb5, 0x58, 0xf0, 0x93, 0x97, 0x32, 0x19, 0x2b, 0xd1, 0xc0,
                0xfd, 0x16, 0x8e, 0x4e,
            ],
            [
                0x26, 0x27, 0xf6, 0x85, 0x97, 0x15, 0xad, 0x1d, 0xd2, 0x94, 0xdd, 0xc4, 0x76, 0x19,
                0x39, 0x31, 0xf1, 0xad, 0xb5, 0x58, 0xf0, 0x93, 0x97, 0x32, 0x19, 0x2b, 0xd1, 0xc0,
                0xfd, 0x16, 0x8e, 0x4e, 0x5d, 0x6d, 0x23, 0x6b, 0x52, 0xd1, 0x8e, 0x3a, 0xb6, 0xd6,
                0x07, 0x2f, 0xb6, 0xe4, 0xc7, 0xd4, 0x6b, 0xd5, 0x9a, 0xd9, 0xcc, 0x19, 0x47, 0x26,
                0x5f, 0x00, 0xb7, 0x20, 0xfa, 0x2c, 0x8f, 0x66,
            ],
            [
                0x5d, 0x6d, 0x23, 0x6b, 0x52, 0xd1, 0x8e, 0x3a, 0xb6, 0xd6, 0x07, 0x2f, 0xb6, 0xe4,
                0xc7, 0xd4, 0x6b, 0xd5, 0x9a, 0xd9, 0xcc, 0x19, 0x47, 0x26, 0x5f, 0x00, 0xb7, 0x20,
                0xfa, 0x2c, 0x8f, 0x66,
            ],
        );
        do_keypair_case(
            [
                0x29, 0x23, 0xbe, 0x84, 0xe1, 0x6c, 0xd6, 0xae, 0x52, 0x90, 0x49, 0xf1, 0xf1, 0xbb,
                0xe9, 0xeb, 0xb3, 0xa6, 0xdb, 0x3c, 0x87, 0x0c, 0x3e, 0x99, 0x24, 0x5e, 0x0d, 0x1c,
                0x06, 0xb7, 0x47, 0xde,
            ],
            [
                0x29, 0x23, 0xbe, 0x84, 0xe1, 0x6c, 0xd6, 0xae, 0x52, 0x90, 0x49, 0xf1, 0xf1, 0xbb,
                0xe9, 0xeb, 0xb3, 0xa6, 0xdb, 0x3c, 0x87, 0x0c, 0x3e, 0x99, 0x24, 0x5e, 0x0d, 0x1c,
                0x06, 0xb7, 0x47, 0xde, 0x5d, 0x83, 0x31, 0x26, 0x56, 0x0c, 0xb1, 0x9a, 0x14, 0x19,
                0x37, 0x27, 0x78, 0x96, 0xf0, 0xfd, 0x43, 0x7b, 0xa6, 0x80, 0x1e, 0xb2, 0x10, 0xac,
                0x4c, 0x39, 0xd9, 0x00, 0x72, 0xd7, 0x0d, 0xa8,
            ],
            [
                0x5d, 0x83, 0x31, 0x26, 0x56, 0x0c, 0xb1, 0x9a, 0x14, 0x19, 0x37, 0x27, 0x78, 0x96,
                0xf0, 0xfd, 0x43, 0x7b, 0xa6, 0x80, 0x1e, 0xb2, 0x10, 0xac, 0x4c, 0x39, 0xd9, 0x00,
                0x72, 0xd7, 0x0d, 0xa8,
            ],
        );
    }

    #[test]
    fn keypair_matches_mont() {
        let private_key = [
            0x26, 0x27, 0xf6, 0x85, 0x97, 0x15, 0xad, 0x1d, 0xd2, 0x94, 0xdd, 0xc4, 0x76, 0x19,
            0x39, 0x31, 0xf1, 0xad, 0xb5, 0x58, 0xf0, 0x93, 0x97, 0x32, 0x19, 0x2b, 0xd1, 0xc0,
            0xfd, 0x16, 0x8e, 0x4e,
        ];
        let (ed_keypair, ed_public) = keypair(&private_key);

        let mut hasher = Sha512::new();
        hasher.input(&ed_keypair[0..32]);
        let mut hash: [u8; 64] = [0; 64];
        hasher.result(&mut hash);

        super::clamp_scalar(&mut hash);

        let curve_scalar = <&[u8; 32]>::try_from(&hash[0..32]).unwrap();
        let cv_public = curve25519_base(curve_scalar);

        let edx_ss = exchange(&ed_public, &private_key);
        let cv_ss = curve25519(&curve_scalar, &cv_public);

        assert_eq!(edx_ss, cv_ss);
    }

    fn do_sign_verify_case(seed: [u8; 32], message: &[u8], expected_signature: [u8; 64]) {
        let (secret_key, public_key) = keypair(&seed);
        let mut actual_signature = signature(message, &secret_key);
        assert_eq!(expected_signature.to_vec(), actual_signature.to_vec());
        assert!(verify(message, &public_key, &actual_signature));

        for &(index, flip) in [(0, 1), (31, 0x80), (20, 0xff)].iter() {
            actual_signature[index] ^= flip;
            assert!(!verify(message, &public_key, &actual_signature));
            actual_signature[index] ^= flip;
        }

        let mut public_key_corrupt = public_key;
        public_key_corrupt[0] ^= 1;
        assert!(!verify(message, &public_key_corrupt, &actual_signature,));
    }

    #[test]
    fn sign_verify_cases() {
        do_sign_verify_case(
            [
                0x2d, 0x20, 0x86, 0x83, 0x2c, 0xc2, 0xfe, 0x3f, 0xd1, 0x8c, 0xb5, 0x1d, 0x6c, 0x5e,
                0x99, 0xa5, 0x75, 0x9f, 0x02, 0x21, 0x1f, 0x85, 0xe5, 0xff, 0x2f, 0x90, 0x4a, 0x78,
                0x0f, 0x58, 0x00, 0x6f,
            ],
            &[
                0x89, 0x8f, 0x9c, 0x4b, 0x2c, 0x6e, 0xe9, 0xe2, 0x28, 0x76, 0x1c, 0xa5, 0x08, 0x97,
                0xb7, 0x1f, 0xfe, 0xca, 0x1c, 0x35, 0x28, 0x46, 0xf5, 0xfe, 0x13, 0xf7, 0xd3, 0xd5,
                0x7e, 0x2c, 0x15, 0xac, 0x60, 0x90, 0x0c, 0xa3, 0x2c, 0x5b, 0x5d, 0xd9, 0x53, 0xc9,
                0xa6, 0x81, 0x0a, 0xcc, 0x64, 0x39, 0x4f, 0xfd, 0x14, 0x98, 0x26, 0xd9, 0x98, 0x06,
                0x29, 0x2a, 0xdd, 0xd1, 0x3f, 0xc3, 0xbb, 0x7d, 0xac, 0x70, 0x1c, 0x5b, 0x4a, 0x2d,
                0x61, 0x5d, 0x15, 0x96, 0x01, 0x28, 0xed, 0x9f, 0x73, 0x6b, 0x98, 0x85, 0x4f, 0x6f,
                0x07, 0x05, 0xb0, 0xf0, 0xda, 0xcb, 0xdc, 0x2c, 0x26, 0x2d, 0x27, 0x39, 0x75, 0x19,
                0x14, 0x9b, 0x0e, 0x4c, 0xbe, 0x16, 0x77, 0xc5, 0x76, 0xc1, 0x39, 0x7a, 0xae, 0x5c,
                0xe3, 0x49, 0x16, 0xe3, 0x51, 0x31, 0x04, 0x63, 0x2e, 0xc2, 0x19, 0x0d, 0xb8, 0xd2,
                0x22, 0x89, 0xc3, 0x72, 0x3c, 0x8d, 0x01, 0x21, 0x3c, 0xad, 0x80, 0x3f, 0x4d, 0x75,
                0x74, 0xc4, 0xdb, 0xb5, 0x37, 0x31, 0xb0, 0x1c, 0x8e, 0xc7, 0x5d, 0x08, 0x2e, 0xf7,
                0xdc, 0x9d, 0x7f, 0x1b, 0x73, 0x15, 0x9f, 0x63, 0xdb, 0x56, 0xaa, 0x12, 0xa2, 0xca,
                0x39, 0xea, 0xce, 0x6b, 0x28, 0xe4, 0xc3, 0x1d, 0x9d, 0x25, 0x67, 0x41, 0x45, 0x2e,
                0x83, 0x87, 0xe1, 0x53, 0x6d, 0x03, 0x02, 0x6e, 0xe4, 0x84, 0x10, 0xd4, 0x3b, 0x21,
                0x91, 0x88, 0xba, 0x14, 0xa8, 0xaf,
            ],
            [
                0x91, 0x20, 0x91, 0x66, 0x1e, 0xed, 0x18, 0xa4, 0x03, 0x4b, 0xc7, 0xdb, 0x4b, 0xd6,
                0x0f, 0xe2, 0xde, 0xeb, 0xf3, 0xff, 0x3b, 0x6b, 0x99, 0x8d, 0xae, 0x20, 0x94, 0xb6,
                0x09, 0x86, 0x5c, 0x20, 0x19, 0xec, 0x67, 0x22, 0xbf, 0xdc, 0x87, 0xbd, 0xa5, 0x40,
                0x91, 0x92, 0x2e, 0x11, 0xe3, 0x93, 0xf5, 0xfd, 0xce, 0xea, 0x3e, 0x09, 0x1f, 0x2e,
                0xe6, 0xbc, 0x62, 0xdf, 0x94, 0x8e, 0x99, 0x09,
            ],
        );
        do_sign_verify_case(
            [
                0x33, 0x19, 0x17, 0x82, 0xc1, 0x70, 0x4f, 0x60, 0xd0, 0x84, 0x8d, 0x75, 0x62, 0xa2,
                0xfa, 0x19, 0xf9, 0x92, 0x4f, 0xea, 0x4e, 0x77, 0x33, 0xcd, 0x45, 0xf6, 0xc3, 0x2f,
                0x21, 0x9a, 0x72, 0x91,
            ],
            &[
                0x77, 0x13, 0x43, 0x5a, 0x0e, 0x34, 0x6f, 0x67, 0x71, 0xae, 0x5a, 0xde, 0xa8, 0x7a,
                0xe7, 0xa4, 0x52, 0xc6, 0x5d, 0x74, 0x8f, 0x48, 0x69, 0xd3, 0x1e, 0xd3, 0x67, 0x47,
                0xc3, 0x28, 0xdd, 0xc4, 0xec, 0x0e, 0x48, 0x67, 0x93, 0xa5, 0x1c, 0x67, 0x66, 0xf7,
                0x06, 0x48, 0x26, 0xd0, 0x74, 0x51, 0x4d, 0xd0, 0x57, 0x41, 0xf3, 0xbe, 0x27, 0x3e,
                0xf2, 0x1f, 0x28, 0x0e, 0x49, 0x07, 0xed, 0x89, 0xbe, 0x30, 0x1a, 0x4e, 0xc8, 0x49,
                0x6e, 0xb6, 0xab, 0x90, 0x00, 0x06, 0xe5, 0xa3, 0xc8, 0xe9, 0xc9, 0x93, 0x62, 0x1d,
                0x6a, 0x3b, 0x0f, 0x6c, 0xba, 0xd0, 0xfd, 0xde, 0xf3, 0xb9, 0xc8, 0x2d,
            ],
            [
                0x4b, 0x8d, 0x9b, 0x1e, 0xca, 0x54, 0x00, 0xea, 0xc6, 0xf5, 0xcc, 0x0c, 0x94, 0x39,
                0x63, 0x00, 0x52, 0xf7, 0x34, 0xce, 0x45, 0x3e, 0x94, 0x26, 0xf3, 0x19, 0xdd, 0x96,
                0x03, 0xb6, 0xae, 0xae, 0xb9, 0xd2, 0x3a, 0x5f, 0x93, 0xf0, 0x6a, 0x46, 0x00, 0x18,
                0xf0, 0x69, 0xdf, 0x19, 0x44, 0x48, 0xf5, 0x60, 0x51, 0xab, 0x9e, 0x6b, 0xfa, 0xeb,
                0x64, 0x10, 0x16, 0xf7, 0xa9, 0x0b, 0xe2, 0x0c,
            ],
        );
    }
}
