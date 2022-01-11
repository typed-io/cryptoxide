//! X25519 - diffie hellman using curve25519
//!
//! Curve25519 elliptic curve from [Specification][1], and extra information also on [Wikipedia][2]
//!
//! # Example
//!
//! Creating a curve25519 point from a secret:
//!
//! ```
//! use cryptoxide::x25519;
//!
//! let secret = x25519::SecretKey::from([0,1,2,3,4,5,6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
//! let public = x25519::base(&secret);
//! ```
//!
//! Doing a ECDH on curve25519 using a curve point 'other_point' and a specific secret:
//!
//! ```
//! use cryptoxide::x25519;
//!
//! # let other_public = x25519::base(&x25519::SecretKey::from([3u8; 32]));
//! let secret = x25519::SecretKey::from([0,1,2,3,4,5,6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
//! let shared_secret = x25519::dh(&secret, &other_public);
//! ```
//!
//! [1]: <https://cr.yp.to/ecdh/curve25519-20060209.pdf>
//! [2]: <https://en.wikipedia.org/wiki/Curve25519>

use crate::curve25519::{curve25519, curve25519_base};

macro_rules! bytes_impl {
    ($t:ident, $n:literal) => {
        impl From<[u8; $n]> for $t {
            fn from(v: [u8; $n]) -> Self {
                $t(v)
            }
        }
        impl core::convert::TryFrom<&[u8]> for $t {
            type Error = ();

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                if value.len() == $n {
                    Ok($t(<[u8; $n]>::try_from(value).unwrap()))
                } else {
                    Err(())
                }
            }
        }
        impl AsRef<[u8]> for $t {
            fn as_ref(&self) -> &[u8] {
                &self.0[..]
            }
        }
    };
}

/// Secret Key
pub struct SecretKey([u8; 32]);

bytes_impl!(SecretKey, 32);

/// Public Key
pub struct PublicKey([u8; 32]);

bytes_impl!(PublicKey, 32);

pub struct SharedSecret([u8; 32]);

bytes_impl!(SharedSecret, 32);

/// Computes a shared secret from the curve25519 private key (n) and public
/// key (p)
pub fn dh(n: &SecretKey, p: &PublicKey) -> SharedSecret {
    SharedSecret(curve25519(&n.0, &p.0))
}

/// Derives a public key from a private key
pub fn base(x: &SecretKey) -> PublicKey {
    PublicKey(curve25519_base(&x.0))
}
