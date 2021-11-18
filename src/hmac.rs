//! Implements the Hash Message Authentication Code (HMAC)
//!
//! # Examples
//!
//! HMAC-SHA256 using a 16 bytes key and the incremental interface:
//!
//! ```
//! use cryptoxide::{hmac, hmac::SHA256};
//!
//! let key = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
//! let mut context = hmac::Context::<SHA256>::new(&key);
//! context.update(b"my ");
//! context.update(b"message");
//! let mac = context.finalize();
//! ```
//!
//! or using the more concise one-shot interface:
//!
//! ```
//! use cryptoxide::hmac::{hmac, SHA256};
//!
//! let key = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
//! let mac = hmac::<SHA256>(&key, b"my message");
//! ```
//!

#![allow(missing_docs)]

use crate::constant_time::{Choice, CtEqual};
use crate::cryptoutil::zero;
use crate::digest::Digest;
use core::convert::TryFrom;

// HMAC is implemented using the following operations:
//
// HMAC(K, m) = H( (K' ⊕ opad) || H( (K' ⊕ ipad) || m ) )
// where
//   K' = H(K) if length K > block size
//      | K    otherwise
//   H is a cryptographic hash function
//   m is the message to be authenticated
//   K is the secret key
//   K' is a block-sized key derived from the secret key, K; either by padding to the right with 0s up to the block size, or by hashing down to less than or equal to the block size first and then padding to the right with zeros
//   || denotes concatenation
//   ⊕ denotes bitwise exclusive or (XOR)
//   opad is the block-sized outer padding, consisting of repeated bytes valued 0x5c
//   ipad is the block-sized inner padding, consisting of repeated bytes valued 0x36

macro_rules! init_key {
    ($key:ident, $new:expr, $digest_len:path, $block_size:path) => {{
        const OPAD: u8 = 0x5c;
        const IPAD: u8 = 0x36;

        assert!($digest_len <= $block_size);

        let mut k = [0u8; $block_size];
        let mut mix = [0u8; $block_size];
        let mut digest_out = [0u8; $digest_len];

        let mut inner_ctx = $new;
        let mut outer_ctx = $new;

        // set k' either as a hash of the key or as the key itself.
        if $key.len() <= $block_size {
            k[0..$key.len()].copy_from_slice($key)
        } else {
            // use inner_ctx to just hash into k
            let k_as_digestlen =
                <&mut [u8; $digest_len]>::try_from(&mut k[0..$digest_len]).unwrap();
            inner_ctx.input($key);
            inner_ctx.result(k_as_digestlen);
            inner_ctx.reset();
        }

        // input the keyed-ipad in the inner-context (the one hashing the message)
        for (m, k_byte) in mix.iter_mut().zip(k.iter()) {
            *m = k_byte ^ IPAD;
        }
        inner_ctx.input(&mix);

        // input the keyed-opad in the outer-context (the one hashing the final result)
        for (m, k_byte) in mix.iter_mut().zip(k.iter()) {
            *m = k_byte ^ OPAD;
        }
        outer_ctx.input(&mix);

        // zero the objects
        zero(&mut k);
        zero(&mut mix);
        zero(&mut digest_out);

        (inner_ctx, outer_ctx)
    }};
}

macro_rules! algorithm_impl {
    ($name:ident, $module:ident, $digest_new:ident) => {
        impl Algorithm for $name {
            const BLOCK_SIZE: usize = Self::BLOCK_SIZE;
            const OUTPUT_SIZE: usize = Self::OUTPUT_SIZE;

            type Context = crate::$module::$digest_new;
            type Output = [u8; Self::OUTPUT_SIZE];
            type MacOutput = Tag<{ Self::OUTPUT_SIZE }>;

            fn init(key: &[u8]) -> (Self::Context, Self::Context) {
                init_key!(
                    key,
                    crate::$module::$digest_new::new(),
                    Self::OUTPUT_SIZE,
                    Self::BLOCK_SIZE
                )
            }
            fn update(_context: &mut Self::Context, _input: &[u8]) {
                _context.input(_input);
            }
            fn finalize(_context: &mut Self::Context) -> Self::MacOutput {
                let mut output = [0u8; Self::OUTPUT_SIZE];
                _context.result(&mut output);
                _context.reset();
                Tag(output)
            }
            fn finalize_at(_context: &mut Self::Context, out: &mut [u8]) {
                _context.result(out);
                _context.reset();
            }
            fn feed(context: &mut Self::Context, other: &mut Self::Context) {
                let mut output = [0u8; Self::OUTPUT_SIZE];
                other.result(&mut output);
                other.reset();
                context.input(&output);
            }
        }
    };
}

macro_rules! algorithm2_impl {
    ($name:ident, $module:ident, $digest_new:ident) => {
        impl Algorithm for $name {
            const BLOCK_SIZE: usize = Self::BLOCK_SIZE;
            const OUTPUT_SIZE: usize = Self::OUTPUT_SIZE;

            type Context = crate::$module::$digest_new;
            type Output = [u8; Self::OUTPUT_SIZE];
            type MacOutput = Tag<{ Self::OUTPUT_SIZE }>;

            fn init(key: &[u8]) -> (Self::Context, Self::Context) {
                init_key!(
                    key,
                    crate::$module::$digest_new::new(Self::OUTPUT_SIZE),
                    Self::OUTPUT_SIZE,
                    Self::BLOCK_SIZE
                )
            }
            fn update(_context: &mut Self::Context, _input: &[u8]) {
                _context.input(_input);
            }
            fn finalize(_context: &mut Self::Context) -> Self::MacOutput {
                let mut output = [0u8; Self::OUTPUT_SIZE];
                _context.result(&mut output);
                _context.reset();
                Tag(output)
            }
            fn finalize_at(_context: &mut Self::Context, out: &mut [u8]) {
                _context.result(out);
                _context.reset();
            }
            fn feed(context: &mut Self::Context, other: &mut Self::Context) {
                let mut output = [0u8; Self::OUTPUT_SIZE];
                other.result(&mut output);
                other.reset();
                context.input(&output);
            }
        }
    };
}

/// Algorithm defined to do HMAC
pub trait Algorithm {
    const BLOCK_SIZE: usize;
    const OUTPUT_SIZE: usize;

    type Context: Clone;

    // Output and MacOutput should not be needed, but there's current compiler
    // limitation in composing the associated type and the constants
    type Output;
    type MacOutput;

    fn init(key: &[u8]) -> (Self::Context, Self::Context);
    fn update(context: &mut Self::Context, input: &[u8]);
    fn feed(context: &mut Self::Context, other: &mut Self::Context);
    fn finalize(context: &mut Self::Context) -> Self::MacOutput;
    fn finalize_at(_context: &mut Self::Context, out: &mut [u8]);
}

#[cfg(feature = "sha1")]
#[derive(Clone, Debug)]
pub struct SHA1;

#[cfg(feature = "sha1")]
impl SHA1 {
    pub const BLOCK_SIZE: usize = 64;
    pub const OUTPUT_SIZE: usize = 20;
}

#[cfg(feature = "sha1")]
algorithm_impl!(SHA1, sha1, Sha1);

#[cfg(feature = "sha2")]
#[derive(Clone, Debug)]
pub struct SHA256;

#[cfg(feature = "sha2")]
impl SHA256 {
    pub const BLOCK_SIZE: usize = 64;
    pub const OUTPUT_SIZE: usize = 32;
}

#[cfg(feature = "sha2")]
algorithm_impl!(SHA256, sha2, Sha256);

#[cfg(feature = "sha2")]
#[derive(Clone, Debug)]
pub struct SHA512;

#[cfg(feature = "sha2")]
impl SHA512 {
    pub const BLOCK_SIZE: usize = 128;
    pub const OUTPUT_SIZE: usize = 64;
}

#[cfg(feature = "sha2")]
algorithm_impl!(SHA512, sha2, Sha512);

#[cfg(feature = "blake2")]
#[derive(Clone, Debug)]
pub struct Blake2b256;

#[cfg(feature = "blake2")]
impl Blake2b256 {
    pub const BLOCK_SIZE: usize = 128;
    pub const OUTPUT_SIZE: usize = 32;
}

#[cfg(feature = "blake2")]
algorithm2_impl!(Blake2b256, blake2b, Blake2b);

#[cfg(feature = "blake2")]
#[derive(Clone, Debug)]
pub struct Blake2b512;

#[cfg(feature = "blake2")]
impl Blake2b512 {
    pub const BLOCK_SIZE: usize = 128;
    pub const OUTPUT_SIZE: usize = 64;
}

#[cfg(feature = "blake2")]
algorithm2_impl!(Blake2b512, blake2b, Blake2b);

#[cfg(feature = "blake2")]
#[derive(Clone, Debug)]
pub struct Blake2s256;

#[cfg(feature = "blake2")]
impl Blake2s256 {
    pub const BLOCK_SIZE: usize = 64;
    pub const OUTPUT_SIZE: usize = 32;
}

#[cfg(feature = "blake2")]
algorithm2_impl!(Blake2s256, blake2s, Blake2s);

/// HMAC context parametrized by the hashing function
///
/// It is composed of 2 hashing contextes, and the construction
/// is meant to hide the initial key from its context, by forcing
/// the key component to be processed by an initial compress step
/// rendering the key not recoverable from the context memory.
///
/// It may not be true for every type of hashing context, specially if they
/// have a buffering / last buffer capability.
pub struct Context<A: Algorithm> {
    inner: A::Context,
    outer: A::Context,
}

impl<A: Algorithm> Clone for Context<A> {
    fn clone(&self) -> Self {
        Context {
            inner: self.inner.clone(),
            outer: self.outer.clone(),
        }
    }
}

/// HMAC Tag with the number of bytes associated as const type parameter
///
/// This type is equiped with a constant time equality, either using the constant time
/// trait (`CtEqual`) but also using the standard equality trait (`Eq`), so
/// if this is used in a equality check it doesn't leak timing information.
///
/// The inner component of the tag, an array of bytes, is exposed publicly
/// and the `Tag` type can be constructed from the component.
pub struct Tag<const N: usize>(pub [u8; N]);

impl<'a, const N: usize> From<&'a Tag<N>> for &'a [u8] {
    fn from(tag: &'a Tag<N>) -> Self {
        &tag.0
    }
}

impl<const N: usize> CtEqual for &Tag<N> {
    fn ct_eq(self, other: Self) -> Choice {
        self.0.ct_eq(&other.0)
    }

    fn ct_ne(self, other: Self) -> Choice {
        self.0.ct_ne(&other.0)
    }
}

impl<const N: usize> PartialEq for Tag<N> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).is_true()
    }
}

impl<const N: usize> Eq for Tag<N> {}

impl<H: Algorithm> Context<H> {
    pub(crate) fn output_bytes(&self) -> usize {
        H::OUTPUT_SIZE
    }

    /// Create a new HMAC context instance with the given key
    ///
    /// The key to use can be any sequence of bytes
    pub fn new(key: &[u8]) -> Self {
        let (inner, outer) = H::init(key);
        Self { inner, outer }
    }

    /// Update the context with message
    ///
    /// This can be called multiple times
    pub fn update(&mut self, message: &[u8]) {
        H::update(&mut self.inner, message)
    }

    /// Finalize the context and get the associated HMAC Tag output
    pub fn finalize(mut self) -> H::MacOutput {
        H::feed(&mut self.outer, &mut self.inner);
        H::finalize(&mut self.outer)
    }

    /// Finalize the context and get the associated HMAC Tag output
    pub fn finalize_at(&mut self, out: &mut [u8]) {
        H::feed(&mut self.outer, &mut self.inner);
        H::finalize_at(&mut self.outer, out)
    }
}

/// Generate a HMAC Tag for a given key and message
///
/// ```
/// # #[cfg(feature = "sha2")]
/// use cryptoxide::hmac::{hmac, SHA256};
///
/// # #[cfg(feature = "sha2")]
/// hmac::<SHA256>(&[1,2,3], b"message");
/// ```
pub fn hmac<D: Algorithm>(key: &[u8], message: &[u8]) -> D::MacOutput {
    let mut context: Context<D> = Context::new(key);
    context.update(message);
    context.finalize()
}

#[cfg(test)]
mod test {
    use crate::hmac;

    //#[cfg(feature = "blake2")]
    //use crate::blake2s::Blake2s;

    struct Test {
        key: &'static [u8],
        data: &'static [u8],
        expected: &'static [u8],
    }

    // Test vectors from: http://tools.ietf.org/html/rfc2104

    fn tests() -> [Test; 3] {
        [
            Test {
                key: &[
                    11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
                ],
                data: b"Hi There",
                expected: &[
                    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf,
                    0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9,
                    0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
                ],
            },
            Test {
                key: b"Jefe",
                data: b"what do ya want for nothing?",
                expected: &[
                    0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08,
                    0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec,
                    0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
                ],
            },
            Test {
                key: &[
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                ],
                data: &[
                    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                ],
                expected: &[
                    0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0,
                    0x91, 0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63,
                    0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe,
                ],
            },
        ]
    }

    #[cfg(feature = "sha2")]
    #[test]
    fn hmac_sha256() {
        for t in tests().iter() {
            let mut h: hmac::Context<hmac::SHA256> = hmac::Context::new(&t.key[..]);
            h.update(&t.data[..]);
            let output = h.finalize();
            assert_eq!(&output.0[..], &t.expected[..]);
        }
    }

    #[cfg(feature = "blake2")]
    #[test]
    fn hmac_blake2s() {
        let key = [
            0x05, 0x5a, 0x62, 0xc4, 0x6f, 0x56, 0x94, 0x0c, 0xb0, 0x00, 0xd5, 0x3d, 0x84, 0x2c,
            0x0a, 0xbd, 0xba, 0x1c, 0x43, 0xb0, 0xa3, 0x0c, 0xa4, 0xc3, 0x8a, 0xd0, 0x84, 0xc2,
            0x1c, 0x34, 0x99, 0x86,
        ];
        let data = b"hello";
        let expected = [
            0x9a, 0x4f, 0xe7, 0x47, 0xf8, 0x28, 0xa6, 0x15, 0x5e, 0xf8, 0x2b, 0xb2, 0x8c, 0xdb,
            0x8f, 0x41, 0xfa, 0xd5, 0x29, 0xe0, 0x15, 0xf9, 0x25, 0x98, 0x74, 0x24, 0x70, 0x37,
            0xaf, 0x28, 0xa6, 0x7a,
        ];

        let mut h: hmac::Context<hmac::Blake2s256> = hmac::Context::new(&key[..]);
        h.update(&data[..]);
        let output = h.finalize();
        assert_eq!(&output.0[..], &expected[..]);
    }
}
