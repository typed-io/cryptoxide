//! SLH-DSA, the Stateless Hash-Based Digital Signature Algorithm standardised
//! in [FIPS 205][1]
//!
//! SLH-DSA (formerly SPHINCS+) is an asymmetric signature algorithm that is
//! believed to be post quantum secure. Unlike ML-DSA, its security rests only
//! on the properties of the hash function it is built on, which makes it the
//! conservative choice of the NIST post quantum signatures; the price is in
//! signature size and signing time.
//!
//! A key is a hypertree: `d` layers of Merkle (XMSS) trees whose leaves are
//! one-time signature (WOTS+) keys, each tree signing the root of a tree of
//! the layer below, and at the bottom a few-time signature (FORS) key that
//! signs the message. The key pair used is picked from the digest of the
//! message, which is what makes the scheme stateless.
//!
//! # Parameter sets
//!
//! Twelve parameter sets are standardised, each one a module of its own:
//!
//! * the hash function family, SHA2 or SHAKE, which has no bearing on sizes;
//! * the security category, 1, 3 or 5, for 128, 192 and 256 bits of security;
//! * the `s` variants, with small signatures but slow signing, or the `f`
//!   ones, with fast signing but larger signatures.
//!
//! Table 2. [FIPS 205][1]:
//!
//! | Parameter sets                      | Category | Verifying key | Signing key | Signature    |
//! | ----------------------------------- | -------- | ------------- | ----------- | ------------ |
//! | [`sha2_128s`], [`shake_128s`]       | 1        | 32 bytes      | 64 bytes    | 7856 bytes   |
//! | [`sha2_128f`], [`shake_128f`]       | 1        | 32 bytes      | 64 bytes    | 17088 bytes  |
//! | [`sha2_192s`], [`shake_192s`]       | 3        | 48 bytes      | 96 bytes    | 16224 bytes  |
//! | [`sha2_192f`], [`shake_192f`]       | 3        | 48 bytes      | 96 bytes    | 35664 bytes  |
//! | [`sha2_256s`], [`shake_256s`]       | 5        | 64 bytes      | 128 bytes   | 29792 bytes  |
//! | [`sha2_256f`], [`shake_256f`]       | 5        | 64 bytes      | 128 bytes   | 49856 bytes  |
//!
//! Key generation costs a whole XMSS tree, and signing one per layer plus the
//! FORS trees, which is at least an order of magnitude more for the `s`
//! variants than for the `f` ones. Verifying is cheap for every set.
//!
//! Signatures are returned by value, and are large: mind the stack of the
//! thread that signs or verifies them.
//!
//! # Example
//!
//! ```
//! use cryptoxide::slhdsa::shake_128f;
//!
//! // the signer generates a key pair and publishes its verifying key
//! # let seed = [0u8; shake_128f::SEED_LENGTH]; // must be random !
//! let (vk, sk) = shake_128f::keypair(&seed);
//!
//! // signing is hedged with fresh randomness, and takes a context string that
//! // separates one use of a key from another
//! # let rnd = [1u8; shake_128f::RANDOMIZER_LENGTH]; // for real use must be proper random
//! let signature = sk.sign(b"message", b"my protocol v1", &rnd).unwrap();
//!
//! assert!(vk.verify(b"message", b"my protocol v1", &signature));
//! assert!(!vk.verify(b"other message", b"my protocol v1", &signature));
//! ```
//!
//! # Randomness
//!
//! Key generation takes `3 n` bytes of seed, which must be independent and
//! freshly generated random bytes, as the whole of the signing key is derived
//! from them: they are, in that order, the secret seed `SK.seed`, the secret
//! `SK.prf` the randomizer of the signatures is derived from, and the public
//! seed `PK.seed`.
//!
//! Signing takes `n` bytes of randomness, `opt_rand`, mixed into the
//! randomizer of the signature. Unlike some other schemes, the security of
//! SLH-DSA does not depend on it, and the deterministic variant
//! (`sign_deterministic`) is as secure; fresh randomness protects against
//! side channel and fault attacks that a repeatable computation is exposed to.
//!
//! # Context strings
//!
//! Every signing and verifying call takes a context string of up to 255 bytes,
//! which is bound into the signature. Two protocols that use the same key with
//! different contexts cannot have a signature of one accepted by the other.
//! Pass `b""` for the empty context if there is nothing to separate.
//!
//! # Pre hashing
//!
//! The `sign_prehash` and `verify_prehash` methods implement `HashSLH-DSA`
//! (FIPS 205 section 10.2.2), which signs a digest of the message rather than
//! the message itself.
//!
//! [1]: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf>

use crate::dsa_prehash;

pub use crate::dsa_prehash::PreHash;

use address::{Adrs, AdrsType};
use hash::Hasher;
use params::{MAX_M, ParameterSet};
use sha2::Sha2Hasher;
use shake::ShakeHasher;

mod address;
mod fors;
mod hash;
mod params;
mod sha2;
mod shake;
mod tree;
mod wots;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod testvectors;

/// Longest context string a signature can be bound to
pub const MAX_CONTEXT_LENGTH: usize = dsa_prehash::MAX_CONTEXT_LENGTH;

/// Potential Error that can happens during signing operation
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningError {
    /// Invalid Context Length. only support up to [`MAX_CONTEXT_LENGTH`] bytes
    InvalidContextLength,
}

/// `slh_keygen_internal` (FIPS 205 Algorithm 18), from the `3 n` bytes of
/// `seed`, `SK.seed || SK.prf || PK.seed`, into the `4 n` bytes of `sk` and
/// the `2 n` bytes of `pk`
fn keygen<const N: usize, P: ParameterSet<N>>(seed: &[u8], sk: &mut [u8], pk: &mut [u8]) {
    let sk_seed = <&[u8; N]>::try_from(&seed[..N]).unwrap();
    let pk_seed = <&[u8; N]>::try_from(&seed[2 * N..3 * N]).unwrap();

    let hs = P::Hash::new(pk_seed);
    let pk_root = tree::root::<N, P>(&hs, sk_seed);

    sk[..3 * N].copy_from_slice(seed);
    sk[3 * N..].copy_from_slice(&pk_root);
    pk[..N].copy_from_slice(pk_seed);
    pk[N..].copy_from_slice(&pk_root);
}

/// The digest of a message, cut into the digest FORS signs and the indices of
/// the FORS key pair that signs it: the XMSS tree of the bottom layer, and the
/// leaf of that tree (FIPS 205 Algorithm 19, lines 7 to 13)
fn message_digest<const N: usize, P: ParameterSet<N>>(
    r: &[u8; N],
    pk_seed: &[u8; N],
    pk_root: &[u8; N],
    m: &[&[u8]],
) -> ([u8; MAX_M], u64, u32) {
    fn to_int(bytes: &[u8], bits: usize) -> u64 {
        let x = bytes.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
        if bits < 64 { x & ((1 << bits) - 1) } else { x }
    }

    let mut digest = [0u8; MAX_M];
    P::Hash::h_msg(r, pk_seed, pk_root, m, &mut digest[..P::M]);

    let (_, rest) = digest[..P::M].split_at(P::MD_BYTES);
    let (tree_bytes, leaf_bytes) = rest.split_at(P::TREE_BYTES);
    let idx_tree = to_int(tree_bytes, P::H - P::HP);
    let idx_leaf = to_int(leaf_bytes, P::HP) as u32;
    (digest, idx_tree, idx_leaf)
}

/// The `FORS_TREE` address of the FORS key pair `idx_leaf` of the tree `idx_tree`
fn fors_address(idx_tree: u64, idx_leaf: u32) -> Adrs {
    let mut adrs = Adrs::ZERO;
    adrs.set_tree(idx_tree);
    adrs.set_type_and_clear(AdrsType::ForsTree);
    adrs.set_keypair(idx_leaf);
    adrs
}

/// `slh_sign_internal` (FIPS 205 Algorithm 19) of the message given as the
/// pieces of `m`, with the `4 n` bytes signing key `sk`, into `sig`
fn sign_internal<const N: usize, P: ParameterSet<N>>(
    sk: &[u8],
    m: &[&[u8]],
    opt_rand: &[u8; N],
    sig: &mut [u8],
) {
    let part = |i: usize| <&[u8; N]>::try_from(&sk[i * N..(i + 1) * N]).unwrap();
    let (sk_seed, sk_prf, pk_seed, pk_root) = (part(0), part(1), part(2), part(3));

    let hs = P::Hash::new(pk_seed);

    let (r_sig, rest) = sig.split_at_mut(N);
    let (fors_sig, ht_sig) = rest.split_at_mut(P::SIG_FORS);

    let r = P::Hash::prf_msg(sk_prf, opt_rand, m);
    r_sig.copy_from_slice(&r);

    let (digest, idx_tree, idx_leaf) = message_digest::<N, P>(&r, pk_seed, pk_root, m);
    let adrs = fors_address(idx_tree, idx_leaf);
    let pk_fors = fors::sign::<N, P>(&hs, &digest[..P::MD_BYTES], sk_seed, &adrs, fors_sig);

    tree::ht_sign::<N, P>(&hs, &pk_fors, sk_seed, idx_tree, idx_leaf, ht_sig);
}

/// `slh_verify_internal` (FIPS 205 Algorithm 20) of the signature `sig` of the
/// message given as the pieces of `m`, with the `2 n` bytes verifying key `pk`
fn verify_internal<const N: usize, P: ParameterSet<N>>(pk: &[u8], m: &[&[u8]], sig: &[u8]) -> bool {
    let pk_seed = <&[u8; N]>::try_from(&pk[..N]).unwrap();
    let pk_root = <&[u8; N]>::try_from(&pk[N..]).unwrap();

    let hs = P::Hash::new(pk_seed);

    let (r, rest) = sig.split_at(N);
    let r = <&[u8; N]>::try_from(r).unwrap();
    let (fors_sig, ht_sig) = rest.split_at(P::SIG_FORS);

    let (digest, idx_tree, idx_leaf) = message_digest::<N, P>(r, pk_seed, pk_root, m);
    let adrs = fors_address(idx_tree, idx_leaf);
    let pk_fors = fors::pk_from_sig::<N, P>(&hs, fors_sig, &digest[..P::MD_BYTES], &adrs);

    tree::ht_verify::<N, P>(&hs, &pk_fors, ht_sig, idx_tree, idx_leaf, pk_root)
}

/// Define the module of one parameter set, with its keys, signature and
/// entry points
macro_rules! slhdsa_impl {
    ($(
        $module:ident, $set:literal, $hasher:ident,
        $n:literal, $h:literal, $d:literal, $hp:literal, $a:literal, $k:literal, $m:literal,
        $vk_len:literal, $sk_len:literal, $sig_len:literal;
    )*) => {$(
        #[doc = concat!("The ", $set, " parameter set")]
        ///
        /// See the [module documentation](super) for the description of the
        /// scheme and of its parameter sets.
        pub mod $module {
            use super::*;

            /// The parameters of the set
            pub(super) struct Params;

            impl ParameterSet<$n> for Params {
                const H: usize = $h;
                const D: usize = $d;
                const HP: usize = $hp;
                const A: usize = $a;
                const K: usize = $k;
                const M: usize = $m;
                type Hash = $hasher<$n>;
            }

            // check the literals against the formulas of FIPS 205 section 11,
            // and against the bounds the implementation sizes its arrays with
            const _: () = {
                type P = Params;
                assert!(<P as ParameterSet<$n>>::H == $d * $hp);
                assert!(<P as ParameterSet<$n>>::LEN <= params::MAX_LEN);
                assert!($hp <= params::MAX_HP && $a <= params::MAX_A && $k <= params::MAX_K);
                assert!($m <= params::MAX_M);
                assert!(
                    $m == <P as ParameterSet<$n>>::MD_BYTES
                        + <P as ParameterSet<$n>>::TREE_BYTES
                        + <P as ParameterSet<$n>>::LEAF_BYTES
                );
                // the tree index fits a u64, and the leaf and FORS leaf indices a u32
                assert!(<P as ParameterSet<$n>>::TREE_BYTES <= 8);
                assert!($hp < 32 && $k * (1 << $a) <= u32::MAX as usize);
                assert!($vk_len == 2 * $n);
                assert!($sk_len == 4 * $n);
                assert!($sig_len == <P as ParameterSet<$n>>::SIG);
            };

            /// Length in bytes of the seed taken by key generation, `SK.seed || SK.prf || PK.seed`
            pub const SEED_LENGTH: usize = 3 * $n;

            /// Length in bytes of the extra randomness taken by signing
            pub const RANDOMIZER_LENGTH: usize = $n;

            #[doc = concat!($set, " verifying key, the public half of a key pair")]
            #[derive(Clone)]
            pub struct VerifyingKey([u8; $vk_len]);

            #[doc = concat!($set, " signing key, the secret half of a key pair")]
            #[derive(Clone)]
            pub struct SigningKey([u8; $sk_len]);

            #[doc = concat!($set, " signature")]
            #[derive(Clone)]
            pub struct Signature([u8; $sig_len]);

            #[doc = concat!("Generate an ", $set, " key pair from `seed`")]
            ///
            /// `seed` must be [`SEED_LENGTH`] independent, freshly generated
            /// random bytes; see the
            /// [module documentation](crate::slhdsa#randomness).
            pub fn keypair(seed: &[u8; SEED_LENGTH]) -> (VerifyingKey, SigningKey) {
                let mut vk = [0u8; $vk_len];
                let mut sk = [0u8; $sk_len];
                keygen::<$n, Params>(seed, &mut sk, &mut vk);
                (VerifyingKey(vk), SigningKey(sk))
            }

            impl SigningKey {
                /// Length in bytes of the serialised key
                pub const LENGTH: usize = $sk_len;

                /// Deserialise a signing key
                ///
                /// Any bytes are a signing key: the `PK.root` it carries is not
                /// checked against the secret seed, which would cost as much as
                /// key generation. A key whose root does not belong to it
                /// simply signs nothing that its own verifying key accepts.
                pub fn from_bytes(bytes: [u8; $sk_len]) -> Self {
                    SigningKey(bytes)
                }

                /// The verifying key of the same key pair
                ///
                /// The signing key carries a copy of it, so this is cheap.
                pub fn verifying_key(&self) -> VerifyingKey {
                    VerifyingKey(self.0[2 * $n..].try_into().unwrap())
                }

                #[doc = concat!("Sign `message` with this ", $set, " key, hedging with `rnd`")]
                ///
                /// `rnd` should be freshly generated random bytes, and does not
                /// have to be kept secret; see the
                /// [module documentation](crate::slhdsa#randomness). `context`
                /// is bound into the signature and must be at most
                /// [`MAX_CONTEXT_LENGTH`] bytes, which is the only way this
                /// can fail.
                pub fn sign(
                    &self,
                    message: &[u8],
                    context: &[u8],
                    rnd: &[u8; RANDOMIZER_LENGTH],
                ) -> Result<Signature, SigningError> {
                    self.sign_with(None, message, context, rnd)
                }

                #[doc = concat!("Sign `message` with this ", $set, " key, without any randomness")]
                ///
                /// This is the deterministic variant of FIPS 205, which uses
                /// `PK.seed` in place of the randomness: the same message and
                /// context always give the same signature.
                pub fn sign_deterministic(
                    &self,
                    message: &[u8],
                    context: &[u8],
                ) -> Result<Signature, SigningError> {
                    self.sign_with(None, message, context, &self.pk_seed())
                }

                /// Sign a digest of `message` rather than the message itself,
                /// hedging with `rnd`
                ///
                /// This is `HashSLH-DSA` (FIPS 205 section 10.2.2); the
                /// signature it produces is not interchangeable with the one
                /// [`sign`](Self::sign) makes over the same message.
                pub fn sign_prehash(
                    &self,
                    prehash: PreHash,
                    message: &[u8],
                    context: &[u8],
                    rnd: &[u8; RANDOMIZER_LENGTH],
                ) -> Result<Signature, SigningError> {
                    self.sign_with(Some(prehash), message, context, rnd)
                }

                /// Sign a digest of `message` rather than the message itself,
                /// without any randomness
                pub fn sign_prehash_deterministic(
                    &self,
                    prehash: PreHash,
                    message: &[u8],
                    context: &[u8],
                ) -> Result<Signature, SigningError> {
                    self.sign_with(Some(prehash), message, context, &self.pk_seed())
                }

                fn pk_seed(&self) -> [u8; $n] {
                    self.0[2 * $n..3 * $n].try_into().unwrap()
                }

                fn sign_with(
                    &self,
                    prehash: Option<PreHash>,
                    message: &[u8],
                    context: &[u8],
                    opt_rand: &[u8; $n],
                ) -> Result<Signature, SigningError> {
                    let mut sig = [0u8; $sig_len];
                    dsa_prehash::message_representative(prehash, message, context, |m| {
                        sign_internal::<$n, Params>(&self.0, m, opt_rand, &mut sig)
                    })
                    .ok_or(SigningError::InvalidContextLength)?;
                    Ok(Signature(sig))
                }

                /// Raw bytes array for the signing key
                pub fn bytes(&self) -> &[u8; $sk_len] {
                    &self.0
                }
            }

            impl VerifyingKey {
                /// Length in bytes of the serialised key
                pub const LENGTH: usize = $vk_len;

                /// Deserialise a verifying key
                ///
                /// Verifying Key doesn't need a particular structure, any bytes
                /// encoding lead to a valid verifying key.
                pub fn from_bytes(bytes: [u8; $vk_len]) -> Self {
                    VerifyingKey(bytes)
                }

                #[doc = concat!("Verify an ", $set, " signature over `message`")]
                ///
                /// `context` must be the one the signature was made with, and
                /// the signature must have been made by
                /// [`SigningKey::sign`] rather than by one of the pre hash
                /// methods, or this returns false.
                pub fn verify(
                    &self,
                    message: &[u8],
                    context: &[u8],
                    signature: &Signature,
                ) -> bool {
                    self.verify_with(None, message, context, signature)
                }

                /// Verify a signature made by [`SigningKey::sign_prehash`]
                ///
                /// `prehash` must be the hash function the signer used: a
                /// signature over a digest of one function is not accepted as
                /// one over the digest of another.
                pub fn verify_prehash(
                    &self,
                    prehash: PreHash,
                    message: &[u8],
                    context: &[u8],
                    signature: &Signature,
                ) -> bool {
                    self.verify_with(Some(prehash), message, context, signature)
                }

                fn verify_with(
                    &self,
                    prehash: Option<PreHash>,
                    message: &[u8],
                    context: &[u8],
                    signature: &Signature,
                ) -> bool {
                    dsa_prehash::message_representative(prehash, message, context, |m| {
                        verify_internal::<$n, Params>(&self.0, m, &signature.0)
                    })
                    .unwrap_or(false)
                }

                /// Raw bytes array for the verifying key
                pub fn bytes(&self) -> &[u8; $vk_len] {
                    &self.0
                }
            }

            impl Signature {
                /// Length in bytes of the serialised signature
                pub const LENGTH: usize = $sig_len;

                /// Deserialise a signature
                ///
                /// Any bytes of the right length are a signature, which is
                /// either valid or not for a given key and message.
                pub fn from_bytes(bytes: [u8; $sig_len]) -> Self {
                    Signature(bytes)
                }

                /// Raw bytes array for the signature
                pub fn bytes(&self) -> &[u8; $sig_len] {
                    &self.0
                }
            }

            impl From<[u8; $vk_len]> for VerifyingKey {
                fn from(bytes: [u8; $vk_len]) -> Self {
                    VerifyingKey(bytes)
                }
            }

            impl From<[u8; $sig_len]> for Signature {
                fn from(bytes: [u8; $sig_len]) -> Self {
                    Signature(bytes)
                }
            }

            impl AsRef<[u8]> for VerifyingKey {
                fn as_ref(&self) -> &[u8] {
                    &self.0[..]
                }
            }

            impl AsRef<[u8]> for SigningKey {
                fn as_ref(&self) -> &[u8] {
                    &self.0[..]
                }
            }

            impl AsRef<[u8]> for Signature {
                fn as_ref(&self) -> &[u8] {
                    &self.0[..]
                }
            }
        }
    )*};
}

// FIPS 205 Table 2
slhdsa_impl! {
    // module    name                  family       n   h   d   h'  a   k   m   vk  sk   signature
    sha2_128s,  "SLH-DSA-SHA2-128s",  Sha2Hasher,  16, 63, 7,  9,  12, 14, 30, 32, 64,  7856;
    sha2_128f,  "SLH-DSA-SHA2-128f",  Sha2Hasher,  16, 66, 22, 3,  6,  33, 34, 32, 64,  17088;
    sha2_192s,  "SLH-DSA-SHA2-192s",  Sha2Hasher,  24, 63, 7,  9,  14, 17, 39, 48, 96,  16224;
    sha2_192f,  "SLH-DSA-SHA2-192f",  Sha2Hasher,  24, 66, 22, 3,  8,  33, 42, 48, 96,  35664;
    sha2_256s,  "SLH-DSA-SHA2-256s",  Sha2Hasher,  32, 64, 8,  8,  14, 22, 47, 64, 128, 29792;
    sha2_256f,  "SLH-DSA-SHA2-256f",  Sha2Hasher,  32, 68, 17, 4,  9,  35, 49, 64, 128, 49856;
    shake_128s, "SLH-DSA-SHAKE-128s", ShakeHasher, 16, 63, 7,  9,  12, 14, 30, 32, 64,  7856;
    shake_128f, "SLH-DSA-SHAKE-128f", ShakeHasher, 16, 66, 22, 3,  6,  33, 34, 32, 64,  17088;
    shake_192s, "SLH-DSA-SHAKE-192s", ShakeHasher, 24, 63, 7,  9,  14, 17, 39, 48, 96,  16224;
    shake_192f, "SLH-DSA-SHAKE-192f", ShakeHasher, 24, 66, 22, 3,  8,  33, 42, 48, 96,  35664;
    shake_256s, "SLH-DSA-SHAKE-256s", ShakeHasher, 32, 64, 8,  8,  14, 22, 47, 64, 128, 29792;
    shake_256f, "SLH-DSA-SHAKE-256f", ShakeHasher, 32, 68, 17, 4,  9,  35, 49, 64, 128, 49856;
}

#[cfg(all(test, feature = "with-bench"))]
mod bench {
    use test::Bencher;

    macro_rules! bench_parameter_set {
        ($($set:ident, $b_keypair:ident, $b_sign:ident, $b_verify:ident;)*) => {$(
            #[bench]
            pub fn $b_keypair(bh: &mut Bencher) {
                use super::$set::*;
                bh.iter(|| keypair(&[1u8; SEED_LENGTH]));
            }

            #[bench]
            pub fn $b_sign(bh: &mut Bencher) {
                use super::$set::*;
                let (_, sk) = keypair(&[1u8; SEED_LENGTH]);
                bh.iter(|| sk.sign(b"message", b"", &[2u8; RANDOMIZER_LENGTH]).unwrap());
            }

            #[bench]
            pub fn $b_verify(bh: &mut Bencher) {
                use super::$set::*;
                let (vk, sk) = keypair(&[1u8; SEED_LENGTH]);
                let sig = sk.sign(b"message", b"", &[2u8; RANDOMIZER_LENGTH]).unwrap();
                bh.iter(|| assert!(vk.verify(b"message", b"", &sig)));
            }
        )*};
    }

    bench_parameter_set! {
        sha2_128s, keypair_sha2_128s, sign_sha2_128s, verify_sha2_128s;
        sha2_128f, keypair_sha2_128f, sign_sha2_128f, verify_sha2_128f;
        sha2_192s, keypair_sha2_192s, sign_sha2_192s, verify_sha2_192s;
        sha2_192f, keypair_sha2_192f, sign_sha2_192f, verify_sha2_192f;
        sha2_256s, keypair_sha2_256s, sign_sha2_256s, verify_sha2_256s;
        sha2_256f, keypair_sha2_256f, sign_sha2_256f, verify_sha2_256f;
        shake_128s, keypair_shake_128s, sign_shake_128s, verify_shake_128s;
        shake_128f, keypair_shake_128f, sign_shake_128f, verify_shake_128f;
        shake_192s, keypair_shake_192s, sign_shake_192s, verify_shake_192s;
        shake_192f, keypair_shake_192f, sign_shake_192f, verify_shake_192f;
        shake_256s, keypair_shake_256s, sign_shake_256s, verify_shake_256s;
        shake_256f, keypair_shake_256f, sign_shake_256f, verify_shake_256f;
    }
}
