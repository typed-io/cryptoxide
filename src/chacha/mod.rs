//! ChaCha Stream Cipher -- Engine implementation
//!
//! Implementation of [ChaCha spec](https://www.rfc-editor.org/info/rfc7539)
//! which is a fast and lean stream cipher.
//!
//! The maximum amount of data to be processed by a single instance of a ChaCha
//! Context, is 256Gb (due to the 32 bits counter). Note that this is not
//! enforced by the context, and using a context to process more than 256Gb of
//! data would be insecure.
//!
//! The Engine is parametrized with the number of rounds to execute, which is
//! enforced by assertion to be either 8, 12 or 20.
//!
//! Note that with stream cipher, there's only one operation [`ChaChaEngine::<N>::process`]
//! and its variant [`ChaChaEngine::<N>::process_mut`] instead of the typical
//! cipher operation encrypt and decrypt.
//!

#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    any(target_feature = "sse2", target_feature = "avx2")
)))]
mod reference;

#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    any(target_feature = "sse2", target_feature = "avx2")
)))]
pub(crate) type ChaChaEngine<const R: usize> = reference::State<R>;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2",
))]
mod sse2;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2",
))]
pub(crate) type ChaChaEngine<const R: usize> = sse2::State<R>;
