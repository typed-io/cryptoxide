//! Optimised SHA256 engine
//!
//! Reference implementation come from haskell's cryptonite cbits
//!
//! The backend is selected at compile time:
//!
//! * On x86/x86-64 with the `sha` and `sse4.1` target features, the SHA-NI
//!   instructions (`sha256rnds2`, `sha256msg1`, `sha256msg2`) are used.
//! * On x86/x86-64 with the `avx2` (or, failing that, `sse4.1`) target feature,
//!   the message schedule of 8 (AVX2) or 4 (SSE4.1) blocks is computed at a time
//!   and the compression is then done with the standard ALU, following
//!   <https://eprint.iacr.org/2012/067.pdf>
//! * On aarch64 with the `sha2` target feature, the ARMv8 Cryptography
//!   Extensions are used.
//! * Otherwise, a portable software implementation is used.
//!
//! The SIMD backends only accelerate the bulk of a long message; each of them
//! hands whatever does not fill its multi-block unit to the next one down.

// x86 SHA-NI backend.
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sha",
    target_feature = "sse4.1"
))]
mod shani;

// x86 multi-block message schedule backends.
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    not(all(target_feature = "sha", target_feature = "sse4.1")),
    target_feature = "avx2"
))]
mod avx2;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    not(all(target_feature = "sha", target_feature = "sse4.1")),
    target_feature = "sse4.1"
))]
mod sse41;

// ARMv8 Cryptography Extensions backend.
#[cfg(all(target_arch = "aarch64", target_feature = "sha2"))]
mod aarch64;

// software implementation valid for all architectures
mod reference;

pub(crate) fn digest_block(state: &mut [u32; 8], block: &[u8]) {
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sha",
        target_feature = "sse4.1"
    ))]
    {
        return shani::digest_block(state, block);
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        not(all(target_feature = "sha", target_feature = "sse4.1")),
        target_feature = "avx2"
    ))]
    {
        return avx2::digest_block(state, block);
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        not(all(target_feature = "sha", target_feature = "sse4.1")),
        not(target_feature = "avx2"),
        target_feature = "sse4.1"
    ))]
    {
        return sse41::digest_block(state, block);
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "sha2"))]
    {
        return aarch64::digest_block(state, block);
    }

    #[allow(unreachable_code)]
    reference::digest_block(state, block)
}
