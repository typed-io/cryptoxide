//! SHA512 engine
//!
//! The backend available at compile time:
//!
//! * On x86-64 with the `avx2` target feature (4 blocks at a time)
//! * On x86-64 with the `sse4.1` target feature (2 blocks at a time)
//! * On aarch64 with the `sha3` target feature, the ARMv8.2 Cryptography Extensions are used.
//! * portable software implementation
//!

#[cfg(all(target_arch = "aarch64", target_feature = "sha3"))]
mod aarch64;

// x86-64 multi-block message schedule backends.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
mod avx2;

#[cfg(all(target_arch = "x86_64", target_feature = "sse4.1"))]
mod sse41;

// software implementation valid for all architectures
mod reference;

pub(crate) fn digest_block(state: &mut [u64; 8], block: &[u8]) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        return avx2::digest_block(state, block);
    }

    #[cfg(all(
        target_arch = "x86_64",
        not(target_feature = "avx2"),
        target_feature = "sse4.1"
    ))]
    {
        return sse41::digest_block(state, block);
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "sha3"))]
    {
        return aarch64::digest_block(state, block);
    }
    #[allow(unreachable_code)]
    reference::digest_block(state, block)
}
