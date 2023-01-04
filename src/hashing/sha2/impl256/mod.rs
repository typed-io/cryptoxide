//! Optimised SHA256 engine
//!
//! Reference implementation come from haskell's cryptonite cbits
//!
//! SSE and AVX optimisation are coming from
//! <https://eprint.iacr.org/2012/067.pdf> and consist
//! of creating the message schedule of 4 (SSE) or 8 (AVX) blocks
//! at a time, then using the standard ALU to do the compression.
//!

#[cfg(all(target_arch = "aarch64", feature = "use-stdsimd"))]
mod aarch64;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "avx"
))]
mod avx;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse4.1"
))]
mod sse41;
//TODO not finished yet
//#[cfg(all(target_arch = "x86_64", target_feature = "sha"))]
//mod x64sha;

// software implementation valid for all architectures
mod reference;

pub(crate) fn digest_block(state: &mut [u32; 8], block: &[u8]) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        /// in waiting for https://github.com/rust-lang/rfcs/pull/2725
        #[cfg(target_feature = "avx")]
        const HAS_AVX: bool = true;
        #[cfg(not(target_feature = "avx"))]
        const HAS_AVX: bool = false;

        #[cfg(target_feature = "sse4.1")]
        const HAS_SSE41: bool = true;
        #[cfg(not(target_feature = "sse4.1"))]
        const HAS_SSE41: bool = false;

        #[cfg(target_feature = "avx")]
        {
            if HAS_AVX {
                return avx::digest_block(state, block);
            }
        }

        #[cfg(target_feature = "sse4.1")]
        {
            if HAS_SSE41 {
                return sse41::digest_block(state, block);
            }
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        #[cfg(feature = "use-stdsimd")]
        if true {
            return aarch64::digest_block(state, block);
        }
    }
    reference::digest_block(state, block)
}
