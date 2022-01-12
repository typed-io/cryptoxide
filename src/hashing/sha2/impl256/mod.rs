//! Optimised SHA256 engine
//!
//! Reference implementation come from haskell's cryptonite cbits
//!
//! SSE and AVX optimisation are coming from
//! <https://eprint.iacr.org/2012/067.pdf> and consist
//! of creating the message schedule of 4 (SSE) or 8 (AVX) blocks
//! at a time, then using the standard ALU to do the compression.
//!
mod reference;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse4.1"
))]
mod sse41;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    all(target_feature = "sse4.1", target_feature = "avx"),
))]
mod avx;

#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    any(target_feature = "sse4.1", target_feature = "avx")
)))]
pub(crate) use reference::*;

#[cfg(all(
    target_arch = "x86_64",
    all(target_feature = "sse4.1", not(target_feature = "avx")),
))]
pub(crate) use sse41::*;

#[cfg(all(
    target_arch = "x86_64",
    all(target_feature = "sse4.1", target_feature = "avx"),
))]
pub(crate) use avx::*;

/*
#[cfg(all(any(target_arch = "x86_64"), target_feature = "sha"))]
mod x64sha;

#[cfg(all(any(target_arch = "x86_64"), target_feature = "sha",))]
pub(crate) use x64sha::*;
*/
