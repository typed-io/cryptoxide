//! Blake2 hash function
//!
//! Blake2 [Specification][1].
//!
//! [1]: https://eprint.iacr.org/2013/322.pdf

mod common;
mod reference;

pub use common::LastBlock;

#[cfg(all(target_arch = "x86_64", target_feature = "avx"))]
mod avx;

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
mod avx2;

mod implementation {
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx")))]
    pub use super::reference::{EngineB, EngineS};

    #[cfg(all(target_arch = "x86_64", target_feature = "avx"))]
    pub use super::avx::EngineS;

    #[cfg(all(
        target_arch = "x86_64",
        all(target_feature = "avx", not(target_feature = "avx2"))
    ))]
    pub use super::avx::EngineB;

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    pub use super::avx2::EngineB;
}

pub use implementation::{EngineB, EngineS};
