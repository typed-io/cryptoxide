mod common;
mod reference;

pub use common::LastBlock;

#[cfg(all(target_arch = "x86_64", target_feature = "avx"))]
mod avx;

#[cfg(not(all(target_arch = "x86_64", target_feature = "avx")))]
pub use reference::{EngineB, EngineS};

#[cfg(all(target_arch = "x86_64", target_feature = "avx"))]
pub use avx::{EngineB, EngineS};
