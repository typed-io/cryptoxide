pub(crate) mod load;

#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse4.1"
)))]
mod fe32;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse4.1",
    target_feature = "nyip"
))]
mod fe64;

#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse4.1"
)))]
pub use fe32::*;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse4.1",
    target_feature = "nyip"
))]
pub use fe64::*;
