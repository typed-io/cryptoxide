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
