mod reference;

pub(crate) fn digest_block(state: &mut [u64; 8], block: &[u8]) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {}
    #[cfg(any(target_arch = "aarch64"))]
    {}
    reference::digest_block(state, block)
}
