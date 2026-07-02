#[cfg(all(target_arch = "aarch64", target_feature = "sha3"))]
mod aarch64;

mod reference;

pub(crate) fn digest_block(state: &mut [u64; 8], block: &[u8]) {
    #[cfg(all(target_arch = "aarch64", target_feature = "sha3"))]
    {
        return aarch64::digest_block(state, block);
    }
    #[allow(unreachable_code)]
    reference::digest_block(state, block)
}
