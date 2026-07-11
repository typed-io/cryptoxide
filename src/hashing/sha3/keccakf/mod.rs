//! The Keccak-f[1600] permutation, the core primitive of SHA-3 and Keccak.
//!
//! The permutation operates on the 200-byte (25 x 64-bit lanes) sponge state.
//! A portable [`reference`] implementation is always available; on aarch64 with
//! the `sha3` target feature an [`aarch64`] backend using the ARMv8.2 SHA-3
//! crypto extensions (`eor3`, `rax1`, `xar`, `bcax`) is selected instead.

#[cfg(all(target_arch = "aarch64", target_feature = "sha3"))]
mod aarch64;

mod reference;

/// Number of rounds of the Keccak-f[1600] permutation.
pub(super) const NROUNDS: usize = 24;

/// Round constants applied during the Iota step.
pub(super) const RC: [u64; NROUNDS] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Apply the Keccak-f[1600] permutation in-place on the sponge state.
pub(super) fn keccak_f(state: &mut [u8; super::B]) {
    #[cfg(all(target_arch = "aarch64", target_feature = "sha3"))]
    {
        return aarch64::keccak_f(state);
    }
    #[allow(unreachable_code)]
    reference::keccak_f(state)
}
