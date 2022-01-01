//! Scalar functions in \Z/(2^252 + 27742317777372353535851937790883648493)

#[cfg(any(any(target_arch = "arm"), feature = "force-32bits"))]
mod scalar32;

#[cfg(not(any(any(target_arch = "arm"), feature = "force-32bits")))]
mod scalar64;

#[cfg(any(any(target_arch = "arm"), feature = "force-32bits"))]
pub(crate) use scalar32::*;

#[cfg(not(any(any(target_arch = "arm"), feature = "force-32bits")))]
pub(crate) use scalar64::*;
