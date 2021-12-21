//! Field Element implementation with 64-bits native unsaturated 51-bits limbs.

/// Field Element in \Z/(2^255-19)
#[derive(Clone)]
pub struct Fe([u64; 5]);
