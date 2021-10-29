pub mod b {
    pub const BLOCK_BYTES: usize = 128;
    pub const MAX_KEYLEN: usize = 64;
    pub const MAX_OUTLEN: usize = 64;
    pub const R1: u32 = 32;
    pub const R2: u32 = 24;
    pub const R3: u32 = 16;
    pub const R4: u32 = 63;

    pub const IV: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    pub const ROUNDS: usize = 12;
}

pub mod s {
    pub const BLOCK_BYTES: usize = 64;
    pub const MAX_KEYLEN: usize = 32;
    pub const MAX_OUTLEN: usize = 32;
    pub const R1: u32 = 16;
    pub const R2: u32 = 12;
    pub const R3: u32 = 8;
    pub const R4: u32 = 7;

    pub const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];

    pub const ROUNDS: usize = 10;
}

// SIGMA is the same for the b and s variant. except that
// in the B variant, there's a 11th and 12th row that is copy of
// the 1st and 2nd.
pub const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// Parameter when hashing the last block for the engine compress function
///
/// see [super::EngineB::compress] or [super::EngineS::compress]
#[derive(Clone, PartialEq, Eq)]
pub enum LastBlock {
    /// To use when this is the last block to process, otherwise use [`LastBlock::No`]
    Yes,
    /// To use for all block to compress except the last one
    No,
}
