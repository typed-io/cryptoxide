//! The hash function address `ADRS` (FIPS 205 section 4.2)
//!
//! Every call of a tweakable hash function is made unique by a 32 bytes
//! address, which locates it in the hypertree:
//!
//! | bytes  | field                                                          |
//! | ------ | -------------------------------------------------------------- |
//! | 0..4   | layer address, the XMSS layer of the hypertree                 |
//! | 4..16  | tree address, the index of the XMSS tree within its layer      |
//! | 16..20 | type, one of the [`AdrsType`]                                  |
//! | 20..24 | key pair address, the WOTS+ or FORS key pair within its tree   |
//! | 24..28 | chain address (WOTS+) or tree height (XMSS, FORS)              |
//! | 28..32 | hash address (WOTS+) or tree index (XMSS, FORS)                |
//!
//! The SHA2 parameter sets hash a compressed form of it instead (section 11.2),
//! see [`Adrs::compressed`].

/// Length in bytes of an address
pub(super) const ADRS_LEN: usize = 32;

/// Length in bytes of the compressed address `ADRSc` of the SHA2 parameter sets
pub(super) const ADRSC_LEN: usize = 22;

/// The type of an address, which selects how its last 12 bytes are read
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(super) enum AdrsType {
    WotsHash = 0,
    WotsPk = 1,
    Tree = 2,
    ForsTree = 3,
    ForsRoots = 4,
    WotsPrf = 5,
    ForsPrf = 6,
}

/// A hash function address
#[derive(Clone, Copy)]
pub(super) struct Adrs(pub(super) [u8; ADRS_LEN]);

impl Adrs {
    /// The all zero address, the one every algorithm starts from
    pub(super) const ZERO: Self = Adrs([0; ADRS_LEN]);

    fn set_word(&mut self, offset: usize, value: u32) {
        self.0[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn word(&self, offset: usize) -> u32 {
        u32::from_be_bytes(self.0[offset..offset + 4].try_into().unwrap())
    }

    /// Set the layer address
    pub(super) fn set_layer(&mut self, layer: u32) {
        self.set_word(0, layer);
    }

    /// Set the tree address
    ///
    /// The field is 12 bytes, but no parameter set has a tree index of more
    /// than 64 bits, so its first 4 bytes always stay zero.
    pub(super) fn set_tree(&mut self, tree: u64) {
        self.0[4..8].fill(0);
        self.0[8..16].copy_from_slice(&tree.to_be_bytes());
    }

    /// Set the type, clearing the last 12 bytes whose meaning depends on it
    pub(super) fn set_type_and_clear(&mut self, ty: AdrsType) {
        self.set_word(16, ty as u32);
        self.0[20..32].fill(0);
    }

    /// Set the key pair address
    pub(super) fn set_keypair(&mut self, keypair: u32) {
        self.set_word(20, keypair);
    }

    /// The key pair address
    pub(super) fn keypair(&self) -> u32 {
        self.word(20)
    }

    /// Set the chain address, of the WOTS+ addresses
    pub(super) fn set_chain(&mut self, chain: u32) {
        self.set_word(24, chain);
    }

    /// Set the hash address, of the WOTS+ addresses
    pub(super) fn set_hash(&mut self, hash: u32) {
        self.set_word(28, hash);
    }

    /// Set the tree height, of the XMSS and FORS addresses
    pub(super) fn set_tree_height(&mut self, height: u32) {
        self.set_word(24, height);
    }

    /// Set the tree index, of the XMSS and FORS addresses
    pub(super) fn set_tree_index(&mut self, index: u32) {
        self.set_word(28, index);
    }

    /// A copy of this address with another type, keeping the key pair address
    ///
    /// This is how WOTS+ and FORS derive the address of their secret values
    /// and of their public key compression from the one they are given.
    pub(super) fn with_type_keeping_keypair(&self, ty: AdrsType) -> Self {
        let mut adrs = *self;
        adrs.set_type_and_clear(ty);
        adrs.set_keypair(self.keypair());
        adrs
    }

    /// The compressed address `ADRSc` (FIPS 205 section 11.2)
    ///
    /// The layer and type fit in a byte, and the tree index in 8 bytes, which
    /// saves enough of the address for the hashed input to fit a single
    /// compression of the SHA2 function.
    pub(super) fn compressed(&self) -> [u8; ADRSC_LEN] {
        let mut c = [0u8; ADRSC_LEN];
        c[0] = self.0[3];
        c[1..9].copy_from_slice(&self.0[8..16]);
        c[9] = self.0[19];
        c[10..22].copy_from_slice(&self.0[20..32]);
        c
    }
}
