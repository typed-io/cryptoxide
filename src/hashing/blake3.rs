//! Blake3 hash function
//!
//! Blake3 [Specification][1].
//!
//! Note that this implementation doesn't take advantages of parallelism speed-up now,
//! nor that this implementation has any SIMD support right now.
//!
//! # Example
//!
//! Hashing using Blake3
//!
//! ```
//! use cryptoxide::hashing::blake3::Blake3;
//!
//! let mut context = Blake3::new();
//! context.update_mut(b"hello world");
//! let digest = context.finalize::<32>();
//! ```
//!
//! [1]: <https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf>

use crate::cryptoutil::{read_u32v_le, write_u32v_le};

/// Block size in bytes (same as BLAKE2s)
const BLOCK_BYTES: usize = 64;

/// Chunk size in bytes (16 blocks)
const CHUNK_LEN: usize = 1024;

const FLAG_CHUNK_START: u32 = 1 << 0; // first block of a chunk
const FLAG_CHUNK_END: u32 = 1 << 1; // last block of a chunk
const FLAG_PARENT: u32 = 1 << 2; // parent node in the merkle tree
const FLAG_ROOT: u32 = 1 << 3; // enables XOF output
const FLAG_KEYED_HASH: u32 = 1 << 4; // keyed hash mode
const FLAG_DERIVE_KEY_CONTEXT: u32 = 1 << 5; // derive key context phase
const FLAG_DERIVE_KEY_MATERIAL: u32 = 1 << 6; // derive key material phase

const MAX_DEPTH: usize = 54; // 2^54 * CHUNK_LEN = 2^64

/// Message word permutation applied between rounds
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// Initialization vector, same as Blake2s IV
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

// The G mixing function (quarter-round).
// Rotation constants are the same as BLAKE2s: 16, 12, 8, 7.
#[inline(always)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

// One round of column mixing followed by diagonal mixing.
fn round(state: &mut [u32; 16], msg: &[u32; 16]) {
    // Column step
    g(state, 0, 4, 8, 12, msg[0], msg[1]);
    g(state, 1, 5, 9, 13, msg[2], msg[3]);
    g(state, 2, 6, 10, 14, msg[4], msg[5]);
    g(state, 3, 7, 11, 15, msg[6], msg[7]);
    // Diagonal step
    g(state, 0, 5, 10, 15, msg[8], msg[9]);
    g(state, 1, 6, 11, 12, msg[10], msg[11]);
    g(state, 2, 7, 8, 13, msg[12], msg[13]);
    g(state, 3, 4, 9, 14, msg[14], msg[15]);
}

// Apply the message word permutation between rounds.
fn permute(msg: &mut [u32; 16]) {
    let permuted = core::array::from_fn(|i| msg[MSG_PERMUTATION[i]]);
    *msg = permuted;
}

/// BLAKE3 compression function.
///
/// Takes a chaining value, block words, counter, block length, and flags,
/// and produces a 16-word state output. The compression performs 7 rounds
/// of column/diagonal mixing with message word permutation between rounds.
fn compress(
    chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut msg = *block_words;

    // 7 rounds total: 6 rounds of (round + permute), then 1 final round
    round(&mut state, &msg);
    permute(&mut msg);
    round(&mut state, &msg);
    permute(&mut msg);
    round(&mut state, &msg);
    permute(&mut msg);
    round(&mut state, &msg);
    permute(&mut msg);
    round(&mut state, &msg);
    permute(&mut msg);
    round(&mut state, &msg);
    permute(&mut msg);
    round(&mut state, &msg);

    // Finalization: XOR both halves with chaining value
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i];
    }

    state
}

struct Output {
    input_chaining_value: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        let compressed = compress(
            &self.input_chaining_value,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        );
        let mut out = [0u32; 8];
        out.copy_from_slice(&compressed[..8]);
        out
    }

    fn root_output_bytes(&self, out: &mut [u8]) {
        let mut output_block_counter: u64 = 0;
        let mut pos = 0;
        while pos < out.len() {
            let words = compress(
                &self.input_chaining_value,
                &self.block_words,
                output_block_counter,
                self.block_len,
                self.flags | FLAG_ROOT,
            );
            let mut block_bytes = [0u8; 64];
            write_u32v_le(&mut block_bytes, &words);
            let take = core::cmp::min(64, out.len() - pos);
            out[pos..pos + take].copy_from_slice(&block_bytes[..take]);
            pos += take;
            output_block_counter += 1;
        }
    }

    fn into_output_reader(self) -> OutputReader {
        OutputReader {
            input_chaining_value: self.input_chaining_value,
            block_words: self.block_words,
            block_len: self.block_len,
            flags: self.flags,
            counter: 0,
            buffer: [0u8; 64],
            buffer_pos: 64, // triggers compression on first fill()
        }
    }
}

#[derive(Clone)]
struct ChunkState {
    chaining_value: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_BYTES],
    block_len: u8,
    blocks_compressed: u8,
    flags: u32,
}

impl ChunkState {
    fn new(key_words: &[u32; 8], chunk_counter: u64, flags: u32) -> Self {
        ChunkState {
            chaining_value: *key_words,
            chunk_counter,
            block: [0u8; BLOCK_BYTES],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_BYTES * self.blocks_compressed as usize + self.block_len as usize
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            FLAG_CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            // If the block buffer is full, compress it
            if self.block_len as usize == BLOCK_BYTES {
                let mut block_words = [0u32; 16];
                read_u32v_le(&mut block_words, &self.block);
                let out = compress(
                    &self.chaining_value,
                    &block_words,
                    self.chunk_counter,
                    BLOCK_BYTES as u32,
                    self.flags | self.start_flag(),
                );
                self.chaining_value.copy_from_slice(&out[..8]);
                self.blocks_compressed += 1;
                self.block = [0u8; BLOCK_BYTES];
                self.block_len = 0;
            }

            // Copy input into the block buffer
            let want = BLOCK_BYTES - self.block_len as usize;
            let take = core::cmp::min(want, input.len());
            self.block[self.block_len as usize..self.block_len as usize + take]
                .copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        let mut block_words = [0u32; 16];
        read_u32v_le(&mut block_words, &self.block);
        Output {
            input_chaining_value: self.chaining_value,
            block_words,
            counter: self.chunk_counter,
            block_len: self.block_len as u32,
            flags: self.flags | self.start_flag() | FLAG_CHUNK_END,
        }
    }
}

fn parent_output(
    left_cv: [u32; 8],
    right_cv: [u32; 8],
    key_words: &[u32; 8],
    flags: u32,
) -> Output {
    let mut block_words = [0u32; 16];
    block_words[..8].copy_from_slice(&left_cv);
    block_words[8..].copy_from_slice(&right_cv);
    Output {
        input_chaining_value: *key_words,
        block_words,
        counter: 0,
        block_len: BLOCK_BYTES as u32,
        flags: flags | FLAG_PARENT,
    }
}

fn parent_cv(left_cv: [u32; 8], right_cv: [u32; 8], key_words: &[u32; 8], flags: u32) -> [u32; 8] {
    parent_output(left_cv, right_cv, key_words, flags).chaining_value()
}

/// Blake3 algorithm
///
/// # Modes
///
/// * **Hash mode** -- [`Blake3::new()`]
/// * **Keyed hash mode** -- [`Blake3::new_keyed()`]
/// * **Key derivation mode** -- [`Blake3::new_derive_key()`]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Blake3;

impl Blake3 {
    /// The block size in bytes of the algorithm
    pub const BLOCK_BYTES: usize = BLOCK_BYTES;

    /// Create a new hash-mode context
    pub fn new() -> Context {
        Context::new()
    }

    /// Create a new keyed-hash context with a 32-byte key
    pub fn new_keyed(key: &[u8; 32]) -> Context {
        Context::new_keyed(key)
    }

    /// Create a new derive-key context from a context string
    ///
    /// The context string should be a hardcoded, globally unique,
    /// application-specific string.
    pub fn new_derive_key(context: &str) -> Context {
        Context::new_derive_key(context)
    }
}

/// Blake3 streaming hash context
///
/// Maintains the Merkle tree state internally via a fixed-size chaining
/// value stack. Supports incremental hashing through [`update`](Context::update)
/// (immutable) and [`update_mut`](Context::update_mut) (mutable) methods.
///
/// Finalization can produce either a fixed-size digest or an
/// [`OutputReader`] for arbitrary-length XOF output.
#[derive(Clone)]
pub struct Context {
    chunk_state: ChunkState,
    key_words: [u32; 8],
    cv_stack: [[u32; 8]; MAX_DEPTH],
    cv_stack_len: u8,
    flags: u32,
}

impl Context {
    /// Create a new hash-mode context
    pub fn new() -> Self {
        Self::new_internal(IV, 0)
    }

    /// Create a new keyed-hash context with a 32-byte key
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        let mut key_words = [0u32; 8];
        read_u32v_le(&mut key_words, key);
        Self::new_internal(key_words, FLAG_KEYED_HASH)
    }

    /// Create a new derive-key context from a context string
    ///
    /// This uses a two-phase initialization: the context string is
    /// first hashed with `DERIVE_KEY_CONTEXT` flags to produce key words,
    /// which then initialize a hasher with `DERIVE_KEY_MATERIAL` flags.
    pub fn new_derive_key(context: &str) -> Self {
        // Phase 1: hash the context string
        let mut context_hasher = Self::new_internal(IV, FLAG_DERIVE_KEY_CONTEXT);
        context_hasher.update_mut(context.as_bytes());
        let mut context_key = [0u8; 32];
        context_hasher
            .final_output()
            .root_output_bytes(&mut context_key);

        // Phase 2: use the derived key words
        let mut context_key_words = [0u32; 8];
        read_u32v_le(&mut context_key_words, &context_key);
        Self::new_internal(context_key_words, FLAG_DERIVE_KEY_MATERIAL)
    }

    fn new_internal(key_words: [u32; 8], flags: u32) -> Self {
        Context {
            chunk_state: ChunkState::new(&key_words, 0, flags),
            key_words,
            cv_stack: [[0u32; 8]; MAX_DEPTH],
            cv_stack_len: 0,
            flags,
        }
    }

    fn push_stack(&mut self, cv: [u32; 8]) {
        self.cv_stack[self.cv_stack_len as usize] = cv;
        self.cv_stack_len += 1;
    }

    fn pop_stack(&mut self) -> [u32; 8] {
        self.cv_stack_len -= 1;
        self.cv_stack[self.cv_stack_len as usize]
    }

    fn add_chunk_chaining_value(&mut self, mut new_cv: [u32; 8], mut total_chunks: u64) {
        // Merge completed binary subtrees using trailing zero bits
        while total_chunks & 1 == 0 {
            new_cv = parent_cv(self.pop_stack(), new_cv, &self.key_words, self.flags);
            total_chunks >>= 1;
        }
        self.push_stack(new_cv);
    }

    /// Update the hashing state by adding the input bytes slice into the state
    ///
    /// This is the immutable builder-style API that consumes and returns the context.
    pub fn update(mut self, input: &[u8]) -> Self {
        self.update_mut(input);
        self
    }

    /// Update in-place the hashing state by adding the input bytes slice into the state
    ///
    /// For the immutable version see [`update`](Context::update).
    pub fn update_mut(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            // If the current chunk is complete, finalize it and start a new one
            if self.chunk_state.len() == CHUNK_LEN {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_chaining_value(chunk_cv, total_chunks);
                self.chunk_state = ChunkState::new(&self.key_words, total_chunks, self.flags);
            }

            // Fill the current chunk with as much input as possible
            let want = CHUNK_LEN - self.chunk_state.len();
            let take = core::cmp::min(want, input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    fn final_output(&self) -> Output {
        let mut output = self.chunk_state.output();

        // Walk the CV stack from top to bottom, merging
        let mut cv_stack_idx = self.cv_stack_len as usize;
        while cv_stack_idx > 0 {
            cv_stack_idx -= 1;
            output = parent_output(
                self.cv_stack[cv_stack_idx],
                output.chaining_value(),
                &self.key_words,
                self.flags,
            );
        }
        output
    }

    /// Finalize the context and output the array of bytes into the mut output slice
    ///
    /// The context is consumed by this function, to prevent buggy reuse.
    /// The output slice size is assert checked to have the correct expected size.
    ///
    /// If the context needs to be kept before finalizing, the user can clone the Context.
    pub fn finalize_at(self, out: &mut [u8]) {
        self.final_output().root_output_bytes(out);
    }

    /// Same as `finalize` but do not consume the context, but instead
    /// reset it in a ready to use state.
    pub fn finalize_reset_at(&mut self, out: &mut [u8]) {
        self.final_output().root_output_bytes(out);
        self.reset();
    }

    /// Finalize the context and return an [`OutputReader`] for XOF output
    ///
    /// The returned reader can produce arbitrary amounts of output via
    /// its [`fill`](OutputReader::fill) method.
    pub fn finalize_xof(self) -> OutputReader {
        self.final_output().into_output_reader()
    }

    /// Reset the context to the state after initial construction
    ///
    /// The key words and mode flags are preserved; only the streaming
    /// state (chunk, CV stack) is cleared.
    pub fn reset(&mut self) {
        self.chunk_state = ChunkState::new(&self.key_words, 0, self.flags);
        self.cv_stack_len = 0;
    }

    /// Finalize the context and return a fixed-size byte array
    ///
    /// The context is consumed by this function, to prevent buggy reuse.
    ///
    /// If the context needs to be kept before finalizing, the user can clone the Context.
    pub fn finalize<const OUT: usize>(self) -> [u8; OUT] {
        let mut out = [0u8; OUT];
        self.finalize_at(&mut out);
        out
    }

    /// Same as `finalize` but do not consume the context, but instead
    /// reset it in a ready to use state.
    pub fn finalize_reset<const OUT: usize>(&mut self) -> [u8; OUT] {
        let mut out = [0u8; OUT];
        self.finalize_reset_at(&mut out);
        out
    }
}

/// Extendable output reader for BLAKE3
///
/// Returned by [`Context::finalize_xof`]. Produces arbitrary-length output
/// by calling the root compression function with incrementing counter values.
/// Each call to [`fill`](OutputReader::fill) appends to the logical output
/// stream. calling `fill` twice with 32-byte buffers is equivalent to
/// calling it once with a 64-byte buffer.
#[derive(Clone)]
pub struct OutputReader {
    input_chaining_value: [u32; 8],
    block_words: [u32; 16],
    block_len: u32,
    flags: u32,
    counter: u64,
    buffer: [u8; 64],
    buffer_pos: u8,
}

impl OutputReader {
    /// Fill the provided buffer with XOF output bytes
    ///
    /// This method can be called repeatedly to extract an arbitrary amount
    /// of output. Successive calls continue where the previous call left off.
    pub fn fill(&mut self, mut output: &mut [u8]) {
        while !output.is_empty() {
            if self.buffer_pos == 64 {
                // Need a new output block
                let words = compress(
                    &self.input_chaining_value,
                    &self.block_words,
                    self.counter,
                    self.block_len,
                    self.flags | FLAG_ROOT,
                );
                write_u32v_le(&mut self.buffer, &words);
                self.counter += 1;
                self.buffer_pos = 0;
            }
            let available = 64 - self.buffer_pos as usize;
            let take = core::cmp::min(available, output.len());
            output[..take].copy_from_slice(
                &self.buffer[self.buffer_pos as usize..self.buffer_pos as usize + take],
            );
            self.buffer_pos += take as u8;
            output = &mut output[take..];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    // Official C2SP test vector key
    const TEST_KEY: &[u8; 32] = b"whats the Elvish word for friend";

    // Official C2SP context string for derive_key mode
    const TEST_CONTEXT: &str = "BLAKE3 2019-12-27 16:29:52 test vectors context";

    fn test_input(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        let mut i = 0;
        while i < hex.len() {
            let byte = u8::from_str_radix(&hex[i..i + 2], 16).unwrap();
            bytes.push(byte);
            i += 2;
        }
        bytes
    }

    // Each test vector: (input_len, hash_hex, keyed_hash_hex, derive_key_hex)
    // https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
    fn test_vectors() -> Vec<(usize, &'static str, &'static str, &'static str)> {
        vec![
            (
                0,
                "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda7001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421cce14d",
                "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26b18171a2f22a4b94822c701f107153dba24918c4bae4d2945c20ece13387627d3b73cbf97b797d5e59948c7ef788f54372df45e45e4293c7dc18c1d41144a9758be58960856be1eabbe22c2653190de560ca3b2ac4aa692a9210694254c371e851bc8f",
                "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d905630c8be290dfcf3e6842f13bddd573c098c3f17361f1f206b8cad9d088aa4a3f746752c6b0ce6a83b0da81d59649257cdf8eb3e9f7d4998e41021fac119deefb896224ac99f860011f73609e6e0e4540f93b273e56547dfd3aa1a035ba6689d89a0",
            ),
            (
                1,
                "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213c3a6cb8bf623e20cdb535f8d1a5ffb86342d9c0b64aca3bce1d31f60adfa137b358ad4d79f97b47c3d5e79f179df87a3b9776ef8325f8329886ba42f07fb138bb502f4081cbcec3195c5871e6c23e2cc97d3c69a613eba131e5f1351f3f1da786545e5",
                "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b6568c0490609413006fbd428eb3fd14e7756d90f73a4725fad147f7bf70fd61c4e0cf7074885e92b0e3f125978b4154986d4fb202a3f331a3fb6cf349a3a70e49990f98fe4289761c8602c4e6ab1138d31d3b62218078b2f3ba9a88e1d08d0dd4cea11",
                "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c5827b91bf889b6b97c5477f535361caefca0b5d8c4746441c57617111933158950670f9aa8a05d791daae10ac683cbef8faf897c84e6114a59d2173c3f417023a35d6983f2c7dfa57e7fc559ad751dbfb9ffab39c2ef8c4aafebc9ae973a64f0c76551",
            ),
            (
                2,
                "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63d8386b22e2ddc05836b7c1bb693d92af006deb5ffbc4c70fb44d0195d0c6f252faac61659ef86523aa16517f87cb5f1340e723756ab65efb2f91964e14391de2a432263a6faf1d146937b35a33621c12d00be8223a7f1919cec0acd12097ff3ab00ab1",
                "5392ddae0e0a69d5f40160462cbd9bd889375082ff224ac9c758802b7a6fd20a9ffbf7efd13e989a6c246f96d3a96b9d279f2c4e63fb0bdff633957acf50ee1a5f658be144bab0f6f16500dee4aa5967fc2c586d85a04caddec90fffb7633f46a60786024353b9e5cebe277fcd9514217fee2267dcda8f7b31697b7c54fab6a939bf8f",
                "1f166565a7df0098ee65922d7fea425fb18b9943f19d6161e2d17939356168e6daa59cae19892b2d54f6fc9f475d26031fd1c22ae0a3e8ef7bdb23f452a15e0027629d2e867b1bb1e6ab21c71297377750826c404dfccc2406bd57a83775f89e0b075e59a7732326715ef912078e213944f490ad68037557518b79c0086de6d6f6cdd2",
            ),
            (
                3,
                "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f5b49b82f805a538c68915c1ae8035c900fd1d4b13902920fd05e1450822f36de9454b7e9996de4900c8e723512883f93f4345f8a58bfe64ee38d3ad71ab027765d25cdd0e448328a8e7a683b9a6af8b0af94fa09010d9186890b096a08471e4230a134",
                "39e67b76b5a007d4921969779fe666da67b5213b096084ab674742f0d5ec62b9b9142d0fab08e1b161efdbb28d18afc64d8f72160c958e53a950cdecf91c1a1bbab1a9c0f01def762a77e2e8545d4dec241e98a89b6db2e9a5b070fc110caae2622690bd7b76c02ab60750a3ea75426a6bb8803c370ffe465f07fb57def95df772c39f",
                "440aba35cb006b61fc17c0529255de438efc06a8c9ebf3f2ddac3b5a86705797f27e2e914574f4d87ec04c379e12789eccbfbc15892626042707802dbe4e97c3ff59dca80c1e54246b6d055154f7348a39b7d098b2b4824ebe90e104e763b2a447512132cede16243484a55a4e40a85790038bb0dcf762e8c053cabae41bbe22a5bff7",
            ),
            (
                4,
                "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f328f603ba4564453e06cdcee6cbe728a4519bbe6f0d41e8a14b5b225174a566dbfa61b56afb1e452dc08c804f8c3143c9e2cc4a31bb738bf8c1917b55830c6e65797211701dc0b98daa1faeaa6ee9e56ab606ce03a1a881e8f14e87a4acf4646272cfd12",
                "7671dde590c95d5ac9616651ff5aa0a27bee5913a348e053b8aa9108917fe070116c0acff3f0d1fa97ab38d813fd46506089118147d83393019b068a55d646251ecf81105f798d76a10ae413f3d925787d6216a7eb444e510fd56916f1d753a5544ecf0072134a146b2615b42f50c179f56b8fae0788008e3e27c67482349e249cb86a",
                "f46085c8190d69022369ce1a18880e9b369c135eb93f3c63550d3e7630e91060fbd7d8f4258bec9da4e05044f88b91944f7cab317a2f0c18279629a3867fad0662c9ad4d42c6f27e5b124da17c8c4f3a94a025ba5d1b623686c6099d202a7317a82e3d95dae46a87de0555d727a5df55de44dab799a20dffe239594d6e99ed17950910",
            ),
            (
                5,
                "b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2ebcfdac6c5d32c31209e1f81a454751280db64942ce395104e1e4eaca62607de1c2ca748251754ea5bbe8c20150e7f47efd57012c63b3c6a6632dc1c7cd15f3e1c999904037d60fac2eb9397f2adbe458d7f264e64f1e73aa927b30988e2aed2f03620",
                "73ac69eecf286894d8102018a6fc729f4b1f4247d3703f69bdc6a5fe3e0c84616ab199d1f2f3e53bffb17f0a2209fe8b4f7d4c7bae59c2bc7d01f1ff94c67588cc6b38fa6024886f2c078bfe09b5d9e6584cd6c521c3bb52f4de7687b37117a2dbbec0d59e92fa9a8cc3240d4432f91757aabcae03e87431dac003e7d73574bfdd8218",
                "1f24eda69dbcb752847ec3ebb5dd42836d86e58500c7c98d906ecd82ed9ae47f6f48a3f67e4e43329c9a89b1ca526b9b35cbf7d25c1e353baffb590fd79be58ddb6c711f1a6b60e98620b851c688670412fcb0435657ba6b638d21f0f2a04f2f6b0bd8834837b10e438d5f4c7c2c71299cf7586ea9144ed09253d51f8f54dd6bff719d",
            ),
            (
                6,
                "06c4e8ffb6872fad96f9aaca5eee1553eb62aed0ad7198cef42e87f6a616c844611a30c4e4f37fe2fe23c0883cde5cf7059d88b657c7ed2087e3d210925ede716435d6d5d82597a1e52b9553919e804f5656278bd739880692c94bff2824d8e0b48cac1d24682699e4883389dc4f2faa2eb3b4db6e39debd5061ff3609916f3e07529a",
                "82d3199d0013035682cc7f2a399d4c212544376a839aa863a0f4c91220ca7a6dc2ffb3aa05f2631f0fa9ac19b6e97eb7e6669e5ec254799350c8b8d189e8807800842a5383c4d907c932f34490aaf00064de8cdb157357bde37c1504d2960034930887603abc5ccb9f5247f79224baff6120a3c622a46d7b1bcaee02c5025460941256",
                "be96b30b37919fe4379dfbe752ae77b4f7e2ab92f7ff27435f76f2f065f6a5f435ae01a1d14bd5a6b3b69d8cbd35f0b01ef2173ff6f9b640ca0bd4748efa398bf9a9c0acd6a66d9332fdc9b47ffe28ba7ab6090c26747b85f4fab22f936b71eb3f64613d8bd9dfabe9bb68da19de78321b481e5297df9e40ec8a3d662f3e1479c65de0",
            ),
            (
                7,
                "3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe66036ef6e6d1a8f54baa9fed1fc11c77cfb9cff65bae915045027046ebe0c01bf5a941f3bb0f73791d3fc0b84370f9f30af0cd5b0fc334dd61f70feb60dad785f070fef1f343ed933b49a5ca0d16a503f599a365a4296739248b28d1a20b0e2cc8975c",
                "af0a7ec382aedc0cfd626e49e7628bc7a353a4cb108855541a5651bf64fbb28a7c5035ba0f48a9c73dabb2be0533d02e8fd5d0d5639a18b2803ba6bf527e1d145d5fd6406c437b79bcaad6c7bdf1cf4bd56a893c3eb9510335a7a798548c6753f74617bede88bef924ba4b334f8852476d90b26c5dc4c3668a2519266a562c6c8034a6",
                "dc3b6485f9d94935329442916b0d059685ba815a1fa2a14107217453a7fc9f0e66266db2ea7c96843f9d8208e600a73f7f45b2f55b9e6d6a7ccf05daae63a3fdd10b25ac0bd2e224ce8291f88c05976d575df998477db86fb2cfbbf91725d62cb57acfeb3c2d973b89b503c2b60dde85a7802b69dc1ac2007d5623cbea8cbfb6b181f5",
            ),
            (
                8,
                "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb725d6d46ceed8f785ab9f2f9b06acfe398c6699c6129da084cb531177445a682894f9685eaf836999221d17c9a64a3a057000524cd2823986db378b074290a1a9b93a22e135ed2c14c7e20c6d045cd00b903400374126676ea78874d79f2dd7883cf5c",
                "be2f5495c61cba1bb348a34948c004045e3bd4dae8f0fe82bf44d0da245a060048eb5e68ce6dea1eb0229e144f578b3aa7e9f4f85febd135df8525e6fe40c6f0340d13dd09b255ccd5112a94238f2be3c0b5b7ecde06580426a93e0708555a265305abf86d874e34b4995b788e37a823491f25127a502fe0704baa6bfdf04e76c13276",
                "2b166978cef14d9d438046c720519d8b1cad707e199746f1562d0c87fbd32940f0e2545a96693a66654225ebbaac76d093bfa9cd8f525a53acb92a861a98c42e7d1c4ae82e68ab691d510012edd2a728f98cd4794ef757e94d6546961b4f280a51aac339cc95b64a92b83cc3f26d8af8dfb4c091c240acdb4d47728d23e7148720ef04",
            ),
            (
                63,
                "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b1197012b1e7d9af4d7cb7bdd1f3bb49a90a9b5dec3ea2bbc6eaebce77f4e470cbf4687093b5352f04e4a4570fba233164e6acc36900e35d185886a827f7ea9bdc1e5c3ce88b095a200e62c10c043b3e9bc6cb9b6ac4dfa51794b02ace9f98779040755",
                "bb1eb5d4afa793c1ebdd9fb08def6c36d10096986ae0cfe148cd101170ce37aea05a63d74a840aecd514f654f080e51ac50fd617d22610d91780fe6b07a26b0847abb38291058c97474ef6ddd190d30fc318185c09ca1589d2024f0a6f16d45f11678377483fa5c005b2a107cb9943e5da634e7046855eaa888663de55d6471371d55d",
                "b6451e30b953c206e34644c6803724e9d2725e0893039cfc49584f991f451af3b89e8ff572d3da4f4022199b9563b9d70ebb616efff0763e9abec71b550f1371e233319c4c4e74da936ba8e5bbb29a598e007a0bbfa929c99738ca2cc098d59134d11ff300c39f82e2fce9f7f0fa266459503f64ab9913befc65fddc474f6dc1c67669",
            ),
            (
                64,
                "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98fc9cc56cb831ffe33ea8e7e1d1df09b26efd2767670066aa82d023b1dfe8ab1b2b7fbb5b97592d46ffe3e05a6a9b592e2949c74160e4674301bc3f97e04903f8c6cf95b863174c33228924cdef7ae47559b10b294acd660666c4538833582b43f82d74",
                "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e68244c26010afc3f762615bbac552a1ca909e67c83e2fd5478cf46b9e811efccc93f77a21b17a152ebaca1695733fdb086e23cd0eb48c41c034d52523fc21236e5d8c9255306e48d52ba40b4dac24256460d56573d1312319afcf3ed39d72d0bfc69acb",
                "a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e9b9493a9befebe0bf0c9509fb3105cfa0e262cde141aa8e3f2c2f77890bb64a4cca96922a21ead111f6338ad5244f2c15c44cb595443ac2ac294231e31be4a4307d0a91e874d36fc9852aeb1265c09b6e0cda7c37ef686fbbcab97e8ff66718be048bb",
            ),
            (
                65,
                "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee0e16e0a4749d6811dd1d6d1265c29729b1b75a9ac346cf93f0e1d7296dfcfd4313b3a227faaaaf7757cc95b4e87a49be3b8a270a12020233509b1c3632b3485eef309d0abc4a4a696c9decc6e90454b53b000f456a3f10079072baaf7a981653221f2c",
                "c0a4edefa2d2accb9277c371ac12fcdbb52988a86edc54f0716e1591b4326e72d5e795f46a596b02d3d4bfb43abad1e5d19211152722ec1f20fef2cd413e3c22f2fc5da3d73041275be6ede3517b3b9f0fc67ade5956a672b8b75d96cb43294b9041497de92637ed3f2439225e683910cb3ae923374449ca788fb0f9bea92731bc26ad",
                "51fd05c3c1cfbc8ed67d139ad76f5cf8236cd2acd26627a30c104dfd9d3ff8a82b02e8bd36d8498a75ad8c8e9b15eb386970283d6dd42c8ae7911cc592887fdbe26a0a5f0bf821cd92986c60b2502c9be3f98a9c133a7e8045ea867e0828c7252e739321f7c2d65daee4468eb4429efae469a42763f1f94977435d10dccae3e3dce88d",
            ),
            (
                127,
                "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640de3137d477156d1fde56b0cf36f8ef18b44b2d79897bece12227539ac9ae0a5119da47644d934d26e74dc316145dcb8bb69ac3f2e05c242dd6ee06484fcb0e956dc44355b452c5e2bbb5e2b66e99f5dd443d0cbcaaafd4beebaed24ae2f8bb672bcef78",
                "c64200ae7dfaf35577ac5a9521c47863fb71514a3bcad18819218b818de85818ee7a317aaccc1458f78d6f65f3427ec97d9c0adb0d6dacd4471374b621b7b5f35cd54663c64dbe0b9e2d95632f84c611313ea5bd90b71ce97b3cf645776f3adc11e27d135cbadb9875c2bf8d3ae6b02f8a0206aba0c35bfe42574011931c9a255ce6dc",
                "c91c090ceee3a3ac81902da31838012625bbcd73fcb92e7d7e56f78deba4f0c3feeb3974306966ccb3e3c69c337ef8a45660ad02526306fd685c88542ad00f759af6dd1adc2e50c2b8aac9f0c5221ff481565cf6455b772515a69463223202e5c371743e35210bbbbabd89651684107fd9fe493c937be16e39cfa7084a36207c99bea3",
            ),
            (
                128,
                "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45efa69faba091427f9c5c4caa873aa07828651f19c55bad85c47d1368b11c6fd99e47ecba5820a0325984d74fe3e4058494ca12e3f1d3293d0010a9722f7dee64f71246f75e9361f44cc8e214a100650db1313ff76a9f93ec6e84edb7add1cb4a95019b0c",
                "b04fe15577457267ff3b6f3c947d93be581e7e3a4b018679125eaf86f6a628ecd86bbe0001f10bda47e6077b735016fca8119da11348d93ca302bbd125bde0db2b50edbe728a620bb9d3e6f706286aedea973425c0b9eedf8a38873544cf91badf49ad92a635a93f71ddfcee1eae536c25d1b270956be16588ef1cfef2f1d15f650bd5",
                "81720f34452f58a0120a58b6b4608384b5c51d11f39ce97161a0c0e442ca022550e7cd651e312f0b4c6afb3c348ae5dd17d2b29fab3b894d9a0034c7b04fd9190cbd90043ff65d1657bbc05bfdecf2897dd894c7a1b54656d59a50b51190a9da44db426266ad6ce7c173a8c0bbe091b75e734b4dadb59b2861cd2518b4e7591e4b83c9",
            ),
            (
                129,
                "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12f96ffa7b36dd78ba321be7e842d364a62a42e3746681c8bace18a4a8a79649285c7127bf8febf125be9de39586d251f0d41da20980b70d35e3dac0eee59e468a894fa7e6a07129aaad09855f6ad4801512a116ba2b7841e6cfc99ad77594a8f2d181a7",
                "d4a64dae6cdccbac1e5287f54f17c5f985105457c1a2ec1878ebd4b57e20d38f1c9db018541eec241b748f87725665b7b1ace3e0065b29c3bcb232c90e37897fa5aaee7e1e8a2ecfcd9b51463e42238cfdd7fee1aecb3267fa7f2128079176132a412cd8aaf0791276f6b98ff67359bd8652ef3a203976d5ff1cd41885573487bcd683",
                "938d2d4435be30eafdbb2b7031f7857c98b04881227391dc40db3c7b21f41fc18d72d0f9c1de5760e1941aebf3100b51d64644cb459eb5d20258e233892805eb98b07570ef2a1787cd48e117c8d6a63a68fd8fc8e59e79dbe63129e88352865721c8d5f0cf183f85e0609860472b0d6087cefdd186d984b21542c1c780684ed6832d8d",
            ),
            (
                1023,
                "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11a182d27a591b05592b15607500e1e8dd56bc6c7fc063715b7a1d737df5bad3339c56778957d870eb9717b57ea3d9fb68d1b55127bba6a906a4a24bbd5acb2d123a37b28f9e9a81bbaae360d58f85e5fc9d75f7c370a0cc09b6522d9c8d822f2f28f485",
                "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e890316d2e6d8b8c25b0a5b2180f94fb1a158ef508c3cde45e2966bd796a696d3e13efd86259d756387d9becf5c8bf1ce2192b87025152907b6d8cc33d17826d8b7b9bc97e38c3c85108ef09f013e01c229c20a83d9e8efac5b37470da28575fd755a10",
                "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea59c413264404661e9e4d955409dfe4ad3aa487871bcd454ed12abfe2c2b1eb7757588cf6cb18d2eccad49e018c0d0fec323bec82bf1644c6325717d13ea712e6840d3e6e730d35553f59eff5377a9c350bcc1556694b924b858f329c44ee64b884ef00d",
            ),
            (
                1024,
                "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af71cf8107265ecdaf8505b95d8fcec83a98a6a96ea5109d2c179c47a387ffbb404756f6eeae7883b446b70ebb144527c2075ab8ab204c0086bb22b7c93d465efc57f8d917f0b385c6df265e77003b85102967486ed57db5c5ca170ba441427ed9afa684e",
                "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4a78bc838c72852d4f49c864acb7adafe2478e824afe51c8919d06168414c265f298a8094b1ad813a9b8614acabac321f24ce61c5a5346eb519520d38ecc43e89b5000236df0597243e4d2493fd626730e2ba17ac4d8824d09d1a4a8f57b8227778e2de",
                "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a6896843027066c23b601d3ddfb391e90d5c8eccdef4ae2a264bce9e612ba15e2bc9d654af1481b2e75dbabe615974f1070bba84d56853265a34330b4766f8e75edd1f4a1650476c10802f22b64bd3919d246ba20a17558bc51c199efdec67e80a227251808d8ce5bad",
            ),
            (
                1025,
                "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444f4c4a22b4b399155358a994e52bf255de60035742ec71bd08ac275a1b51cc6bfe332b0ef84b409108cda080e6269ed4b3e2c3f7d722aa4cdc98d16deb554e5627be8f955c98e1d5f9565a9194cad0c4285f93700062d9595adb992ae68ff12800ab67a",
                "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69362396b77fdc0d2634a552970843722066c3c15902ae5097e00ff53f1e116f1cd5352720113a837ab2452cafbde4d54085d9cf5d21ca613071551b25d52e69d6c81123872b6f19cd3bc1333edf0c52b94de23ba772cf82636cff4542540a7738d5b930",
                "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb5d31013a167509e9066273ab6e2123bc835b408b067d88f96addb550d96b6852dad38e320b9d940f86db74d398c770f462118b35d2724efa13da97194491d96dd37c3c09cbef665953f2ee85ec83d88b88d11547a6f911c8217cca46defa2751e7f3ad",
            ),
            (
                2048,
                "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a9a60bf80001410ec9eea6698cd537939fad4749edd484cb541aced55cd9bf54764d063f23f6f1e32e12958ba5cfeb1bf618ad094266d4fc3c968c2088f677454c288c67ba0dba337b9d91c7e1ba586dc9a5bc2d5e90c14f53a8863ac75655461cea8f9",
                "879cf1fa2ea0e79126cb1063617a05b6ad9d0b696d0d757cf053439f60a99dd10173b961cd574288194b23ece278c330fbb8585485e74967f31352a8183aa782b2b22f26cdcadb61eed1a5bc144b8198fbb0c13abbf8e3192c145d0a5c21633b0ef86054f42809df823389ee40811a5910dcbd1018af31c3b43aa55201ed4edaac74fe",
                "7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23e2c11a1ebffcea4d80447867b61badb1383d842d4e79645d48dd82ccba290769caa7af8eaa1bd78a2a5e6e94fbdab78d9c7b74e894879f6a515257ccf6f95056f4e25390f24f6b35ffbb74b766202569b1d797f2d4bd9d17524c720107f985f4ddc583",
            ),
            (
                2049,
                "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b687952256303096de31d71d74103403822a2e0bc1eb193e7aecc9643a76b7bbc0c9f9c52e8783aae98764ca468962b5c2ec92f0c74eb5448d519713e09413719431c802f948dd5d90425a4ecdadece9eb178d80f26efccae630734dff63340285adec2aed3b51073ad3",
                "9f29700902f7c86e514ddc4df1e3049f258b2472b6dd5267f61bf13983b78dd5f9a88abfefdfa1e00b418971f2b39c64ca621e8eb37fceac57fd0c8fc8e117d43b81447be22d5d8186f8f5919ba6bcc6846bd7d50726c06d245672c2ad4f61702c646499ee1173daa061ffe15bf45a631e2946d616a4c345822f1151284712f76b2b0e",
                "2ea477c5515cc3dd606512ee72bb3e0e758cfae7232826f35fb98ca1bcbdf27316d8e9e79081a80b046b60f6a263616f33ca464bd78d79fa18200d06c7fc9bffd808cc4755277a7d5e09da0f29ed150f6537ea9bed946227ff184cc66a72a5f8c1e4bd8b04e81cf40fe6dc4427ad5678311a61f4ffc39d195589bdbc670f63ae70f4b6",
            ),
            (
                8192,
                "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a635fe51a27db045a567c1ad51be5aa34c01c6651c4d9b5b5ac5d0fd58cf18dd61a47778566b797a8c67df7b1d60b97b19288d2d877bb2df417ace009dcb0241ca1257d62712b6a4043b4ff33f690d849da91ea3bf711ed583cb7b7a7da2839ba71309bbf",
                "dc9637c8845a770b4cbf76b8daec0eebf7dc2eac11498517f08d44c8fc00d58a4834464159dcbc12a0ba0c6d6eb41bac0ed6585cabfe0aca36a375e6c5480c22afdc40785c170f5a6b8a1107dbee282318d00d915ac9ed1143ad40765ec120042ee121cd2baa36250c618adaf9e27260fda2f94dea8fb6f08c04f8f10c78292aa46102",
                "ad01d7ae4ad059b0d33baa3c01319dcf8088094d0359e5fd45d6aeaa8b2d0c3d4c9e58958553513b67f84f8eac653aeeb02ae1d5672dcecf91cd9985a0e67f4501910ecba25555395427ccc7241d70dc21c190e2aadee875e5aae6bf1912837e53411dabf7a56cbf8e4fb780432b0d7fe6cec45024a0788cf5874616407757e9e6bef7",
            ),
            (
                16384,
                "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde49d764c270176e53e97bdffa58d549073f2c660be0e81293767ed4e4929f9ad34bbb39a529334c57c4a381ffd2a6d4bfdbf1482651b172aa883cc13408fa67758a3e47503f93f87720a3177325f7823251b85275f64636a8f1d599c2e49722f42e93893",
                "9e9fc4eb7cf081ea7c47d1807790ed211bfec56aa25bb7037784c13c4b707b0df9e601b101e4cf63a404dfe50f2e1865bb12edc8fca166579ce0c70dba5a5c0fc960ad6f3772183416a00bd29d4c6e651ea7620bb100c9449858bf14e1ddc9ecd35725581ca5b9160de04060045993d972571c3e8f71e9d0496bfa744656861b169d65",
                "160e18b5878cd0df1c3af85eb25a0db5344d43a6fbd7a8ef4ed98d0714c3f7e160dc0b1f09caa35f2f417b9ef309dfe5ebd67f4c9507995a531374d099cf8ae317542e885ec6f589378864d3ea98716b3bbb65ef4ab5e0ab5bb298a501f19a41ec19af84a5e6b428ecd813b1a47ed91c9657c3fba11c406bc316768b58f6802c9e9b57",
            ),
            (
                31744,
                "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47860cc51f2b0c28a7b77304bd55fe73af663c02d3f52ea053ba43431ca5bab7bfea2f5e9d7121770d88f70ae9649ea713087d1914f7f312147e247f87eb2d4ffef0ac978bf7b6579d57d533355aa20b8b77b13fd09748728a5cc327a8ec470f4013226f",
                "efa53b389ab67c593dba624d898d0f7353ab99e4ac9d42302ee64cbf9939a4193a7258db2d9cd32a7a3ecfce46144114b15c2fcb68a618a976bd74515d47be08b628be420b5e830fade7c080e351a076fbc38641ad80c736c8a18fe3c66ce12f95c61c2462a9770d60d0f77115bbcd3782b593016a4e728d4c06cee4505cb0c08a42ec",
                "39772aef80e0ebe60596361e45b061e8f417429d529171b6764468c22928e28e9759adeb797a3fbf771b1bcea30150a020e317982bf0d6e7d14dd9f064bc11025c25f31e81bd78a921db0174f03dd481d30e93fd8e90f8b2fee209f849f2d2a52f31719a490fb0ba7aea1e09814ee912eba111a9fde9d5c274185f7bae8ba85d300a2b",
            ),
            (
                102400,
                "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085e01c59dab908c04c3342b816941a26d69c2605ebee5ec5291cc55e15b76146e6745f0601156c3596cb75065a9c57f35585a52e1ac70f69131c23d611ce11ee4ab1ec2c009012d236648e77be9295dd0426f29b764d65de58eb7d01dd42248204f45f8e",
                "1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7f9dbdd3e1d81dcbca3ba241bb18760f207710b751846faaeb9dff8262710999a59b2aa1aca298a032d94eacfadf1aa192418eb54808db23b56e34213266aa08499a16b354f018fc4967d05f8b9d2ad87a7278337be9693fc638a3bfdbe314574ee6fc4",
                "4652cff7a3f385a6103b5c260fc1593e13c778dbe608efb092fe7ee69df6e9c6d83a3e041bc3a48df2879f4a0a3ed40e7c961c73eff740f3117a0504c2dff4786d44fb17f1549eb0ba585e40ec29bf7732f0b7e286ff8acddc4cb1e23b87ff5d824a986458dcc6a04ac83969b80637562953df51ed1a7e90a7926924d2763778be8560",
            ),
        ]
    }

    #[test]
    fn test_blake3_hash_vectors() {
        for (input_len, hash_hex, _, _) in test_vectors() {
            let input = test_input(input_len);
            let expected_full = hex_to_bytes(hash_hex);

            // Test fixed 256-bit output via finalize()
            let digest = Blake3::new().update(&input).finalize::<32>();
            assert_eq!(
                &digest[..],
                &expected_full[..32],
                "BLAKE3 hash failed for input_len={}",
                input_len,
            );

            // Test XOF extended output (131 bytes)
            let mut xof_out = [0u8; 131];
            Blake3::new()
                .update(&input)
                .finalize_xof()
                .fill(&mut xof_out);
            assert_eq!(
                &xof_out[..],
                &expected_full[..],
                "BLAKE3 hash XOF failed for input_len={}",
                input_len,
            );
        }
    }

    #[test]
    fn test_blake3_keyed_hash_vectors() {
        for (input_len, _, keyed_hex, _) in test_vectors() {
            let input = test_input(input_len);
            let expected_full = hex_to_bytes(keyed_hex);

            // Test fixed 256-bit output via finalize()
            let digest = Blake3::new_keyed(TEST_KEY).update(&input).finalize::<32>();
            assert_eq!(
                &digest[..],
                &expected_full[..32],
                "BLAKE3 keyed_hash failed for input_len={}",
                input_len,
            );

            // Test XOF extended output (131 bytes)
            let mut xof_out = [0u8; 131];
            Blake3::new_keyed(TEST_KEY)
                .update(&input)
                .finalize_xof()
                .fill(&mut xof_out);
            assert_eq!(
                &xof_out[..],
                &expected_full[..],
                "BLAKE3 keyed_hash XOF failed for input_len={}",
                input_len,
            );
        }
    }

    #[test]
    fn test_blake3_derive_key_vectors() {
        for (input_len, _, _, derive_hex) in test_vectors() {
            let input = test_input(input_len);
            let expected_full = hex_to_bytes(derive_hex);

            // Test fixed 256-bit output via finalize()
            let digest = Blake3::new_derive_key(TEST_CONTEXT)
                .update(&input)
                .finalize::<32>();
            assert_eq!(
                &digest[..],
                &expected_full[..32],
                "BLAKE3 derive_key failed for input_len={}",
                input_len,
            );

            // Test XOF extended output (131 bytes)
            let mut xof_out = [0u8; 131];
            Blake3::new_derive_key(TEST_CONTEXT)
                .update(&input)
                .finalize_xof()
                .fill(&mut xof_out);
            assert_eq!(
                &xof_out[..],
                &expected_full[..],
                "BLAKE3 derive_key XOF failed for input_len={}",
                input_len,
            );
        }
    }

    #[test]
    fn test_blake3_incremental() {
        let input = test_input(4096);
        let expected = Blake3::new().update(&input).finalize::<32>();

        // Byte-by-byte with update (immutable)
        {
            let mut ctx = Blake3::new();
            for byte in &input {
                ctx = ctx.update(core::slice::from_ref(byte));
            }
            assert_eq!(
                ctx.finalize(),
                expected,
                "byte-by-byte (immutable) mismatch"
            );
        }

        // Byte-by-byte with update_mut (mutable)
        {
            let mut ctx = Blake3::new();
            for byte in &input {
                ctx.update_mut(core::slice::from_ref(byte));
            }
            assert_eq!(ctx.finalize(), expected, "byte-by-byte (mutable) mismatch");
        }

        // 3-byte chunks
        {
            let mut ctx = Blake3::new();
            for chunk in input.chunks(3) {
                ctx.update_mut(chunk);
            }
            assert_eq!(ctx.finalize(), expected, "3-byte chunk mismatch");
        }

        // 16-byte chunks
        {
            let mut ctx = Blake3::new();
            for chunk in input.chunks(16) {
                ctx.update_mut(chunk);
            }
            assert_eq!(ctx.finalize(), expected, "16-byte chunk mismatch");
        }

        // 64-byte chunks (one block)
        {
            let mut ctx = Blake3::new();
            for chunk in input.chunks(64) {
                ctx.update_mut(chunk);
            }
            assert_eq!(ctx.finalize(), expected, "64-byte chunk mismatch");
        }

        // 1024-byte chunks (one chunk)
        {
            let mut ctx = Blake3::new();
            for chunk in input.chunks(1024) {
                ctx.update_mut(chunk);
            }
            assert_eq!(ctx.finalize(), expected, "1024-byte chunk mismatch");
        }

        // Also verify XOF incremental consistency
        {
            let mut expected_xof = [0u8; 131];
            Blake3::new()
                .update(&input)
                .finalize_xof()
                .fill(&mut expected_xof);

            let mut ctx = Blake3::new();
            for chunk in input.chunks(7) {
                ctx.update_mut(chunk);
            }
            let mut actual_xof = [0u8; 131];
            ctx.finalize_xof().fill(&mut actual_xof);
            assert_eq!(
                expected_xof, actual_xof,
                "XOF incremental (7-byte chunks) mismatch"
            );
        }
    }

    #[test]
    fn test_blake3_reset() {
        let input_a = test_input(100);
        let input_b = test_input(1025);

        let expected = Blake3::new().update(&input_b).finalize::<32>();

        // Hash mode: hash input_a, reset, hash input_b
        {
            let mut ctx = Blake3::new();
            ctx.update_mut(&input_a);
            ctx.reset();
            ctx.update_mut(&input_b);
            assert_eq!(ctx.finalize(), expected, "hash mode reset mismatch");
        }

        // finalize_reset: finalize then continue with same context
        {
            let mut ctx = Blake3::new();
            ctx.update_mut(&input_a);
            let _ = ctx.finalize_reset::<32>();
            // Context is now reset
            ctx.update_mut(&input_b);
            assert_eq!(ctx.finalize(), expected, "finalize_reset mismatch");
        }

        // Keyed mode: reset preserves key
        {
            let expected_keyed = Blake3::new_keyed(TEST_KEY)
                .update(&input_b)
                .finalize::<32>();
            let mut ctx = Blake3::new_keyed(TEST_KEY);
            ctx.update_mut(&input_a);
            ctx.reset();
            ctx.update_mut(&input_b);
            assert_eq!(ctx.finalize(), expected_keyed, "keyed mode reset mismatch");
        }

        // Derive key mode: reset preserves derived key
        {
            let expected_derive = Blake3::new_derive_key(TEST_CONTEXT)
                .update(&input_b)
                .finalize::<32>();
            let mut ctx = Blake3::new_derive_key(TEST_CONTEXT);
            ctx.update_mut(&input_a);
            ctx.reset();
            ctx.update_mut(&input_b);
            assert_eq!(
                ctx.finalize(),
                expected_derive,
                "derive_key mode reset mismatch"
            );
        }
    }
}
