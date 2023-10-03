//! Salsa20 Stream Cipher
//!
//! # Examples
//!
//! Combine a simple input using a 128 bits key and 64 bit nonce:
//!
//! ```
//! use cryptoxide::salsa20::Salsa20;
//!
//! let key : [u8; 16] = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
//! let nonce : [u8; 8] = [1,2,3,4,5,6,7,8];
//! let input : &[u8; 12] = b"hello world!";
//! let mut out : [u8; 12] = [0u8; 12];
//!
//! // create a new cipher
//! let mut cipher = Salsa20::new(&key, &nonce);
//!
//! // encrypt the msg
//! cipher.process(input, &mut out);
//! ```
//!

use crate::cryptoutil::{read_u32_le, write_u32_le, write_u32v_le, xor_keystream_mut};

use core::cmp;

#[derive(Clone)]
struct State<const ROUNDS: usize> {
    state: [u32; 16],
}

macro_rules! QR {
    ($a:ident, $b:ident, $c:ident, $d:ident) => {
        $b ^= $a.wrapping_add($d).rotate_left(7);
        $c ^= $b.wrapping_add($a).rotate_left(9);
        $d ^= $c.wrapping_add($b).rotate_left(13);
        $a ^= $d.wrapping_add($c).rotate_left(18);
    };
}

impl<const ROUNDS: usize> State<ROUNDS> {
    pub(crate) fn init(key: &[u8], nonce: &[u8]) -> Self {
        let constant = match key.len() {
            16 => b"expand 16-byte k",
            32 => b"expand 32-byte k",
            _ => unreachable!(),
        };

        let key_tail = if key.len() == 16 { key } else { &key[16..32] };

        let (x8, x9) = if nonce.len() == 16 {
            // HSalsa uses the full 16 byte nonce.
            (read_u32_le(&nonce[8..12]), read_u32_le(&nonce[12..16]))
        } else {
            (0, 0)
        };

        let state = [
            read_u32_le(&constant[0..4]),
            read_u32_le(&key[0..4]),
            read_u32_le(&key[4..8]),
            read_u32_le(&key[8..12]),
            read_u32_le(&key[12..16]),
            read_u32_le(&constant[4..8]),
            read_u32_le(&nonce[0..4]),
            read_u32_le(&nonce[4..8]),
            x8,
            x9,
            read_u32_le(&constant[8..12]),
            read_u32_le(&key_tail[0..4]),
            read_u32_le(&key_tail[4..8]),
            read_u32_le(&key_tail[8..12]),
            read_u32_le(&key_tail[12..16]),
            read_u32_le(&constant[12..16]),
        ];
        Self { state }
    }

    #[inline]
    pub(crate) fn rounds(&mut self) {
        let [mut x0, mut x1, mut x2, mut x3, mut x4, mut x5, mut x6, mut x7, mut x8, mut x9, mut x10, mut x11, mut x12, mut x13, mut x14, mut x15] =
            self.state;

        for _ in 0..(ROUNDS / 2) {
            QR!(x0, x4, x8, x12);
            QR!(x5, x9, x13, x1);
            QR!(x10, x14, x2, x6);
            QR!(x15, x3, x7, x11);
            QR!(x0, x1, x2, x3);
            QR!(x5, x6, x7, x4);
            QR!(x10, x11, x8, x9);
            QR!(x15, x12, x13, x14);
        }

        self.state = [
            x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15,
        ];
    }

    #[inline]
    /// Add back the initial state
    pub(crate) fn add_back(&mut self, initial: &Self) {
        for i in 0..16 {
            self.state[i] = self.state[i].wrapping_add(initial.state[i]);
        }
    }

    #[inline]
    pub(crate) fn increment(&mut self) {
        self.state[8] = self.state[8].wrapping_add(1);
        if self.state[8] == 0 {
            self.state[9] = self.state[9].wrapping_add(1);
        }
    }

    #[inline]
    pub(crate) fn output_bytes(&self, output: &mut [u8]) {
        write_u32v_le(output, &self.state);
    }

    #[inline]
    pub(crate) fn output_ad_bytes(&self, output: &mut [u8; 32]) {
        write_u32_le(&mut output[0..4], self.state[0]);
        write_u32_le(&mut output[4..8], self.state[5]);
        write_u32_le(&mut output[8..12], self.state[10]);
        write_u32_le(&mut output[12..16], self.state[15]);
        write_u32_le(&mut output[16..20], self.state[6]);
        write_u32_le(&mut output[20..24], self.state[7]);
        write_u32_le(&mut output[24..28], self.state[8]);
        write_u32_le(&mut output[28..32], self.state[9]);
    }
}

/// Salsa streaming cipher context
#[derive(Clone)]
pub struct Salsa<const ROUNDS: usize> {
    state: State<ROUNDS>,
    output: [u8; 64],
    offset: usize,
}

/// Typealias for Salsa with (common) 20 rounds
pub type Salsa20 = Salsa<20>;

impl<const ROUNDS: usize> Salsa<ROUNDS> {
    /// Create a new ChaCha20 context.
    ///
    /// * The key must be 16 or 32 bytes
    /// * The nonce must be 8 bytes
    pub fn new(key: &[u8], nonce: &[u8; 8]) -> Self {
        assert!(key.len() == 16 || key.len() == 32);
        assert!(ROUNDS == 8 || ROUNDS == 12 || ROUNDS == 20);

        Salsa {
            state: State::<ROUNDS>::init(key, nonce),
            output: [0; 64],
            offset: 64,
        }
    }

    fn update(&mut self) {
        let mut state = self.state.clone();
        state.rounds();
        state.add_back(&self.state);

        state.output_bytes(&mut self.output);

        self.state.increment();
        self.offset = 0;
    }

    /// Process the input in place through the cipher xoring
    ///
    /// To get only the stream of this cipher, one can just pass the zero
    /// buffer (X xor 0 = X)
    pub fn process_mut(&mut self, data: &mut [u8]) {
        let len = data.len();
        let mut i = 0;
        while i < len {
            // If there is no keystream available in the output buffer,
            // generate the next block.
            if self.offset == 64 {
                self.update();
            }

            // Process the min(available keystream, remaining input length).
            let count = cmp::min(64 - self.offset, len - i);
            xor_keystream_mut(&mut data[i..i + count], &self.output[self.offset..]);
            i += count;
            self.offset += count;
        }
    }

    /// Process the input through the cipher, xoring the byte one-by-one
    ///
    /// the output need to be the same size as the input otherwise
    /// this function will panic.
    pub fn process(&mut self, input: &[u8], output: &mut [u8]) {
        assert_eq!(
            input.len(),
            output.len(),
            "chacha::process need to have input and output of the same size"
        );
        output.copy_from_slice(input);
        self.process_mut(output);
    }
}

/// XSalsa streaming cipher context (Salsa Variant)
#[derive(Clone)]
pub struct XSalsa<const ROUNDS: usize> {
    state: State<ROUNDS>,
    output: [u8; 64],
    offset: usize,
}

/// Typealias for XSalsa with (common) 20 rounds
pub type XSalsa20 = XSalsa<20>;

impl<const ROUNDS: usize> XSalsa<ROUNDS> {
    /// Create a new XSalsa context.
    ///
    /// Key must be 32 bytes and the nonce 24 bytes.
    pub fn new(key: &[u8; 32], nonce: &[u8; 24]) -> Self {
        assert!(ROUNDS == 8 || ROUNDS == 12 || ROUNDS == 20);

        let mut hsalsa = State::<ROUNDS>::init(key, &nonce[0..16]);
        hsalsa.rounds();
        let mut new_key = [0; 32];
        hsalsa.output_ad_bytes(&mut new_key);

        let xsalsa = Self {
            state: State::init(&new_key, &nonce[16..24]),
            output: [0u8; 64],
            offset: 64,
        };
        xsalsa
    }

    fn update(&mut self) {
        let mut state = self.state.clone();
        state.rounds();
        state.add_back(&self.state);

        state.output_bytes(&mut self.output);

        self.state.increment();
        self.offset = 0;
    }

    /// Process the input in place through the cipher xoring
    ///
    /// To get only the stream of this cipher, one can just pass the zero
    /// buffer (X xor 0 = X)
    pub fn process_mut(&mut self, data: &mut [u8]) {
        let len = data.len();
        let mut i = 0;
        while i < len {
            // If there is no keystream available in the output buffer,
            // generate the next block.
            if self.offset == 64 {
                self.update();
            }

            // Process the min(available keystream, remaining input length).
            let count = cmp::min(64 - self.offset, len - i);
            xor_keystream_mut(&mut data[i..i + count], &self.output[self.offset..]);
            i += count;
            self.offset += count;
        }
    }

    /// Process the input through the cipher, xoring the byte one-by-one
    ///
    /// the output need to be the same size as the input otherwise
    /// this function will panic.
    pub fn process(&mut self, input: &[u8], output: &mut [u8]) {
        assert_eq!(
            input.len(),
            output.len(),
            "chacha::process need to have input and output of the same size"
        );
        output.copy_from_slice(input);
        self.process_mut(output);
    }
}

#[cfg(test)]
mod test {
    use super::{Salsa20, XSalsa20};

    use crate::digest::Digest;
    use crate::sha2::Sha256;

    #[test]
    fn test_salsa20_128bit_ecrypt_set_1_vector_0() {
        let key = [128u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let nonce = [0u8; 8];
        let input = [0u8; 64];
        let mut stream = [0u8; 64];
        let result = [
            0x4D, 0xFA, 0x5E, 0x48, 0x1D, 0xA2, 0x3E, 0xA0, 0x9A, 0x31, 0x02, 0x20, 0x50, 0x85,
            0x99, 0x36, 0xDA, 0x52, 0xFC, 0xEE, 0x21, 0x80, 0x05, 0x16, 0x4F, 0x26, 0x7C, 0xB6,
            0x5F, 0x5C, 0xFD, 0x7F, 0x2B, 0x4F, 0x97, 0xE0, 0xFF, 0x16, 0x92, 0x4A, 0x52, 0xDF,
            0x26, 0x95, 0x15, 0x11, 0x0A, 0x07, 0xF9, 0xE4, 0x60, 0xBC, 0x65, 0xEF, 0x95, 0xDA,
            0x58, 0xF7, 0x40, 0xB7, 0xD1, 0xDB, 0xB0, 0xAA,
        ];

        let mut salsa20 = Salsa20::new(&key, &nonce);
        salsa20.process(&input, &mut stream);
        assert_eq!(stream, result);
    }

    #[test]
    fn test_salsa20_256bit_ecrypt_set_1_vector_0() {
        let key = [
            128u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let nonce = [0u8; 8];
        let input = [0u8; 64];
        let mut stream = [0u8; 64];
        let result = [
            0xE3, 0xBE, 0x8F, 0xDD, 0x8B, 0xEC, 0xA2, 0xE3, 0xEA, 0x8E, 0xF9, 0x47, 0x5B, 0x29,
            0xA6, 0xE7, 0x00, 0x39, 0x51, 0xE1, 0x09, 0x7A, 0x5C, 0x38, 0xD2, 0x3B, 0x7A, 0x5F,
            0xAD, 0x9F, 0x68, 0x44, 0xB2, 0x2C, 0x97, 0x55, 0x9E, 0x27, 0x23, 0xC7, 0xCB, 0xBD,
            0x3F, 0xE4, 0xFC, 0x8D, 0x9A, 0x07, 0x44, 0x65, 0x2A, 0x83, 0xE7, 0x2A, 0x9C, 0x46,
            0x18, 0x76, 0xAF, 0x4D, 0x7E, 0xF1, 0xA1, 0x17,
        ];

        let mut salsa20 = Salsa20::new(&key, &nonce);
        salsa20.process(&input, &mut stream);
        assert_eq!(stream, result);
    }

    #[test]
    fn test_salsa20_256bit_nacl_vector_2() {
        let key = [
            0xdc, 0x90, 0x8d, 0xda, 0x0b, 0x93, 0x44, 0xa9, 0x53, 0x62, 0x9b, 0x73, 0x38, 0x20,
            0x77, 0x88, 0x80, 0xf3, 0xce, 0xb4, 0x21, 0xbb, 0x61, 0xb9, 0x1c, 0xbd, 0x4c, 0x3e,
            0x66, 0x25, 0x6c, 0xe4,
        ];
        let nonce = [0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37];
        let output_str = "662b9d0e3463029156069b12f918691a98f7dfb2ca0393c96bbfc6b1fbd630a2";

        let mut salsa20 = Salsa20::new(&key, &nonce);

        // hash 4194304 0-bytes (512*8192) in SHA256
        let mut sh = Sha256::new();

        let block = [0u8; 512];
        let mut stream_output = [0u8; 512];
        for _ in 0..8192 {
            salsa20.process(&block, &mut stream_output);
            sh.input(&stream_output);
        }

        let out_str = sh.result_str();
        assert_eq!(out_str, output_str);
    }

    #[test]
    fn test_xsalsa20_cryptopp() {
        let key = [
            0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a,
            0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08,
            0x44, 0xf6, 0x83, 0x89,
        ];
        let nonce = [
            0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc,
            0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37,
        ];
        let input = [0u8; 139];
        let mut stream = [0u8; 139];
        let result = [
            0xee, 0xa6, 0xa7, 0x25, 0x1c, 0x1e, 0x72, 0x91, 0x6d, 0x11, 0xc2, 0xcb, 0x21, 0x4d,
            0x3c, 0x25, 0x25, 0x39, 0x12, 0x1d, 0x8e, 0x23, 0x4e, 0x65, 0x2d, 0x65, 0x1f, 0xa4,
            0xc8, 0xcf, 0xf8, 0x80, 0x30, 0x9e, 0x64, 0x5a, 0x74, 0xe9, 0xe0, 0xa6, 0x0d, 0x82,
            0x43, 0xac, 0xd9, 0x17, 0x7a, 0xb5, 0x1a, 0x1b, 0xeb, 0x8d, 0x5a, 0x2f, 0x5d, 0x70,
            0x0c, 0x09, 0x3c, 0x5e, 0x55, 0x85, 0x57, 0x96, 0x25, 0x33, 0x7b, 0xd3, 0xab, 0x61,
            0x9d, 0x61, 0x57, 0x60, 0xd8, 0xc5, 0xb2, 0x24, 0xa8, 0x5b, 0x1d, 0x0e, 0xfe, 0x0e,
            0xb8, 0xa7, 0xee, 0x16, 0x3a, 0xbb, 0x03, 0x76, 0x52, 0x9f, 0xcc, 0x09, 0xba, 0xb5,
            0x06, 0xc6, 0x18, 0xe1, 0x3c, 0xe7, 0x77, 0xd8, 0x2c, 0x3a, 0xe9, 0xd1, 0xa6, 0xf9,
            0x72, 0xd4, 0x16, 0x02, 0x87, 0xcb, 0xfe, 0x60, 0xbf, 0x21, 0x30, 0xfc, 0x0a, 0x6f,
            0xf6, 0x04, 0x9d, 0x0a, 0x5c, 0x8a, 0x82, 0xf4, 0x29, 0x23, 0x1f, 0x00, 0x80,
        ];

        let mut xsalsa20 = XSalsa20::new(&key, &nonce);
        xsalsa20.process(&input, &mut stream);
        assert_eq!(stream, result);
    }
}

#[cfg(all(test, feature = "with-bench"))]
mod bench {
    use super::Salsa20;
    use test::Bencher;

    #[bench]
    pub fn salsa20_10(bh: &mut Bencher) {
        let mut salsa20 = Salsa20::new(&[0; 32], &[0; 8]);
        let input = [1u8; 10];
        let mut output = [0u8; 10];
        bh.iter(|| {
            salsa20.process(&input, &mut output);
        });
        bh.bytes = input.len() as u64;
    }

    #[bench]
    pub fn salsa20_1k(bh: &mut Bencher) {
        let mut salsa20 = Salsa20::new(&[0; 32], &[0; 8]);
        let input = [1u8; 1024];
        let mut output = [0u8; 1024];
        bh.iter(|| {
            salsa20.process(&input, &mut output);
        });
        bh.bytes = input.len() as u64;
    }

    #[bench]
    pub fn salsa20_64k(bh: &mut Bencher) {
        let mut salsa20 = Salsa20::new(&[0; 32], &[0; 8]);
        let input = [1u8; 65536];
        let mut output = [0u8; 65536];
        bh.iter(|| {
            salsa20.process(&input, &mut output);
        });
        bh.bytes = input.len() as u64;
    }
}
