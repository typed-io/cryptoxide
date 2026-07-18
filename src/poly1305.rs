//! Poly1305 Message Authentication Code (MAC) as defined in [Specification][1].
//!
//! # Examples
//!
//! ```
//! use cryptoxide::{mac::Mac, poly1305::Poly1305};
//!
//! let mut context = Poly1305::new(&[0u8;32]);
//! context.update_mut(b"data to authenticate");
//! let mac = context.finalize();
//! ```
//!
//! [1]: <https://cr.yp.to/mac/poly1305-20050329.pdf>

// This is a port of Andrew Moons poly1305-donna
// <https://github.com/floodyberry/poly1305-donna>

use core::cmp::min;

// The arithmetic core comes in two flavours selected at compile time, sharing
// the same `State` interface (`new` / `reset` / `blocks` / `finish`):
//
// * a 32-bits backend (5x26-bits limbs, 32x32->64 multiplications), used on
//   known 32-bits architectures (arm, riscv32) and when the `force-32bits`
//   feature is enabled.
// * a 64-bits backend (3x44-bits limbs, 64x64->128 multiplications), used
//   everywhere else as it is roughly twice as fast.
//
// This mirrors the architecture split already used by the curve25519 backends.

#[cfg(any(target_arch = "arm", target_arch = "riscv32", feature = "force-32bits"))]
mod donna32;
#[cfg(any(target_arch = "arm", target_arch = "riscv32", feature = "force-32bits"))]
use donna32::State;

#[cfg(not(any(target_arch = "arm", target_arch = "riscv32", feature = "force-32bits")))]
mod donna64;
#[cfg(not(any(target_arch = "arm", target_arch = "riscv32", feature = "force-32bits")))]
use donna64::State;

use crate::constant_time::{Choice, CtEqual};

/// `Poly1305` Context
///
/// Use the `Mac` traits for interaction
#[derive(Clone)]
pub struct Poly1305 {
    state: State,
    leftover: usize,
    buffer: [u8; 16],
}

/// Poly1305 Authenticated Tag (128 bits)
#[derive(Debug, Clone)]
pub struct Tag(pub [u8; 16]);

impl CtEqual for &Tag {
    fn ct_eq(self, other: Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
    fn ct_ne(self, b: Self) -> Choice {
        self.ct_eq(b).negate()
    }
}

impl PartialEq for Tag {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).is_true()
    }
}

impl Eq for Tag {}

impl AsRef<[u8; 16]> for Tag {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl AsMut<[u8; 16]> for Tag {
    fn as_mut(&mut self) -> &mut [u8; 16] {
        &mut self.0
    }
}

impl Poly1305 {
    /// Create a new `Poly1305` context using the key (32 bytes)
    pub fn new(key: &[u8; 32]) -> Self {
        Poly1305 {
            state: State::new(key),
            leftover: 0,
            buffer: [0u8; 16],
        }
    }

    /// Update the local state using the data
    pub fn update_mut(&mut self, data: &[u8]) {
        let mut m = data;

        if self.leftover > 0 {
            let want = min(16 - self.leftover, m.len());

            self.buffer[self.leftover..self.leftover + want].copy_from_slice(&m[..want]);
            m = &m[want..];
            self.leftover += want;

            if self.leftover < 16 {
                return;
            }

            let tmp = self.buffer;
            self.state.blocks(&tmp, false);

            self.leftover = 0;
        }

        let nblocks = m.len() / 16;
        if nblocks > 0 {
            let nbytes = nblocks * 16;
            self.state.blocks(&m[..nbytes], false);
            m = &m[nbytes..];
        }

        self.buffer[..m.len()].copy_from_slice(m);

        self.leftover = m.len();
    }

    /// Finalize the state and return the Poly1305 Tag
    pub fn finalize(mut self) -> Tag {
        // pad and process the remaining partial block (if any). the 0x01
        // terminator is written into the buffer, so the backend is told not to
        // add the implicit high bit for this block.
        if self.leftover > 0 {
            self.buffer[self.leftover] = 1;
            for b in self.buffer[self.leftover + 1..].iter_mut() {
                *b = 0;
            }
            let tmp = self.buffer;
            self.state.blocks(&tmp, true);
        }

        Tag(self.state.finish())
    }

    /// Finalize the state into the tag, and reset the state to a new context
    pub fn finalize_reset(&mut self, tag: &mut [u8; 16]) {
        // pad and process the remaining partial block (if any). the 0x01
        // terminator is written into the buffer, so the backend is told not to
        // add the implicit high bit for this block.
        if self.leftover > 0 {
            self.buffer[self.leftover] = 1;
            for b in self.buffer[self.leftover + 1..].iter_mut() {
                *b = 0;
            }
            let tmp = self.buffer;
            self.state.blocks(&tmp, true);
        }
        *tag = self.state.finish();

        self.leftover = 0;
        self.buffer = [0; 16];
        self.state.reset();
    }
}

#[cfg(test)]
mod test {
    use super::{Poly1305, Tag};

    fn poly1305(key: &[u8; 32], msg: &[u8]) -> Tag {
        let mut poly = Poly1305::new(key);
        poly.update_mut(msg);
        poly.finalize()
    }

    #[test]
    fn test_nacl_vector() {
        let key = [
            0xee, 0xa6, 0xa7, 0x25, 0x1c, 0x1e, 0x72, 0x91, 0x6d, 0x11, 0xc2, 0xcb, 0x21, 0x4d,
            0x3c, 0x25, 0x25, 0x39, 0x12, 0x1d, 0x8e, 0x23, 0x4e, 0x65, 0x2d, 0x65, 0x1f, 0xa4,
            0xc8, 0xcf, 0xf8, 0x80,
        ];

        let msg = [
            0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73, 0xc2, 0x96, 0x50, 0xba, 0x32, 0xfc,
            0x76, 0xce, 0x48, 0x33, 0x2e, 0xa7, 0x16, 0x4d, 0x96, 0xa4, 0x47, 0x6f, 0xb8, 0xc5,
            0x31, 0xa1, 0x18, 0x6a, 0xc0, 0xdf, 0xc1, 0x7c, 0x98, 0xdc, 0xe8, 0x7b, 0x4d, 0xa7,
            0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72, 0x71, 0xd2, 0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2,
            0x27, 0x0d, 0x6f, 0xb8, 0x63, 0xd5, 0x17, 0x38, 0xb4, 0x8e, 0xee, 0xe3, 0x14, 0xa7,
            0xcc, 0x8a, 0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26, 0xae, 0x90, 0x22, 0x43, 0x68,
            0x51, 0x7a, 0xcf, 0xea, 0xbd, 0x6b, 0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda, 0x99, 0x83,
            0x2b, 0x61, 0xca, 0x01, 0xb6, 0xde, 0x56, 0x24, 0x4a, 0x9e, 0x88, 0xd5, 0xf9, 0xb3,
            0x79, 0x73, 0xf6, 0x22, 0xa4, 0x3d, 0x14, 0xa6, 0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4,
            0x5a, 0x74, 0xe3, 0x55, 0xa5,
        ];

        let expected = Tag([
            0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5, 0x2a, 0x7d, 0xfb, 0x4b, 0x3d, 0x33,
            0x05, 0xd9,
        ]);

        let mac = poly1305(&key, &msg);
        assert_eq!(mac, expected);

        let mut poly = Poly1305::new(&key);
        poly.update_mut(&msg[0..32]);
        poly.update_mut(&msg[32..96]);
        poly.update_mut(&msg[96..112]);
        poly.update_mut(&msg[112..120]);
        poly.update_mut(&msg[120..124]);
        poly.update_mut(&msg[124..126]);
        poly.update_mut(&msg[126..127]);
        poly.update_mut(&msg[127..128]);
        poly.update_mut(&msg[128..129]);
        poly.update_mut(&msg[129..130]);
        poly.update_mut(&msg[130..131]);
        let mac = poly.finalize();
        assert_eq!(mac, expected);
    }

    #[test]
    fn donna_self_test() {
        let wrap_key = [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let wrap_msg = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff,
        ];

        let wrap_mac = Tag([
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);

        let mac = poly1305(&wrap_key, &wrap_msg);
        assert_eq!(mac, wrap_mac);

        let total_key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00,
        ];

        let total_mac = Tag([
            0x64, 0xaf, 0xe2, 0xe8, 0xd6, 0xad, 0x7b, 0xbd, 0xd2, 0x87, 0xf9, 0x7c, 0x44, 0x62,
            0x3d, 0x39,
        ]);

        let mut tpoly = Poly1305::new(&total_key);
        for i in 0..256 {
            let key = [i as u8; 32];
            let msg = [i as u8; 256];
            let mac = poly1305(&key, &msg[0..i]);
            tpoly.update_mut(mac.as_ref());
        }
        let mac = tpoly.finalize();
        assert_eq!(mac, total_mac);
    }

    #[test]
    fn test_tls_vectors() {
        // from http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04
        let key = b"this is 32-byte key for Poly1305";
        let msg = [0u8; 32];
        let expected = Tag([
            0x49, 0xec, 0x78, 0x09, 0x0e, 0x48, 0x1e, 0xc6, 0xc2, 0x6b, 0x33, 0xb9, 0x1c, 0xcc,
            0x03, 0x07,
        ]);
        let mac = poly1305(key, &msg);
        assert_eq!(mac, expected);

        let msg = b"Hello world!";
        let expected = Tag([
            0xa6, 0xf7, 0x45, 0x00, 0x8f, 0x81, 0xc9, 0x16, 0xa2, 0x0d, 0xcc, 0x74, 0xee, 0xf2,
            0xb2, 0xf0,
        ]);
        let mac = poly1305(key, msg);
        assert_eq!(mac, expected);
    }
}

#[cfg(all(test, feature = "with-bench"))]
mod bench {
    use crate::mac::Mac;
    use crate::poly1305::Poly1305;
    use test::Bencher;

    #[bench]
    pub fn poly1305_10(bh: &mut Bencher) {
        let mut mac = [0u8; 16];
        let key = [0u8; 32];
        let bytes = [1u8; 10];
        bh.iter(|| {
            let mut poly = Poly1305::new(&key);
            poly.input(&bytes);
            poly.raw_result(&mut mac);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn poly1305_1k(bh: &mut Bencher) {
        let mut mac = [0u8; 16];
        let key = [0u8; 32];
        let bytes = [1u8; 1024];
        bh.iter(|| {
            let mut poly = Poly1305::new(&key);
            poly.input(&bytes);
            poly.raw_result(&mut mac);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn poly1305_64k(bh: &mut Bencher) {
        let mut mac = [0u8; 16];
        let key = [0u8; 32];
        let bytes = [1u8; 65536];
        bh.iter(|| {
            let mut poly = Poly1305::new(&key);
            poly.input(&bytes);
            poly.raw_result(&mut mac);
        });
        bh.bytes = bytes.len() as u64;
    }
}
