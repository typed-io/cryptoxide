//! Cryptographic Hash abstraction definition
//!
//! ```rust
//! use self::cryptoxide::digest::Digest;
//! use self::cryptoxide::sha2::Sha512;
//!
//! // create a Sha512 object
//! let mut hasher = Sha512::new();
//!
//! // write input message
//! hasher.input_str("hello world");
//! let hex = hasher.result_str();
//! ```

// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use alloc::string::String;
use alloc::vec::Vec;
use core::iter::repeat;

const CHARS: &'static [u8; 16] = b"0123456789abcdef";

/**
 * The Digest trait specifies an interface common to digest functions, such as SHA-1 and the SHA-2
 * family of digest functions.
 */
pub trait Digest {
    /**
     * Append message data in the digest state.
     *
     * # Arguments
     *
     * * input - some message data
     */
    fn input(&mut self, input: &[u8]);

    /**
     * Retrieve the digest result. This method may be called multiple times.
     *
     * # Arguments
     *
     * * out - the vector to hold the result. Must be large enough to contain output_bits().
     */
    fn result(&mut self, out: &mut [u8]);

    /**
     * Reset the digest. This method must be called after result() and before supplying more
     * data.
     */
    fn reset(&mut self);

    /**
     * Get the output size in bits.
     */
    fn output_bits(&self) -> usize;

    /**
     * Get the output size in bytes.
     */
    fn output_bytes(&self) -> usize {
        (self.output_bits() + 7) / 8
    }

    /**
     * Get the block size in bytes.
     */
    fn block_size(&self) -> usize;

    /**
     * Convenience function that feeds a string into a digest.
     *
     * # Arguments
     *
     * * `input` The string to feed into the digest
     */
    fn input_str(&mut self, input: &str) {
        self.input(input.as_bytes());
    }

    /**
     * Convenience function that retrieves the result of a digest as a
     * String in hexadecimal format.
     */
    fn result_str(&mut self) -> String {
        let mut buf: Vec<u8> = repeat(0).take((self.output_bits() + 7) / 8).collect();
        self.result(&mut buf);

        // inline buf[..].to_hex()
        let mut v = Vec::with_capacity(buf.len() * 2);
        for &byte in buf.iter() {
            v.push(CHARS[(byte >> 4) as usize]);
            v.push(CHARS[(byte & 0xf) as usize]);
        }

        unsafe { String::from_utf8_unchecked(v) }
    }
}
