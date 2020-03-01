//! Various utility to write/read in buffers

// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use core::{cmp, mem::size_of, ptr};

use crate::buffer::BufferResult::{BufferOverflow, BufferUnderflow};
use crate::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crate::symmetriccipher::{SymmetricCipherError, SynchronousStreamCipher};

macro_rules! write_type {
    ($C: ident, $T: ident, $F: ident) => {
        /// Write a $T into a vector, which must be of the correct size. The value is written using $F for endianness
        pub fn $C(dst: &mut [u8], input: $T) {
            const SZ: usize = size_of::<$T>();
            assert!(dst.len() == SZ);
            let as_bytes = input.$F();
            unsafe {
                let tmp = &as_bytes as *const u8;
                ptr::copy_nonoverlapping(tmp, dst.get_unchecked_mut(0), SZ);
            }
        }
    };
}

write_type!(write_u128_be, u128, to_be_bytes);
//write_type!(write_u128_le, u128, to_le_bytes);
write_type!(write_u64_be, u64, to_be_bytes);
write_type!(write_u64_le, u64, to_le_bytes);
write_type!(write_u32_be, u32, to_be_bytes);
write_type!(write_u32_le, u32, to_le_bytes);

macro_rules! write_array_type {
    ($C: ident, $T: ident, $F: ident) => {
        /// Write a $T into a vector, which must be of the correct size. The value is written using $F for endianness
        pub fn $C(dst: &mut [u8], input: &[$T]) {
            const SZ: usize = size_of::<$T>();
            assert!(dst.len() == SZ * input.len());
            unsafe {
                let mut x: *mut u8 = dst.get_unchecked_mut(0);
                for v in input.iter() {
                    let tmp = v.$F();
                    ptr::copy_nonoverlapping(&tmp as *const u8, x, SZ);
                    x = x.add(SZ);
                }
            }
        }
    };
}

write_array_type!(write_u64v_le, u64, to_le_bytes);
write_array_type!(write_u64v_be, u64, to_be_bytes);
write_array_type!(write_u32v_le, u32, to_le_bytes);
write_array_type!(write_u32v_be, u32, to_be_bytes);

macro_rules! read_array_type {
    ($C: ident, $T: ident, $F: ident) => {
        /// Read an array of bytes into an array of $T. The values are read with $F for endianness.
        pub fn $C(dst: &mut [$T], input: &[u8]) {
            const SZ: usize = size_of::<$T>();
            assert!(dst.len() * SZ == input.len());

            unsafe {
                let mut x: *mut $T = dst.get_unchecked_mut(0);
                let mut y: *const u8 = input.get_unchecked(0);

                for _ in 0..dst.len() {
                    let mut tmp = [0u8; SZ];
                    ptr::copy_nonoverlapping(y, &mut tmp as *mut _ as *mut u8, SZ);
                    *x = $T::$F(tmp);
                    x = x.add(1);
                    y = y.add(SZ);
                }
            }
        }
    };
}

read_array_type!(read_u64v_be, u64, from_be_bytes);
read_array_type!(read_u64v_le, u64, from_le_bytes);
read_array_type!(read_u32v_be, u32, from_be_bytes);
read_array_type!(read_u32v_le, u32, from_le_bytes);

/// Read the value of a vector of bytes as a u32 value in little-endian format.
pub fn read_u32_le(input: &[u8]) -> u32 {
    assert!(input.len() == 4);
    let mut tmp = [0u8; 4];
    unsafe {
        ptr::copy_nonoverlapping(input.get_unchecked(0), &mut tmp as *mut _ as *mut u8, 4);
    }
    u32::from_le_bytes(tmp)
}

/*
/// Read the value of a vector of bytes as a u32 value in big-endian format.
pub fn read_u32_be(input: &[u8]) -> u32 {
    assert!(input.len() == 4);
    unsafe {
        let mut tmp: u32 = mem::uninitialized();
        ptr::copy_nonoverlapping(input.get_unchecked(0), &mut tmp as *mut _ as *mut u8, 4);
        u32::from_be(tmp)
    }
}
*/

/// XOR plaintext and keystream, storing the result in dst.
pub fn xor_keystream(dst: &mut [u8], plaintext: &[u8], keystream: &[u8]) {
    assert!(dst.len() == plaintext.len());
    assert!(plaintext.len() <= keystream.len());

    // Do one byte at a time, using unsafe to skip bounds checking.
    let p = plaintext.as_ptr();
    let k = keystream.as_ptr();
    let d = dst.as_mut_ptr();
    for i in 0isize..plaintext.len() as isize {
        unsafe { *d.offset(i) = *p.offset(i) ^ *k.offset(i) };
    }
}

/// XOR a keystream in a buffer
pub fn xor_keystream_mut(buf: &mut [u8], keystream: &[u8]) {
    assert!(buf.len() <= keystream.len());

    // Do one byte at a time, using unsafe to skip bounds checking.
    let k = keystream.as_ptr();
    let d = buf.as_mut_ptr();
    for i in 0isize..buf.len() as isize {
        unsafe { *d.offset(i) = *d.offset(i) ^ *k.offset(i) };
    }
}

/// Copy bytes from src to dest
#[inline]
pub fn copy_memory(src: &[u8], dst: &mut [u8]) {
    assert!(dst.len() >= src.len());
    unsafe {
        let srcp = src.as_ptr();
        let dstp = dst.as_mut_ptr();
        ptr::copy_nonoverlapping(srcp, dstp, src.len());
    }
}

/// Zero all bytes in dst
#[inline]
pub fn zero(dst: &mut [u8]) {
    unsafe {
        ptr::write_bytes(dst.as_mut_ptr(), 0, dst.len());
    }
}

/// `symm_enc_or_dec()` implements the necessary functionality to turn a `SynchronousStreamCipher` into
/// an Encryptor or Decryptor
pub fn symm_enc_or_dec<S: SynchronousStreamCipher, R: ReadBuffer, W: WriteBuffer>(
    c: &mut S,
    input: &mut R,
    output: &mut W,
) -> Result<BufferResult, SymmetricCipherError> {
    let count = cmp::min(input.remaining(), output.remaining());
    c.process(input.take_next(count), output.take_next(count));
    if input.is_empty() {
        Ok(BufferUnderflow)
    } else {
        Ok(BufferOverflow)
    }
}

/// A `FixedBuffer`, likes its name implies, is a fixed size buffer. When the buffer becomes full, it
/// must be processed. The `input()` method takes care of processing and then clearing the buffer
/// automatically. However, other methods do not and require the caller to process the buffer. Any
/// method that modifies the buffer directory or provides the caller with bytes that can be modifies
/// results in those bytes being marked as used by the buffer.
pub trait FixedBuffer {
    /// Input a vector of bytes. If the buffer becomes full, process it with the provided
    /// function and then clear the buffer.
    fn input<F: FnMut(&[u8])>(&mut self, input: &[u8], func: F);

    /// Reset the buffer.
    fn reset(&mut self);

    /// Zero the buffer up until the specified index. The buffer position currently must not be
    /// greater than that index.
    fn zero_until(&mut self, idx: usize);

    /// Get a slice of the buffer of the specified size. There must be at least that many bytes
    /// remaining in the buffer.
    fn next(&mut self, len: usize) -> &mut [u8];

    /// Get the current buffer. The buffer must already be full. This clears the buffer as well.
    fn full_buffer(&mut self) -> &[u8];

    /// Get the current buffer.
    fn current_buffer(&mut self) -> &[u8];

    /// Get the current position of the buffer.
    fn position(&self) -> usize;

    /// Get the number of bytes remaining in the buffer until it is full.
    fn remaining(&self) -> usize;

    /// Get the size of the buffer
    fn size(&self) -> usize;
}

macro_rules! impl_fixed_buffer( ($name:ident, $size:expr, $shift:expr) => (
    impl FixedBuffer for $name {
        fn input<F: FnMut(&[u8])>(&mut self, input: &[u8], mut func: F) {
            let mut i = 0;

            // FIXME: #6304 - This local variable shouldn't be necessary.
            let size = $size;

            // If there is already data in the buffer, copy as much as we can into it and process
            // the data if the buffer becomes full.
            if self.buffer_idx != 0 {
                let buffer_remaining = size - self.buffer_idx;
                if input.len() >= buffer_remaining {
                        copy_memory(
                            &input[..buffer_remaining],
                            &mut self.buffer[self.buffer_idx..size]);
                    self.buffer_idx = 0;
                    func(&self.buffer);
                    i += buffer_remaining;
                } else {
                    copy_memory(
                        input,
                        &mut self.buffer[self.buffer_idx..self.buffer_idx + input.len()]);
                    self.buffer_idx += input.len();
                    return;
                }
            }

            // While we have at least a full buffer size chunks's worth of data, process that data
            // without copying it into the buffer
            if input.len() - i >= size {
                let remaining = input.len() - i;
                let block_bytes = (remaining >> $shift) << $shift;
                func(&input[i..i + block_bytes]);
                i += block_bytes;
            }

            // Copy any input data into the buffer. At this point in the method, the ammount of
            // data left in the input vector will be less than the buffer size and the buffer will
            // be empty.
            let input_remaining = input.len() - i;
            copy_memory(
                &input[i..],
                &mut self.buffer[0..input_remaining]);
            self.buffer_idx += input_remaining;
        }

        fn reset(&mut self) {
            self.buffer_idx = 0;
        }

        fn zero_until(&mut self, idx: usize) {
            assert!(idx >= self.buffer_idx);
            zero(&mut self.buffer[self.buffer_idx..idx]);
            self.buffer_idx = idx;
        }

        fn next(&mut self, len: usize) -> &mut [u8] {
            self.buffer_idx += len;
            &mut self.buffer[self.buffer_idx - len..self.buffer_idx]
        }

        fn full_buffer(&mut self) -> &[u8] {
            assert!(self.buffer_idx == $size);
            self.buffer_idx = 0;
            &self.buffer[..$size]
        }

        fn current_buffer(&mut self) -> &[u8] {
            let tmp = self.buffer_idx;
            self.buffer_idx = 0;
            &self.buffer[..tmp]
        }

        fn position(&self) -> usize { self.buffer_idx }

        fn remaining(&self) -> usize { $size - self.buffer_idx }

        fn size(&self) -> usize { $size }
    }
));

/// A fixed size buffer of 64 bytes useful for cryptographic operations.
#[derive(Clone)]
pub struct FixedBuffer64 {
    buffer: [u8; 64],
    buffer_idx: usize,
}

impl FixedBuffer64 {
    /// Create a new buffer
    pub fn new() -> FixedBuffer64 {
        FixedBuffer64 {
            buffer: [0u8; 64],
            buffer_idx: 0,
        }
    }
}

impl_fixed_buffer!(FixedBuffer64, 64, 6);

/// A fixed size buffer of 128 bytes useful for cryptographic operations.
#[derive(Clone)]
pub struct FixedBuffer128 {
    buffer: [u8; 128],
    buffer_idx: usize,
}

impl FixedBuffer128 {
    /// Create a new buffer
    pub fn new() -> FixedBuffer128 {
        FixedBuffer128 {
            buffer: [0u8; 128],
            buffer_idx: 0,
        }
    }
}

impl_fixed_buffer!(FixedBuffer128, 128, 7);

/// The `StandardPadding` trait adds a method useful for various hash algorithms to a `FixedBuffer`
/// struct.
pub trait StandardPadding {
    /// Add standard padding to the buffer. The buffer must not be full when this method is called
    /// and is guaranteed to have exactly rem remaining bytes when it returns. If there are not at
    /// least rem bytes available, the buffer will be zero padded, processed, cleared, and then
    /// filled with zeros again until only rem bytes are remaining.
    fn standard_padding<F: FnMut(&[u8])>(&mut self, rem: usize, func: F);
}

impl<T: FixedBuffer> StandardPadding for T {
    fn standard_padding<F: FnMut(&[u8])>(&mut self, rem: usize, mut func: F) {
        let size = self.size();

        self.next(1)[0] = 128;

        if self.remaining() < rem {
            self.zero_until(size);
            func(self.full_buffer());
        }

        self.zero_until(size - rem);
    }
}

#[cfg(test)]
pub mod test {
    use std::iter::repeat;
    use std::vec::Vec;

    use crate::digest::Digest;

    /// Feed 1,000,000 'a's into the digest with varying input sizes and check that the result is
    /// correct.
    pub fn test_digest_1million_random<D: Digest>(
        digest: &mut D,
        blocksize: usize,
        expected: &str,
    ) {
        let total_size = 1000000;
        let buffer: Vec<u8> = repeat(b'a').take(blocksize * 2).collect();
        //let mut rng = IsaacRng::new_unseeded();
        //let range = Range::new(0, 2 * blocksize + 1);
        let mut count = 0;

        digest.reset();

        while count < total_size {
            //let next = range.ind_sample(&mut rng);
            let next = 10;
            let remaining = total_size - count;
            let size = if next > remaining { remaining } else { next };
            digest.input(&buffer[..size]);
            count += size;
        }

        let result_str = digest.result_str();

        assert!(expected == &result_str[..]);
    }
}
