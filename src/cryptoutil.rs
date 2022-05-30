//! Various utility to write/read in buffers

use core::convert::TryFrom;
use core::{mem::size_of, ptr};

#[inline]
pub(crate) fn write_u64_le(dst: &mut [u8], input: u64) {
    *<&mut [u8; 8]>::try_from(dst).unwrap() = input.to_le_bytes();
}

#[inline]
pub(crate) fn write_u32_le(dst: &mut [u8], input: u32) {
    *<&mut [u8; 4]>::try_from(dst).unwrap() = input.to_le_bytes();
}

#[inline]
pub(crate) fn write_u32_be(dst: &mut [u8], input: u32) {
    *<&mut [u8; 4]>::try_from(dst).unwrap() = input.to_be_bytes();
}

macro_rules! write_array_type {
    ($C: ident, $T: ident, $F: ident) => {
        /// Write a $T into a vector, which must be of the correct size. The value is written using $F for endianness
        pub fn $C(dst: &mut [u8], input: &[$T]) {
            const SZ: usize = size_of::<$T>();
            assert!(dst.len() == SZ * input.len());
            let mut offset = 0;
            for v in input.iter() {
                match <&mut [u8; SZ]>::try_from(&mut dst[offset..offset + SZ]) {
                    Ok(t) => *t = v.$F(),
                    Err(_) => unsafe { core::hint::unreachable_unchecked() },
                }
                offset += SZ;
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
    let tmp: [u8; 4] = *<&[u8; 4]>::try_from(input).unwrap();
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

/// XOR the content an array of u64 of size N with the right hand side in place:
///
/// Figuratively this does: `lhs ^= rhs`
pub fn xor_array64_mut<const N: usize>(lhs: &mut [u64; N], rhs: &[u64; N]) {
    for (left, right) in lhs.iter_mut().zip(rhs.iter()) {
        *left ^= *right
    }
}

/// Zero all bytes in dst
#[inline]
pub fn zero(dst: &mut [u8]) {
    unsafe {
        ptr::write_bytes(dst.as_mut_ptr(), 0, dst.len());
    }
}

/// A fixed size buffer of N bytes useful for cryptographic operations.
#[derive(Clone)]
pub(crate) struct FixedBuffer<const N: usize> {
    buffer: [u8; N],
    buffer_idx: usize,
}

impl<const N: usize> PartialEq for FixedBuffer<N> {
    fn eq(&self, other: &Self) -> bool {
        self.buffer_idx == other.buffer_idx
            && self.buffer[0..self.buffer_idx] == other.buffer[0..self.buffer_idx]
    }
}

impl<const N: usize> Eq for FixedBuffer<N> {}

impl<const N: usize> FixedBuffer<N> {
    /// Create a new buffer
    pub const fn new() -> Self {
        Self {
            buffer: [0u8; N],
            buffer_idx: 0,
        }
    }

    pub fn input<F: FnMut(&[u8])>(&mut self, input: &[u8], mut func: F) {
        let mut i = 0;

        // If there is already data in the buffer, copy as much as we can into it and process
        // the data if the buffer becomes full.
        if self.buffer_idx != 0 {
            let buffer_remaining = N - self.buffer_idx;
            if input.len() >= buffer_remaining {
                self.buffer[self.buffer_idx..N].copy_from_slice(&input[..buffer_remaining]);
                self.buffer_idx = 0;
                func(&self.buffer);
                i += buffer_remaining;
            } else {
                self.buffer[self.buffer_idx..self.buffer_idx + input.len()].copy_from_slice(&input);
                self.buffer_idx += input.len();
                return;
            }
        }

        // While we have at least a full buffer size chunks's worth of data, process that data
        // without copying it into the buffer
        if input.len() - i >= N {
            let remaining = input.len() - i;
            let block_bytes = (remaining / N) * N;
            func(&input[i..i + block_bytes]);
            i += block_bytes;
        }

        // Copy any input data into the buffer. At this point in the method, the ammount of
        // data left in the input vector will be less than the buffer size and the buffer will
        // be empty.
        let input_remaining = input.len() - i;
        self.buffer[0..input_remaining].copy_from_slice(&input[i..]);
        self.buffer_idx += input_remaining;
    }

    pub fn reset(&mut self) {
        self.buffer_idx = 0;
    }

    fn zero_until(&mut self, idx: usize) {
        assert!(idx >= self.buffer_idx);
        zero(&mut self.buffer[self.buffer_idx..idx]);
        self.buffer_idx = idx;
    }

    pub fn next<const I: usize>(&mut self) -> &mut [u8; I] {
        let start = self.buffer_idx;
        self.buffer_idx += I;
        <&mut [u8; I]>::try_from(&mut self.buffer[start..self.buffer_idx]).unwrap()
    }

    pub fn full_buffer(&mut self) -> &[u8; N] {
        assert!(self.buffer_idx == N);
        self.buffer_idx = 0;
        &self.buffer
    }

    /// Add standard padding to the buffer. The buffer must not be full when this method is called
    /// and is guaranteed to have exactly rem remaining bytes when it returns. If there are not at
    /// least rem bytes available, the buffer will be zero padded, processed, cleared, and then
    /// filled with zeros again until only rem bytes are remaining.
    pub fn standard_padding<F: FnMut(&[u8; N])>(&mut self, rem: usize, mut func: F) {
        self.next::<1>()[0] = 128;

        if (N - self.buffer_idx) < rem {
            self.zero_until(N);
            func(self.full_buffer());
        }

        self.zero_until(N - rem);
    }
}
