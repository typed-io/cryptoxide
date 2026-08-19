//! Various utility to write/read in buffers

#[cfg(any(
    all(feature = "chacha", feature = "poly1305"),
    all(
        feature = "poly1305",
        not(any(target_arch = "arm", target_arch = "riscv32", feature = "force-32bits"))
    )
))]
#[inline]
pub(crate) fn write_u64_le(dst: &mut [u8], input: u64) {
    *<&mut [u8; 8]>::try_from(dst).unwrap() = input.to_le_bytes();
}

#[cfg(any(
    feature = "ripemd160",
    feature = "salsa",
    feature = "scrypt",
    all(
        feature = "poly1305",
        any(target_arch = "arm", target_arch = "riscv32", feature = "force-32bits")
    )
))]
#[inline]
pub(crate) fn write_u32_le(dst: &mut [u8], input: u32) {
    *<&mut [u8; 4]>::try_from(dst).unwrap() = input.to_le_bytes();
}

#[cfg(any(feature = "sha1", feature = "sha2"))]
#[inline]
pub(crate) fn write_u32_be(dst: &mut [u8], input: u32) {
    *<&mut [u8; 4]>::try_from(dst).unwrap() = input.to_be_bytes();
}

macro_rules! write_array_type {
    ($C: ident, $T: ident, $F: ident, $($feat: literal),+) => {
        /// Write a $T into a vector, which must be of the correct size. The value is written using $F for endianness
        #[cfg(any($(feature = $feat),+))]
        pub fn $C(dst: &mut [u8], input: &[$T]) {
            const SZ: usize = core::mem::size_of::<$T>();
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

write_array_type!(write_u64v_le, u64, to_le_bytes, "blake2", "sha3");
write_array_type!(write_u64v_be, u64, to_be_bytes, "sha2");
write_array_type!(
    write_u32v_le,
    u32,
    to_le_bytes,
    "salsa",
    "chacha",
    "blake2",
    "blake3"
);
write_array_type!(write_u32v_be, u32, to_be_bytes, "sha2");

macro_rules! read_array_type {
    ($C: ident, $T: ident, $F: ident, $($feat: literal),+) => {
        /// Read an array of bytes into an array of $T. The values are read with $F for endianness.
        #[cfg(any($(feature = $feat),+))]
        pub fn $C(dst: &mut [$T], input: &[u8]) {
            const SZ: usize = core::mem::size_of::<$T>();
            assert!(dst.len() * SZ == input.len());

            unsafe {
                let mut x: *mut $T = dst.as_mut_ptr();
                let mut y: *const u8 = input.as_ptr();

                for _ in 0..dst.len() {
                    let mut tmp = [0u8; SZ];
                    core::ptr::copy_nonoverlapping(y, &mut tmp as *mut _ as *mut u8, SZ);
                    *x = $T::$F(tmp);
                    x = x.add(1);
                    y = y.add(SZ);
                }
            }
        }
    };
}

read_array_type!(read_u64v_be, u64, from_be_bytes, "sha2");
read_array_type!(read_u64v_le, u64, from_le_bytes, "blake2", "sha3");
read_array_type!(read_u32v_be, u32, from_be_bytes, "sha2", "sha1");
read_array_type!(
    read_u32v_le,
    u32,
    from_le_bytes,
    "scrypt",
    "blake3",
    "ripemd160",
    "blake2"
);

/// Read the value of a vector of bytes as a u32 value in little-endian format.
#[cfg(any(
    feature = "salsa",
    feature = "chacha",
    feature = "scrypt",
    all(
        feature = "poly1305",
        any(target_arch = "arm", target_arch = "riscv32", feature = "force-32bits")
    )
))]
#[inline]
pub fn read_u32_le(input: &[u8]) -> u32 {
    let tmp: [u8; 4] = *<&[u8; 4]>::try_from(input).unwrap();
    u32::from_le_bytes(tmp)
}

/// Read the value of a vector of bytes as a u64 value in little-endian format.
#[cfg(all(
    feature = "poly1305",
    not(any(target_arch = "arm", target_arch = "riscv32", feature = "force-32bits"))
))]
#[inline]
pub fn read_u64_le(input: &[u8]) -> u64 {
    let tmp: [u8; 8] = *<&[u8; 8]>::try_from(input).unwrap();
    u64::from_le_bytes(tmp)
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

/// XOR a keystream in a buffer
#[cfg(any(feature = "chacha", feature = "salsa"))]
pub fn xor_keystream_mut(buf: &mut [u8], keystream: &[u8]) {
    assert!(buf.len() <= keystream.len());
    for (d, k) in buf.iter_mut().zip(keystream.iter()) {
        *d ^= *k
    }
}

/// XOR the content an array of u64 of size N with the right hand side in place:
///
/// Figuratively this does: `lhs ^= rhs`
#[cfg(feature = "argon2")]
pub fn xor_array64_mut<const N: usize>(lhs: &mut [u64; N], rhs: &[u64; N]) {
    for (left, right) in lhs.iter_mut().zip(rhs.iter()) {
        *left ^= *right
    }
}

/// Zero all bytes in dst
#[cfg(any(
    feature = "blake2",
    feature = "hmac",
    feature = "poly1305",
    feature = "ripemd160",
    feature = "sha1",
    feature = "sha2",
    feature = "sha3"
))]
#[inline]
pub fn zero(dst: &mut [u8]) {
    unsafe {
        core::ptr::write_bytes(dst.as_mut_ptr(), 0, dst.len());
    }
}

/// A fixed size buffer of N bytes useful for cryptographic operations.
#[cfg(any(
    feature = "poly1305",
    feature = "ripemd160",
    feature = "sha1",
    feature = "sha2"
))]
#[derive(Clone)]
pub(crate) struct FixedBuffer<const N: usize> {
    buffer: [u8; N],
    buffer_idx: usize,
}

#[cfg(any(
    feature = "poly1305",
    feature = "ripemd160",
    feature = "sha1",
    feature = "sha2"
))]
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

    /// Return whether the buffer holds no pending byte
    #[cfg(feature = "poly1305")]
    pub fn is_empty(&self) -> bool {
        self.buffer_idx == 0
    }

    /// Zero the buffer from the current position until idx, and set the
    /// current position to idx
    pub fn zero_until(&mut self, idx: usize) {
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
    #[cfg(any(feature = "ripemd160", feature = "sha1", feature = "sha2"))]
    pub fn standard_padding<F: FnMut(&[u8; N])>(&mut self, rem: usize, mut func: F) {
        self.next::<1>()[0] = 128;

        if (N - self.buffer_idx) < rem {
            self.zero_until(N);
            func(self.full_buffer());
        }

        self.zero_until(N - rem);
    }
}

#[cfg(all(
    test,
    feature = "with-bench",
    any(feature = "chacha", feature = "salsa")
))]
mod bench {
    use ::test::Bencher;

    /// current implementation: one byte at a time through raw pointers
    fn xor_unsafe_ptr(buf: &mut [u8], keystream: &[u8]) {
        assert!(buf.len() <= keystream.len());
        let k = keystream.as_ptr();
        let d = buf.as_mut_ptr();
        for i in 0isize..buf.len() as isize {
            unsafe { *d.offset(i) = *d.offset(i) ^ *k.offset(i) };
        }
    }

    /// safe: plain zip of both iterators
    fn xor_zip(buf: &mut [u8], keystream: &[u8]) {
        assert!(buf.len() <= keystream.len());
        for (d, k) in buf.iter_mut().zip(keystream.iter()) {
            *d ^= *k
        }
    }

    /// safe: truncate the keystream first, so both slices have a length the
    /// optimiser can prove identical
    fn xor_zip_trunc(buf: &mut [u8], keystream: &[u8]) {
        let keystream = &keystream[..buf.len()];
        for (d, k) in buf.iter_mut().zip(keystream.iter()) {
            *d ^= *k
        }
    }

    /// safe: 8 bytes at a time, tail byte by byte
    fn xor_chunks8(buf: &mut [u8], keystream: &[u8]) {
        let keystream = &keystream[..buf.len()];
        let mut d = buf.chunks_exact_mut(8);
        let mut k = keystream.chunks_exact(8);
        for (d, k) in d.by_ref().zip(k.by_ref()) {
            let dv = u64::from_ne_bytes(<[u8; 8]>::try_from(&*d).unwrap());
            let kv = u64::from_ne_bytes(<[u8; 8]>::try_from(k).unwrap());
            d.copy_from_slice(&(dv ^ kv).to_ne_bytes());
        }
        for (d, k) in d.into_remainder().iter_mut().zip(k.remainder().iter()) {
            *d ^= *k
        }
    }

    /// safe: 16 bytes at a time, tail byte by byte
    fn xor_chunks16(buf: &mut [u8], keystream: &[u8]) {
        let keystream = &keystream[..buf.len()];
        let mut d = buf.chunks_exact_mut(16);
        let mut k = keystream.chunks_exact(16);
        for (d, k) in d.by_ref().zip(k.by_ref()) {
            for i in 0..16 {
                d[i] ^= k[i]
            }
        }
        for (d, k) in d.into_remainder().iter_mut().zip(k.remainder().iter()) {
            *d ^= *k
        }
    }

    static KS: [u8; 4096] = [0x5au8; 4096];

    macro_rules! bench_variants {
        ($($name:ident => $len:expr,)*) => {
            $(
            mod $name {
                use super::*;

                macro_rules! bench_one {
                    ($bench:ident, $f:ident) => {
                        #[bench]
                        fn $bench(bh: &mut Bencher) {
                            let mut buf = [3u8; $len];
                            bh.iter(|| {
                                $f(
                                    ::test::black_box(&mut buf[..]),
                                    ::test::black_box(&KS[..]),
                                );
                            });
                            bh.bytes = $len as u64;
                        }
                    };
                }

                bench_one!(unsafe_ptr, xor_unsafe_ptr);
                bench_one!(safe_zip, xor_zip);
                bench_one!(safe_zip_trunc, xor_zip_trunc);
                bench_one!(safe_chunks8, xor_chunks8);
                bench_one!(safe_chunks16, xor_chunks16);
            }
            )*
        }
    }

    bench_variants! {
        len_16 => 16,
        len_63 => 63,
        len_64 => 64,
        len_256 => 256,
        len_1024 => 1024,
        len_4096 => 4096,
    }

    #[test]
    fn variants_agree() {
        let ks: [u8; 300] = core::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(7));
        for len in [0usize, 1, 7, 8, 15, 16, 17, 63, 64, 255, 256, 300] {
            let orig: [u8; 300] = core::array::from_fn(|i| (i as u8).wrapping_mul(13));
            let mut expected = orig;
            xor_unsafe_ptr(&mut expected[..len], &ks);
            for f in [
                xor_zip as fn(&mut [u8], &[u8]),
                xor_zip_trunc,
                xor_chunks8,
                xor_chunks16,
            ] {
                let mut got = orig;
                f(&mut got[..len], &ks);
                assert_eq!(&got[..], &expected[..], "mismatch at len {}", len);
            }
        }
    }
}
