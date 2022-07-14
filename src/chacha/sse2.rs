#![allow(clippy::cast_ptr_alignment)]

#[cfg(target_arch = "x86")]
use core::arch::x86::*;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use core::convert::TryInto;

#[derive(Clone)]
pub(crate) struct State<const ROUNDS: usize> {
    a: __m128i,
    b: __m128i,
    c: __m128i,
    d: __m128i,
}

#[repr(align(16))]
pub struct Align128([u32; 4]);

impl Align128 {
    pub fn zero() -> Self {
        Self([0u32; 4])
    }

    #[inline]
    fn to_m128i(&self) -> __m128i {
        unsafe { _mm_load_si128(self.0.as_ptr() as *const __m128i) }
    }

    #[inline]
    fn from_m128i(&mut self, v: __m128i) {
        unsafe { _mm_store_si128(self.0.as_mut_ptr() as *mut __m128i, v) }
    }
}

macro_rules! swizzle {
    ($b: expr, $c: expr, $d: expr) => {
        $b = _mm_shuffle_epi32($b, 0b00111001); // <<< 8
        $c = _mm_shuffle_epi32($c, 0b01001110); // <<< 16
        $d = _mm_shuffle_epi32($d, 0b10010011); // <<< 24
    };
}

macro_rules! add_rotate_xor {
    ($a: expr, $b: expr, $c: expr, $d: literal) => {
        // a += b; c ^= a; c <<<= d;
        $a = _mm_add_epi32($a, $b);
        $c = _mm_xor_si128($c, $a);
        $c = _mm_xor_si128(_mm_slli_epi32($c, $d), _mm_srli_epi32($c, 32 - $d));
    };
}

macro_rules! round {
    ($a: expr, $b: expr, $c: expr, $d: expr) => {
        add_rotate_xor!($a, $b, $d, 16);
        add_rotate_xor!($c, $d, $b, 12);
        add_rotate_xor!($a, $b, $d, 8);
        add_rotate_xor!($c, $d, $b, 7);
    };
}

impl<const ROUNDS: usize> State<ROUNDS> {
    // state initialization constant le-32bit array of b"expand 16-byte k"
    const CST16: [u32; 4] = [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574];

    // state initialization constant le-32bit array of b"expand 32-byte k"
    const CST32: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    // state is initialized to the following 32 bits elements:
    // C1 C2 C3 C4
    // K1 K2 K3 K4
    // K1 K2 K3 K4 (16 bytes key) or K5 K6 K7 K8 (32 bytes keys)
    // N1 N2 N3 N4 (16 bytes nonce) or 0 N1 N2 N3 (12 bytes nonce) or 0 0 N1 N2 (8 bytes nonce)

    #[inline]
    unsafe fn constant32() -> __m128i {
        _mm_loadu_si128(Self::CST32.as_ptr() as *const __m128i)
    }

    #[inline]
    unsafe fn constant16() -> __m128i {
        _mm_loadu_si128(Self::CST16.as_ptr() as *const __m128i)
    }

    #[inline]
    fn key32(key: &[u8]) -> (__m128i, __m128i, __m128i) {
        let k = key.as_ptr();
        unsafe {
            (
                Self::constant32(),
                _mm_loadu_si128(k as *const __m128i),
                _mm_loadu_si128(k.add(16) as *const __m128i),
            )
        }
    }

    #[inline]
    fn key16(key: &[u8]) -> (__m128i, __m128i, __m128i) {
        let k = unsafe { _mm_loadu_si128(key.as_ptr() as *const __m128i) };
        (unsafe { Self::constant16() }, k, k)
    }

    #[inline]
    fn nonce(nonce: &[u8]) -> __m128i {
        if nonce.len() == 16 {
            unsafe { _mm_loadu_si128(nonce.as_ptr() as *const __m128i) }
        } else {
            let mut n = Align128::zero();
            if nonce.len() == 12 {
                n.0[1] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
                n.0[2] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
                n.0[3] = u32::from_le_bytes(nonce[8..12].try_into().unwrap());
                n.to_m128i()
            } else if nonce.len() == 8 {
                n.0[2] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
                n.0[3] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
                n.to_m128i()
            } else {
                unreachable!()
            }
        }
    }

    /// Initialize the state with key and nonce
    pub(crate) fn init(key: &[u8], nonce: &[u8]) -> Self {
        let (a, b, c) = match key.len() {
            32 => Self::key32(key),
            16 => Self::key16(key),
            _ => unreachable!(),
        };
        let d = Self::nonce(nonce);
        Self { a, b, c, d }
    }

    #[inline]
    pub(crate) fn rounds(&mut self) {
        unsafe {
            for _ in 0..(ROUNDS / 2) {
                round!(self.a, self.b, self.c, self.d);
                swizzle!(self.b, self.c, self.d);
                round!(self.a, self.b, self.c, self.d);
                swizzle!(self.d, self.c, self.b);
            }
        }
    }

    #[inline]
    pub(crate) fn increment(&mut self) {
        let mut align = Align128::zero();
        align.from_m128i(self.d);
        let (a, overflowed) = align.0[0].overflowing_add(1);
        if overflowed {
            align.0[1] = align.0[1].wrapping_add(1);
        }
        align.0[0] = a;
        self.d = align.to_m128i();
    }

    #[inline]
    /// Add back the initial state
    pub(crate) fn add_back(&mut self, initial: &Self) {
        unsafe {
            self.a = _mm_add_epi32(self.a, initial.a);
            self.b = _mm_add_epi32(self.b, initial.b);
            self.c = _mm_add_epi32(self.c, initial.c);
            self.d = _mm_add_epi32(self.d, initial.d);
        }
    }

    #[inline]
    pub(crate) fn output_bytes(&self, output: &mut [u8]) {
        #[allow(clippy::cast_ptr_alignment)]
        let o = output.as_mut_ptr() as *mut __m128i;
        unsafe {
            _mm_storeu_si128(o, self.a);
            _mm_storeu_si128(o.add(1), self.b);
            _mm_storeu_si128(o.add(2), self.c);
            _mm_storeu_si128(o.add(3), self.d);
        }
    }

    #[inline]
    pub(crate) fn output_ad_bytes(&self, output: &mut [u8; 32]) {
        #[allow(clippy::cast_ptr_alignment)]
        let o = output.as_mut_ptr() as *mut __m128i;
        unsafe {
            _mm_storeu_si128(o, self.a);
            _mm_storeu_si128(o.add(1), self.d);
        }
    }
}
