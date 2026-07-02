#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

use core::convert::TryInto;

#[derive(Clone)]
pub(crate) struct State<const ROUNDS: usize> {
    a: uint32x4_t,
    b: uint32x4_t,
    c: uint32x4_t,
    d: uint32x4_t,
}

#[repr(align(16))]
pub struct Align128([u32; 4]);

impl Align128 {
    pub fn zero() -> Self {
        Self([0u32; 4])
    }

    #[inline]
    fn to_uint32x4(&self) -> uint32x4_t {
        unsafe { vld1q_u32(self.0.as_ptr()) }
    }

    #[inline]
    fn from_uint32x4(&mut self, v: uint32x4_t) {
        unsafe { vst1q_u32(self.0.as_mut_ptr(), v) }
    }
}

// load 16 unaligned bytes as a 128 bits vector
#[inline]
unsafe fn loadu(p: *const u8) -> uint32x4_t {
    vreinterpretq_u32_u8(vld1q_u8(p))
}

// The four ChaCha rotation amounts (16, 12, 8, 7) each map to a dedicated
// NEON sequence rather than the generic shift-shift-xor (3 instructions):
//
// * <<< 16 : `vrev32q_u16` swaps the two 16-bit halves of each word (1 insn)
// * <<< 8  : a byte-wise `tbl` shuffle rotates each word by one byte (1 insn)
// * <<< 12 : `vsri` fuses the shift-right into the shift-left result (2 insns)
// * <<< 7  : idem (2 insns)

#[inline(always)]
unsafe fn rotl16(x: uint32x4_t) -> uint32x4_t {
    vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)))
}

#[inline(always)]
unsafe fn rotl8(x: uint32x4_t) -> uint32x4_t {
    // per 32-bit lane, bytes [b0,b1,b2,b3] (le) rotate-left-8 to [b3,b0,b1,b2]
    const IDX: [u8; 16] = [3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14];
    vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(x), vld1q_u8(IDX.as_ptr())))
}

#[inline(always)]
unsafe fn rotl12(x: uint32x4_t) -> uint32x4_t {
    vsriq_n_u32::<20>(vshlq_n_u32::<12>(x), x)
}

#[inline(always)]
unsafe fn rotl7(x: uint32x4_t) -> uint32x4_t {
    vsriq_n_u32::<25>(vshlq_n_u32::<7>(x), x)
}

macro_rules! swizzle {
    ($b: expr, $c: expr, $d: expr) => {
        $b = vextq_u32::<1>($b, $b); // <<< 8
        $c = vextq_u32::<2>($c, $c); // <<< 16
        $d = vextq_u32::<3>($d, $d); // <<< 24
    };
}

macro_rules! rotate_left {
    ($c: expr, 16) => {
        $c = rotl16($c);
    };
    ($c: expr, 12) => {
        $c = rotl12($c);
    };
    ($c: expr, 8) => {
        $c = rotl8($c);
    };
    ($c: expr, 7) => {
        $c = rotl7($c);
    };
}

macro_rules! add_rotate_xor {
    ($a: expr, $b: expr, $c: expr, $d: tt) => {
        // a += b; c ^= a; c <<<= d;
        $a = vaddq_u32($a, $b);
        $c = veorq_u32($c, $a);
        rotate_left!($c, $d);
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

// Full ChaCha quarter-round on 4 vectors, used by the 4-way keystream path
// where each vector holds one state word for 4 parallel blocks (lane = block).
// Because the words are already laid out vertically, both the column and the
// diagonal rounds are plain lane-wise operations and no swizzle is needed.
macro_rules! quarter {
    ($a: expr, $b: expr, $c: expr, $d: expr) => {
        $a = vaddq_u32($a, $b);
        $d = rotl16(veorq_u32($d, $a));
        $c = vaddq_u32($c, $d);
        $b = rotl12(veorq_u32($b, $c));
        $a = vaddq_u32($a, $b);
        $d = rotl8(veorq_u32($d, $a));
        $c = vaddq_u32($c, $d);
        $b = rotl7(veorq_u32($b, $c));
    };
}

// Transpose the 4 word-vectors of one quarter of the state (words g*4..g*4+4,
// each holding that word for the 4 blocks) into per-block vectors and store
// them. After transposition `bJ` holds the 4 words of block J for this quarter,
// which land at byte offset `J*64 + g*16` in the 256 bytes output.
macro_rules! transpose_store {
    ($optr: expr, $g: literal, $sa: expr, $sb: expr, $sc: expr, $sd: expr) => {{
        let t0 = vreinterpretq_u64_u32(vtrn1q_u32($sa, $sb));
        let t1 = vreinterpretq_u64_u32(vtrn2q_u32($sa, $sb));
        let t2 = vreinterpretq_u64_u32(vtrn1q_u32($sc, $sd));
        let t3 = vreinterpretq_u64_u32(vtrn2q_u32($sc, $sd));
        let b0 = vreinterpretq_u8_u64(vtrn1q_u64(t0, t2));
        let b1 = vreinterpretq_u8_u64(vtrn1q_u64(t1, t3));
        let b2 = vreinterpretq_u8_u64(vtrn2q_u64(t0, t2));
        let b3 = vreinterpretq_u8_u64(vtrn2q_u64(t1, t3));
        vst1q_u8($optr.add($g * 16), b0);
        vst1q_u8($optr.add(64 + $g * 16), b1);
        vst1q_u8($optr.add(128 + $g * 16), b2);
        vst1q_u8($optr.add(192 + $g * 16), b3);
    }};
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
    unsafe fn constant32() -> uint32x4_t {
        vld1q_u32(Self::CST32.as_ptr())
    }

    #[inline]
    unsafe fn constant16() -> uint32x4_t {
        vld1q_u32(Self::CST16.as_ptr())
    }

    #[inline]
    fn key32(key: &[u8]) -> (uint32x4_t, uint32x4_t, uint32x4_t) {
        let k = key.as_ptr();
        unsafe { (Self::constant32(), loadu(k), loadu(k.add(16))) }
    }

    #[inline]
    fn key16(key: &[u8]) -> (uint32x4_t, uint32x4_t, uint32x4_t) {
        let k = unsafe { loadu(key.as_ptr()) };
        (unsafe { Self::constant16() }, k, k)
    }

    #[inline]
    fn nonce(nonce: &[u8]) -> uint32x4_t {
        if nonce.len() == 16 {
            unsafe { loadu(nonce.as_ptr()) }
        } else {
            let mut n = Align128::zero();
            if nonce.len() == 12 {
                n.0[1] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
                n.0[2] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
                n.0[3] = u32::from_le_bytes(nonce[8..12].try_into().unwrap());
                n.to_uint32x4()
            } else if nonce.len() == 8 {
                n.0[2] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
                n.0[3] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
                n.to_uint32x4()
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
    pub(crate) fn set_counter(&mut self, counter: u32) {
        let mut align = Align128::zero();
        align.from_uint32x4(self.d);
        align.0[0] = counter;
        self.d = align.to_uint32x4();
    }

    #[inline]
    pub(crate) fn increment(&mut self) {
        let mut align = Align128::zero();
        align.from_uint32x4(self.d);
        align.0[0] = align.0[0].wrapping_add(1);
        self.d = align.to_uint32x4();
    }

    #[inline]
    pub(crate) fn increment64(&mut self) {
        let mut align = Align128::zero();
        align.from_uint32x4(self.d);
        let (a, overflowed) = align.0[0].overflowing_add(1);
        if overflowed {
            align.0[1] = align.0[1].wrapping_add(1);
        }
        align.0[0] = a;
        self.d = align.to_uint32x4();
    }

    #[inline]
    /// Add back the initial state
    pub(crate) fn add_back(&mut self, initial: &Self) {
        unsafe {
            self.a = vaddq_u32(self.a, initial.a);
            self.b = vaddq_u32(self.b, initial.b);
            self.c = vaddq_u32(self.c, initial.c);
            self.d = vaddq_u32(self.d, initial.d);
        }
    }

    #[inline]
    pub(crate) fn output_bytes(&self, output: &mut [u8]) {
        let o = output.as_mut_ptr();
        unsafe {
            vst1q_u8(o, vreinterpretq_u8_u32(self.a));
            vst1q_u8(o.add(16), vreinterpretq_u8_u32(self.b));
            vst1q_u8(o.add(32), vreinterpretq_u8_u32(self.c));
            vst1q_u8(o.add(48), vreinterpretq_u8_u32(self.d));
        }
    }

    #[inline]
    pub(crate) fn output_ad_bytes(&self, output: &mut [u8; 32]) {
        let o = output.as_mut_ptr();
        unsafe {
            vst1q_u8(o, vreinterpretq_u8_u32(self.a));
            vst1q_u8(o.add(16), vreinterpretq_u8_u32(self.d));
        }
    }

    /// Generate the next 4 keystream blocks (256 bytes) in one pass and advance
    /// the (32-bit) block counter by 4.
    ///
    /// The 16 state words are held "vertically": vector `sN` keeps word `N` for
    /// all 4 blocks (lane `j` = block `base + j`). This exposes 4 independent
    /// quarter-rounds per round for the pipelines to overlap and removes the
    /// per-block swizzle; a final 4x4 transpose lays each block out contiguously.
    #[inline]
    pub(crate) fn keystream4(&mut self, out: &mut [u8; 256]) {
        // per-lane counter offsets for the 4 parallel blocks
        const CTR: [u32; 4] = [0, 1, 2, 3];
        unsafe {
            // broadcast each word to all lanes; word 12 additionally gets the
            // [0,1,2,3] counter offsets so lane j processes block (base + j)
            let i0 = vdupq_laneq_u32::<0>(self.a);
            let i1 = vdupq_laneq_u32::<1>(self.a);
            let i2 = vdupq_laneq_u32::<2>(self.a);
            let i3 = vdupq_laneq_u32::<3>(self.a);
            let i4 = vdupq_laneq_u32::<0>(self.b);
            let i5 = vdupq_laneq_u32::<1>(self.b);
            let i6 = vdupq_laneq_u32::<2>(self.b);
            let i7 = vdupq_laneq_u32::<3>(self.b);
            let i8 = vdupq_laneq_u32::<0>(self.c);
            let i9 = vdupq_laneq_u32::<1>(self.c);
            let i10 = vdupq_laneq_u32::<2>(self.c);
            let i11 = vdupq_laneq_u32::<3>(self.c);
            let i12 = vaddq_u32(vdupq_laneq_u32::<0>(self.d), vld1q_u32(CTR.as_ptr()));
            let i13 = vdupq_laneq_u32::<1>(self.d);
            let i14 = vdupq_laneq_u32::<2>(self.d);
            let i15 = vdupq_laneq_u32::<3>(self.d);

            let (mut s0, mut s1, mut s2, mut s3) = (i0, i1, i2, i3);
            let (mut s4, mut s5, mut s6, mut s7) = (i4, i5, i6, i7);
            let (mut s8, mut s9, mut s10, mut s11) = (i8, i9, i10, i11);
            let (mut s12, mut s13, mut s14, mut s15) = (i12, i13, i14, i15);

            for _ in 0..(ROUNDS / 2) {
                // column round
                quarter!(s0, s4, s8, s12);
                quarter!(s1, s5, s9, s13);
                quarter!(s2, s6, s10, s14);
                quarter!(s3, s7, s11, s15);
                // diagonal round
                quarter!(s0, s5, s10, s15);
                quarter!(s1, s6, s11, s12);
                quarter!(s2, s7, s8, s13);
                quarter!(s3, s4, s9, s14);
            }

            // add the initial state back
            s0 = vaddq_u32(s0, i0);
            s1 = vaddq_u32(s1, i1);
            s2 = vaddq_u32(s2, i2);
            s3 = vaddq_u32(s3, i3);
            s4 = vaddq_u32(s4, i4);
            s5 = vaddq_u32(s5, i5);
            s6 = vaddq_u32(s6, i6);
            s7 = vaddq_u32(s7, i7);
            s8 = vaddq_u32(s8, i8);
            s9 = vaddq_u32(s9, i9);
            s10 = vaddq_u32(s10, i10);
            s11 = vaddq_u32(s11, i11);
            s12 = vaddq_u32(s12, i12);
            s13 = vaddq_u32(s13, i13);
            s14 = vaddq_u32(s14, i14);
            s15 = vaddq_u32(s15, i15);

            // transpose the vertical layout back to 4 contiguous blocks
            let o = out.as_mut_ptr();
            transpose_store!(o, 0, s0, s1, s2, s3);
            transpose_store!(o, 1, s4, s5, s6, s7);
            transpose_store!(o, 2, s8, s9, s10, s11);
            transpose_store!(o, 3, s12, s13, s14, s15);
        }

        // advance the single-block counter (word 12) by the 4 blocks consumed
        let mut align = Align128::zero();
        align.from_uint32x4(self.d);
        align.0[0] = align.0[0].wrapping_add(4);
        self.d = align.to_uint32x4();
    }
}
