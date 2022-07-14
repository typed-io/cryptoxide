use crate::cryptoutil::{read_u32_le, write_u32v_le};
use crate::simd::u32x4;

#[derive(Clone)]
pub(crate) struct State<const ROUNDS: usize> {
    a: u32x4,
    b: u32x4,
    c: u32x4,
    d: u32x4,
}

// b row <<< 8, c row <<< 16, d row <<< 24
macro_rules! swizzle {
    ($b: expr, $c: expr, $d: expr) => {{
        let u32x4(b10, b11, b12, b13) = $b;
        $b = u32x4(b11, b12, b13, b10);
        let u32x4(c10, c11, c12, c13) = $c;
        $c = u32x4(c12, c13, c10, c11);
        let u32x4(d10, d11, d12, d13) = $d;
        $d = u32x4(d13, d10, d11, d12);
    }};
}

macro_rules! round {
    ($state: expr) => {{
        $state.a = $state.a + $state.b;
        rotate!($state.d, $state.a, S16);
        $state.c = $state.c + $state.d;
        rotate!($state.b, $state.c, S12);
        $state.a = $state.a + $state.b;
        rotate!($state.d, $state.a, S8);
        $state.c = $state.c + $state.d;
        rotate!($state.b, $state.c, S7);
    }};
}

macro_rules! rotate {
    ($a: expr, $b: expr, $c:expr) => {{
        let v = $a ^ $b;
        let r = S32 - $c;
        let right = v >> r;
        $a = (v << $c) ^ right
    }};
}

static S32: u32x4 = u32x4(32, 32, 32, 32);
static S16: u32x4 = u32x4(16, 16, 16, 16);
static S12: u32x4 = u32x4(12, 12, 12, 12);
static S8: u32x4 = u32x4(8, 8, 8, 8);
static S7: u32x4 = u32x4(7, 7, 7, 7);

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

    /// Initialize the state with key and nonce
    pub(crate) fn init(key: &[u8], nonce: &[u8]) -> Self {
        let (a, b, c) = match key.len() {
            16 => Self::init_key16(key),
            32 => Self::init_key32(key),
            _ => unreachable!(),
        };
        let d = Self::init_nonce(nonce);
        Self { a, b, c, d }
    }

    #[inline]
    fn init_key16(key: &[u8]) -> (u32x4, u32x4, u32x4) {
        let constant: &[u32; 4] = &Self::CST16;
        let c = u32x4(constant[0], constant[1], constant[2], constant[3]);
        let k1 = u32x4(
            read_u32_le(&key[0..4]),
            read_u32_le(&key[4..8]),
            read_u32_le(&key[8..12]),
            read_u32_le(&key[12..16]),
        );
        (c, k1, k1)
    }

    #[inline]
    fn init_key32(key: &[u8]) -> (u32x4, u32x4, u32x4) {
        let constant: &[u32; 4] = &Self::CST32;
        let c = u32x4(constant[0], constant[1], constant[2], constant[3]);
        let k1 = u32x4(
            read_u32_le(&key[0..4]),
            read_u32_le(&key[4..8]),
            read_u32_le(&key[8..12]),
            read_u32_le(&key[12..16]),
        );
        let k2 = u32x4(
            read_u32_le(&key[16..20]),
            read_u32_le(&key[20..24]),
            read_u32_le(&key[24..28]),
            read_u32_le(&key[28..32]),
        );
        (c, k1, k2)
    }

    #[inline]
    fn init_nonce(nonce: &[u8]) -> u32x4 {
        if nonce.len() == 16 {
            u32x4(
                read_u32_le(&nonce[0..4]),
                read_u32_le(&nonce[4..8]),
                read_u32_le(&nonce[8..12]),
                read_u32_le(&nonce[12..16]),
            )
        } else if nonce.len() == 12 {
            u32x4(
                0,
                read_u32_le(&nonce[0..4]),
                read_u32_le(&nonce[4..8]),
                read_u32_le(&nonce[8..12]),
            )
        } else {
            u32x4(0, 0, read_u32_le(&nonce[0..4]), read_u32_le(&nonce[4..8]))
        }
    }

    #[inline]
    pub(crate) fn rounds(&mut self) {
        for _ in 0..(ROUNDS / 2) {
            round!(self);
            swizzle!(self.b, self.c, self.d);
            round!(self);
            swizzle!(self.d, self.c, self.b);
        }
    }

    #[inline]
    pub(crate) fn increment(&mut self) {
        self.d = self.d + u32x4(1, 0, 0, 0);
    }

    #[inline]
    /// Add back the initial state
    pub(crate) fn add_back(&mut self, initial: &Self) {
        self.a = self.a + initial.a;
        self.b = self.b + initial.b;
        self.c = self.c + initial.c;
        self.d = self.d + initial.d;
    }

    #[inline]
    pub(crate) fn output_bytes(&self, output: &mut [u8]) {
        let u32x4(a1, a2, a3, a4) = self.a;
        let u32x4(b1, b2, b3, b4) = self.b;
        let u32x4(c1, c2, c3, c4) = self.c;
        let u32x4(d1, d2, d3, d4) = self.d;
        write_u32v_le(
            output,
            &[
                a1, a2, a3, a4, b1, b2, b3, b4, c1, c2, c3, c4, d1, d2, d3, d4,
            ],
        );
    }

    #[inline]
    pub(crate) fn output_ad_bytes(&self, output: &mut [u8; 32]) {
        let u32x4(a1, a2, a3, a4) = self.a;
        let u32x4(d1, d2, d3, d4) = self.d;
        write_u32v_le(&mut output[..], &[a1, a2, a3, a4, d1, d2, d3, d4]);
    }
}
