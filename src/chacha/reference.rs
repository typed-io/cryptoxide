use crate::cryptoutil::{read_u32_le, write_u32v_le};

#[derive(Clone)]
pub(crate) struct State<const ROUNDS: usize> {
    state: [u32; 16],
}

macro_rules! QR {
    ($a:ident, $b:ident, $c:ident, $d:ident) => {
        $a = $a.wrapping_add($b);
        $d = ($d ^ $a).rotate_left(16);
        $c = $c.wrapping_add($d);
        $b = ($b ^ $c).rotate_left(12);
        $a = $a.wrapping_add($b);
        $d = ($d ^ $a).rotate_left(8);
        $c = $c.wrapping_add($d);
        $b = ($b ^ $c).rotate_left(7);
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

    /// Initialize the state with key and nonce
    pub(crate) fn init(key: &[u8], nonce: &[u8]) -> Self {
        let mut state = [0u32; 16];
        match key.len() {
            16 => {
                state[0] = Self::CST16[0];
                state[1] = Self::CST16[1];
                state[2] = Self::CST16[2];
                state[3] = Self::CST16[3];
            }
            32 => {
                state[0] = Self::CST32[0];
                state[1] = Self::CST32[1];
                state[2] = Self::CST32[2];
                state[3] = Self::CST32[3];
                state[4] = read_u32_le(&key[0..4]);
                state[5] = read_u32_le(&key[4..8]);
                state[6] = read_u32_le(&key[8..12]);
                state[7] = read_u32_le(&key[12..16]);
                state[8] = read_u32_le(&key[16..20]);
                state[9] = read_u32_le(&key[20..24]);
                state[10] = read_u32_le(&key[24..28]);
                state[11] = read_u32_le(&key[28..32]);
            }
            _ => unreachable!(),
        };
        if nonce.len() == 16 {
            state[12] = read_u32_le(&nonce[0..4]);
            state[13] = read_u32_le(&nonce[4..8]);
            state[14] = read_u32_le(&nonce[8..12]);
            state[15] = read_u32_le(&nonce[12..16]);
        } else if nonce.len() == 12 {
            // 12 is already set to 0
            state[13] = read_u32_le(&nonce[0..4]);
            state[14] = read_u32_le(&nonce[4..8]);
            state[15] = read_u32_le(&nonce[8..12]);
        } else {
            // 12 and 13 already set to 0
            state[14] = read_u32_le(&nonce[0..4]);
            state[15] = read_u32_le(&nonce[4..8]);
        }
        Self { state }
    }

    #[inline]
    pub(crate) fn rounds(&mut self) {
        let [mut x0, mut x1, mut x2, mut x3, mut x4, mut x5, mut x6, mut x7, mut x8, mut x9, mut x10, mut x11, mut x12, mut x13, mut x14, mut x15] =
            self.state;

        for _ in 0..(ROUNDS / 2) {
            QR!(x0, x4, x8, x12);
            QR!(x1, x5, x9, x13);
            QR!(x2, x6, x10, x14);
            QR!(x3, x7, x11, x15);

            QR!(x0, x5, x10, x15);
            QR!(x1, x6, x11, x12);
            QR!(x2, x7, x8, x13);
            QR!(x3, x4, x9, x14);
        }

        self.state = [
            x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15,
        ];
    }

    #[inline]
    pub(crate) fn increment(&mut self) {
        self.state[12] = self.state[12].wrapping_add(1);
    }

    #[inline]
    pub(crate) fn increment64(&mut self) {
        self.state[12] = self.state[12].wrapping_add(1);
        if self.state[12] == 0 {
            self.state[13] = self.state[13].wrapping_add(1);
        }
    }

    #[inline]
    /// Add back the initial state
    pub(crate) fn add_back(&mut self, initial: &Self) {
        for i in 0..16 {
            self.state[i] = self.state[i].wrapping_add(initial.state[i]);
        }
    }

    #[inline]
    pub(crate) fn output_bytes(&self, output: &mut [u8]) {
        write_u32v_le(output, &self.state);
    }

    #[inline]
    pub(crate) fn output_ad_bytes(&self, output: &mut [u8; 32]) {
        write_u32v_le(&mut output[0..16], &self.state[0..4]);
        write_u32v_le(&mut output[16..32], &self.state[12..16]);
    }
}
