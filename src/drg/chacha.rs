//! A simple DRG (Deterministic Random Generator) based on Chacha Stream cipher
//!
/// The ROUNDS parameters of the DRG is the same as ChaCha ROUNDS,
/// and only the value 8, 12 and 20 are valid.
///
/// Note that lowest ROUNDS will produce a faster random generator, but will reduce
/// the margin of security of the cipher
///
/// ```
/// use cryptoxide::drg::chacha::Drg;
/// // Typically should be coming from an entropy generator (see getrandom package),
/// // or some other high quality random value
/// let seed = [1u8; 32];
/// let mut drg = Drg::<8>::new(&seed);
///
/// // produce 25 bytes of random value
/// let random = drg.bytes::<25>();
/// ```
use crate::chacha20::ChaCha;

/// A simple DRG (Deterministic Random Generator) based on ChaCha Stream cipher
///
/// The ROUNDS parameters of the DRG is the same as ChaCha ROUNDS,
/// and only the value 8, 12 and 20 are valid.
///
/// Note that lowest ROUNDS will produce a faster random generator, but will reduce
/// the margin of security of the cipher
///
/// Once created the following methods can be used to generate randomness:
///
/// * u32
/// * u64
/// * bytes<N>
/// * fill_bytes<N>
/// * fill_slice
pub struct Drg<const ROUNDS: usize>(ChaCha<ROUNDS>);

impl<const ROUNDS: usize> Drg<ROUNDS> {
    /// Create a new DRG using the seed
    pub fn new(seed: &[u8; 32]) -> Self {
        Self(ChaCha::new(seed, &[0; 8]))
    }

    /// Return the next N bytes of random data as a byte array
    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0; N];
        self.0.process_mut(&mut out);
        out
    }

    /// fill N bytes of the mutable byte array with random data
    pub fn fill_bytes<const N: usize>(&mut self, out: &mut [u8; N]) {
        self.0.process_mut(out)
    }

    /// fill bytes of the mutable byte slice with random data
    pub fn fill_slice(&mut self, out: &mut [u8]) {
        self.0.process_mut(out)
    }

    /// Return the next 8 bytes as a u64
    pub fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.bytes())
    }

    /// Return the next 4 bytes as a u32
    pub fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.bytes())
    }
}
