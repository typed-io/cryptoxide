//! Constant time Base16 (hexadecimal) encoding and decoding, as defined by
//! [RFC 4648 §8](https://datatracker.ietf.org/doc/html/rfc4648#section-8)
//!
//! The alphabet is the standard one: `0`-`9` for the values 0 to 9, and
//! `A`-`F` for the values 10 to 15.
//!
//! Unlike Base32, Base16 produces no padding: every input byte maps to exactly
//! two symbols, so the encoded size is always `2 * decoded_len`. The functions
//! named after their padded counterparts (e.g. [`decode`], [`encode`]) are
//! kept for API symmetry with the other encodings and behave identically to
//! their unpadded counterparts.
//!
//! Every function here works on fixed size buffers: the length of the input
//! `N` and the length of the output `M` are const generic parameters, and
//! their relation is checked at compilation time. Use [`encoded_len`] (or
//! [`encoded_len_unpadded`]) to compute the encoded size associated with a
//! given decoded size:
//!
//! ```
//! use cryptoxide::constant_time::base16;
//!
//! const SECRET_LEN: usize = 5;
//! const ENCODED_LEN: usize = base16::encoded_len(SECRET_LEN);
//!
//! let encoded: [u8; ENCODED_LEN] = base16::encode(b"fooba");
//! assert_eq!(&encoded, b"666F6F6261");
//!
//! let decoded = base16::decode::<ENCODED_LEN, SECRET_LEN>(&encoded);
//! assert_eq!(decoded.into_option(), Some(*b"fooba"));
//! ```
//!
//! Both the encoder and the decoder are branch-free with respect to the data
//! they process: all the loop bounds and indices only depend on the const
//! generic sizes, which are public information, and the mapping from and to
//! the alphabet is done arithmetically instead of with a lookup table. This
//! makes it suitable to handle secret material, e.g. a key or a seed.
//!
//! Decoding never returns early on invalid input: the whole input is always
//! processed and the validity is reported as a [`CtOption`], so that the
//! failure reason (invalid character) doesn't leak through the timing of the
//! call.
//!
//! Note that decoding is strict: only the upper case alphabet is accepted, so
//! any symbol outside of `0`-`9` and `A`-`F` makes the decoded result absent.

use super::{Choice, CtGreater, CtLesser, CtOption};

/// Number of bytes of an unencoded block
const BLOCK_DECODED: usize = 1;

/// Number of symbols of an encoded block
const BLOCK_ENCODED: usize = 2;

/// Length of the Base16 encoding, of a `decoded_len` bytes input
///
/// The result is always `2 * decoded_len`, as every input byte maps to two
/// hexadecimal symbols.
///
/// ```
/// use cryptoxide::constant_time::base16;
///
/// assert_eq!(base16::encoded_len(0), 0);
/// assert_eq!(base16::encoded_len(1), 2);
/// assert_eq!(base16::encoded_len(3), 6);
/// assert_eq!(base16::encoded_len(4), 8);
/// ```
pub const fn encoded_len(decoded_len: usize) -> usize {
    decoded_len * 2
}

/// Length of the Base16 encoding, without padding, of a `decoded_len` bytes input
///
/// For Base16 every input byte already maps to a whole number of symbols, so
/// this is equal to [`encoded_len`].
///
/// ```
/// use cryptoxide::constant_time::base16;
///
/// assert_eq!(base16::encoded_len_unpadded(0), 0);
/// assert_eq!(base16::encoded_len_unpadded(1), 2);
/// assert_eq!(base16::encoded_len_unpadded(3), 6);
/// assert_eq!(base16::encoded_len_unpadded(4), 8);
/// ```
pub const fn encoded_len_unpadded(decoded_len: usize) -> usize {
    decoded_len * 2
}

/// Map a 4 bits value to its symbol in the alphabet, in constant time
///
/// values 0 to 9 map to `0` to `9`, and values 10 to 15 map to `A` to `F`.
/// The input is expected to be already reduced to 4 bits.
fn encode_symbol(value: u8) -> u8 {
    let is_digit = u64::ct_lt(value as u64, 10).to_mask() as u8;
    let digit = value.wrapping_add(b'0');
    let letter = value.wrapping_add(b'A'.wrapping_sub(10));
    (digit & is_digit) | (letter & !is_digit)
}

/// Map a symbol of the alphabet back to its 4 bits value, in constant time
///
/// Return the value along with the [`Choice`] of whether the symbol was part
/// of the alphabet at all; when it is not, the value returned is 0 and needs
/// to be discarded by the caller through the associated choice.
fn decode_symbol(symbol: u8) -> (Choice, u8) {
    let is_digit = in_range(symbol, b'0', b'9');
    let is_letter = in_range(symbol, b'A', b'F');
    let digit_mask = is_digit.to_mask() as u8;
    let letter_mask = is_letter.to_mask() as u8;

    let digit = symbol.wrapping_sub(b'0');
    let letter = symbol.wrapping_sub(b'A').wrapping_add(10);

    let value = (digit & digit_mask) | (letter & letter_mask);
    (is_digit | is_letter, value)
}

/// Constant time `low <= value && value <= high`
fn in_range(value: u8, low: u8, high: u8) -> Choice {
    let value = value as u64;
    u64::ct_ge(value, low as u64) & u64::ct_le(value, high as u64)
}

/// Turn a block of 1 byte (8 bits) into 2 symbols of 4 bits each
fn encode_block(input: &[u8; BLOCK_DECODED]) -> [u8; BLOCK_ENCODED] {
    let [b0] = *input;
    let values = [b0 >> 4, b0 & 0x0f];
    let mut out = [0; BLOCK_ENCODED];
    for (o, v) in out.iter_mut().zip(values.iter()) {
        *o = encode_symbol(*v);
    }
    out
}

/// Turn a block of 2 values of 4 bits each (8 bits) into 1 byte
///
/// Each value is expected to be already reduced to 4 bits.
fn decode_block(values: &[u8; BLOCK_ENCODED]) -> [u8; BLOCK_DECODED] {
    let [v0, v1] = *values;
    [(v0 << 4) | v1]
}

/// Encode `input` into `output`, `output` being the encoded length of `input`
///
/// No padding symbol is ever produced by Base16, so the caller does not need
/// to pre-fill the output.
fn encode_raw(input: &[u8], output: &mut [u8]) {
    let blocks = input.len() / BLOCK_DECODED;

    for i in 0..blocks {
        let mut block = [0; BLOCK_DECODED];
        block.copy_from_slice(&input[i * BLOCK_DECODED..(i + 1) * BLOCK_DECODED]);
        let symbols = encode_block(&block);
        output[i * BLOCK_ENCODED..(i + 1) * BLOCK_ENCODED].copy_from_slice(&symbols);
    }
}

/// Decode `input` into `output`, `input` being the encoded length of `output`
///
/// Return whether the input was a valid canonical encoding; when it is not,
/// the output is filled with a placeholder value that need to be discarded.
///
/// Base16 has no padding, so there is nothing to validate beyond the symbols
/// themselves.
fn decode_raw(input: &[u8], output: &mut [u8]) -> Choice {
    let blocks = output.len() / BLOCK_DECODED;
    let mut valid = Choice::TRUE;

    for i in 0..blocks {
        let mut values = [0; BLOCK_ENCODED];
        for (v, symbol) in values
            .iter_mut()
            .zip(input[i * BLOCK_ENCODED..(i + 1) * BLOCK_ENCODED].iter())
        {
            let (ok, value) = decode_symbol(*symbol);
            valid = valid & ok;
            *v = value;
        }
        let bytes = decode_block(&values);
        output[i * BLOCK_DECODED..(i + 1) * BLOCK_DECODED].copy_from_slice(&bytes);
    }

    valid
}

/// Encode a `N` bytes input into its `M` symbols Base16 representation
///
/// `M` need to be [`encoded_len`]`(N)`, which is checked at compilation time.
/// As Base16 produces no padding, this is identical to [`encode_unpadded`].
///
/// ```
/// use cryptoxide::constant_time::base16;
///
/// assert_eq!(&base16::encode::<3, 6>(b"foo"), b"666F6F");
/// ```
pub fn encode<const N: usize, const M: usize>(input: &[u8; N]) -> [u8; M] {
    const { assert!(M == encoded_len(N), "base16: invalid encoded output size") }
    let mut output = [0; M];
    encode_raw(input, &mut output);
    output
}

/// Encode a bytes input slice into its symbols Base16 representation.
///
/// `output.len()` need to be [`encoded_len`]`(input.len())`, which is checked at runtime.
/// As Base16 produces no padding, this is identical to [`encode_unpadded_slice`].
pub fn encode_slice(input: &[u8], output: &mut [u8]) {
    assert_eq!(
        output.len(),
        encoded_len(input.len()),
        "base16: invalid encoded output size"
    );
    encode_raw(input, output)
}

/// Encode a `N` bytes input into its `M` symbols Base16 representation
///
/// `M` need to be [`encoded_len_unpadded`]`(N)`, which is checked at compilation time.
/// As Base16 produces no padding, this is identical to [`encode`].
///
/// ```
/// use cryptoxide::constant_time::base16;
///
/// assert_eq!(&base16::encode_unpadded::<3, 6>(b"foo"), b"666F6F");
/// ```
pub fn encode_unpadded<const N: usize, const M: usize>(input: &[u8; N]) -> [u8; M] {
    const {
        assert!(
            M == encoded_len_unpadded(N),
            "base16: invalid encoded output size"
        )
    }
    let mut output = [0; M];
    encode_raw(input, &mut output);
    output
}

/// Encode a bytes input slice into its symbols Base16 representation.
///
/// `output.len()` need to be [`encoded_len_unpadded`]`(input.len())`, which is checked at runtime.
/// As Base16 produces no padding, this is identical to [`encode_slice`].
pub fn encode_unpadded_slice(input: &[u8], output: &mut [u8]) {
    assert_eq!(
        output.len(),
        encoded_len_unpadded(input.len()),
        "base16: invalid encoded output size"
    );
    encode_raw(input, output)
}

/// Decode a `N` symbols Base16 input into its `M` bytes representation
///
/// `N` need to be [`encoded_len`]`(M)`, which is checked at compilation time.
///
/// The decoding is strict: any symbol outside of the alphabet makes the
/// returned [`CtOption`] absent. The bytes carried by an absent result are
/// unspecified and need to be discarded.
///
/// ```
/// use cryptoxide::constant_time::base16;
///
/// let decoded = base16::decode::<6, 3>(b"666F6F");
/// assert_eq!(decoded.into_option(), Some(*b"foo"));
///
/// let invalid = base16::decode::<6, 3>(b"666==F");
/// assert_eq!(invalid.into_option(), None);
/// ```
pub fn decode<const N: usize, const M: usize>(input: &[u8; N]) -> CtOption<[u8; M]> {
    const { assert!(N == encoded_len(M), "base16: invalid encoded input size") }
    let mut output = [0; M];
    let valid = decode_raw(input, &mut output);
    (valid, output).into()
}

/// Decode a Base16 input slice into its output slice.
///
/// `len(input)` need to be [`encoded_len`]`(output.len())`, which is asserted at runtime.
///
/// The decoding is strict: any symbol outside of the alphabet makes the
/// returned [`Choice`] false. The bytes carried by an absent result are
/// unspecified and need to be discarded.
pub fn decode_slice(input: &[u8], output: &mut [u8]) -> Choice {
    assert_eq!(
        input.len(),
        encoded_len(output.len()),
        "base16: invalid encoded input size"
    );
    decode_raw(input, output)
}

/// Decode a `N` symbols unpadded Base16 input into its `M` bytes representation
///
/// `N` need to be [`encoded_len_unpadded`]`(M)`, which is checked at compilation time.
///
/// As every Base16 byte maps to a whole number of symbols, this behaves exactly
/// like [`decode`]; it exists for API symmetry with the other encodings.
///
/// ```
/// use cryptoxide::constant_time::base16;
///
/// let decoded = base16::decode_unpadded::<6, 3>(b"666F6F");
/// assert_eq!(decoded.into_option(), Some(*b"foo"));
/// ```
pub fn decode_unpadded<const N: usize, const M: usize>(input: &[u8; N]) -> CtOption<[u8; M]> {
    const {
        assert!(
            N == encoded_len_unpadded(M),
            "base16: invalid encoded input size"
        )
    }
    let mut output = [0; M];
    let valid = decode_raw(input, &mut output);
    (valid, output).into()
}

/// Decode an unpadded Base16 input slice into its output slice.
///
/// `N` need to be [`encoded_len_unpadded`]`(M)`, which is asserted at runtime.
///
/// As every Base16 byte maps to a whole number of symbols, this behaves exactly
/// like [`decode_slice`]; it exists for API symmetry with the other encodings.
pub fn decode_unpadded_slice(input: &[u8], output: &mut [u8]) -> Choice {
    assert_eq!(
        input.len(),
        encoded_len_unpadded(output.len()),
        "base16: invalid encoded input size"
    );
    decode_raw(input, output)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4648 §10 test vectors
    const VECTORS: [(&[u8], &str); 5] = [
        (b"", ""),
        (b"f", "66"),
        (b"fo", "666F"),
        (b"foo", "666F6F"),
        (b"foobar", "666F6F626172"),
    ];

    #[test]
    fn rfc4648_encode() {
        assert_eq!(&encode::<0, 0>(b""), VECTORS[0].1.as_bytes());
        assert_eq!(&encode::<1, 2>(b"f"), VECTORS[1].1.as_bytes());
        assert_eq!(&encode::<2, 4>(b"fo"), VECTORS[2].1.as_bytes());
        assert_eq!(&encode::<3, 6>(b"foo"), VECTORS[3].1.as_bytes());
        assert_eq!(&encode::<6, 12>(b"foobar"), VECTORS[4].1.as_bytes());
    }

    #[test]
    fn rfc4648_decode() {
        assert_eq!(decode::<0, 0>(b"").into_option(), Some(*b""));
        assert_eq!(decode::<2, 1>(b"66").into_option(), Some(*b"f"));
        assert_eq!(decode::<4, 2>(b"666F").into_option(), Some(*b"fo"));
        assert_eq!(decode::<6, 3>(b"666F6F").into_option(), Some(*b"foo"));
        assert_eq!(
            decode::<12, 6>(b"666F6F626172").into_option(),
            Some(*b"foobar")
        );
    }

    #[test]
    fn rfc4648_unpadded() {
        assert_eq!(&encode_unpadded::<1, 2>(b"f"), b"66");
        assert_eq!(&encode_unpadded::<2, 4>(b"fo"), b"666F");
        assert_eq!(&encode_unpadded::<3, 6>(b"foo"), b"666F6F");
        assert_eq!(&encode_unpadded::<6, 12>(b"foobar"), b"666F6F626172");

        assert_eq!(decode_unpadded::<2, 1>(b"66").into_option(), Some(*b"f"));
        assert_eq!(decode_unpadded::<4, 2>(b"666F").into_option(), Some(*b"fo"));
        assert_eq!(
            decode_unpadded::<6, 3>(b"666F6F").into_option(),
            Some(*b"foo")
        );
        assert_eq!(
            decode_unpadded::<12, 6>(b"666F6F626172").into_option(),
            Some(*b"foobar")
        );
    }

    #[test]
    fn alphabet() {
        // each of the sixteen symbols maps back and forth to its value 0..16
        let expected = b"0123456789ABCDEF";
        for (i, sym) in expected.iter().enumerate() {
            assert_eq!(encode_symbol(i as u8), *sym);
            let (ok, decoded) = decode_symbol(*sym);
            assert!(ok.is_true());
            assert_eq!(decoded, i as u8);
        }
    }

    #[test]
    fn roundtrip() {
        // an arbitrary 25 bytes input, exercising various sizes
        let input: [u8; 25] = [
            0xde, 0xad, 0xbe, 0xef, 0x00, 0xff, 0x01, 0x10, 0x7f, 0x80, 0x55, 0xaa, 0x12, 0x34,
            0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b,
        ];

        macro_rules! roundtrip {
            ($m:expr, $n:expr) => {
                let mut chunk = [0; $m];
                chunk.copy_from_slice(&input[..$m]);

                {
                    let encoded = encode::<$m, $n>(&chunk);
                    let decoded = decode::<$n, $m>(&encoded).into_option();
                    assert_eq!(decoded, Some(chunk));
                }

                {
                    let encoded = encode_unpadded::<$m, $n>(&chunk);
                    assert_eq!(
                        decode_unpadded::<$n, $m>(&encoded).into_option(),
                        Some(chunk)
                    );
                }

                {
                    let mut encoded = [0; $n];
                    let mut decoded = [0; $m];
                    encode_slice(&chunk, &mut encoded);
                    decode_slice(&encoded, &mut decoded);
                    assert_eq!(decoded, chunk);
                }
            };
        }

        roundtrip!(1, 2);
        roundtrip!(2, 4);
        roundtrip!(3, 6);
        roundtrip!(4, 8);
        roundtrip!(5, 10);
        roundtrip!(6, 12);
        roundtrip!(10, 20);
        roundtrip!(25, 50);
    }

    #[test]
    fn invalid_symbol() {
        // characters outside of the alphabet
        for symbol in [b'g', b'G', b'a', b'z', b'@', b'[', b'!', 0xff, b':'] {
            let (ok, _) = decode_symbol(symbol);
            assert!(ok.is_false(), "{} should not be in the alphabet", symbol);
        }

        // the lower case alphabet is rejected
        assert!(decode::<2, 1>(b"6f").into_option().is_none());
        assert!(decode_unpadded::<2, 1>(b"6f").into_option().is_none());
    }

    #[test]
    fn padded_equals_unpadded() {
        // base16 produces no padding, so the "padded" and "unpadded" APIs
        // agree on every input
        assert_eq!(encode::<3, 6>(b"foo"), encode_unpadded::<3, 6>(b"foo"));

        let encoded = encode::<3, 6>(b"foo");
        assert_eq!(
            decode::<6, 3>(&encoded).into_option(),
            decode_unpadded::<6, 3>(&encoded).into_option()
        );
        assert!(decode::<6, 3>(&encoded).into_option().is_some());
        assert_eq!(decode::<0, 0>(b"").into_option(), Some(*b""));
    }
}
