//! Constant time Base32 encoding and decoding, as defined by
//! [RFC 4648 §6](https://datatracker.ietf.org/doc/html/rfc4648#section-6)
//!
//! The alphabet is the standard one: `A`-`Z` for the values 0 to 25, and
//! `2`-`7` for the values 26 to 31, with `=` used as padding character.
//!
//! Every function here works on fixed size buffers: the length of the input
//! `N` and the length of the output `M` are const generic parameters, and
//! their relation is checked at compilation time. Use [`encoded_len`] (or
//! [`encoded_len_unpadded`]) to compute the encoded size associated with a
//! given decoded size:
//!
//! ```
//! use cryptoxide::constant_time::base32;
//!
//! const SECRET_LEN: usize = 5;
//! const ENCODED_LEN: usize = base32::encoded_len(SECRET_LEN);
//!
//! let encoded: [u8; ENCODED_LEN] = base32::encode(b"fooba");
//! assert_eq!(&encoded, b"MZXW6YTB");
//!
//! let decoded = base32::decode::<ENCODED_LEN, SECRET_LEN>(&encoded);
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
//! failure reason (invalid character, bad padding, non canonical trailing
//! bits) doesn't leak through the timing of the call.
//!
//! Note that decoding is strict: only the upper case alphabet is accepted,
//! the padding needs to be exactly the one expected for the output size, and
//! the unused bits of the last symbol need to be zero (i.e. only the
//! canonical encoding of a given byte string decodes successfully).

use super::{Choice, CtEqual, CtGreater, CtLesser, CtOption, CtZero};

/// Number of bytes of an unencoded block
const BLOCK_DECODED: usize = 5;

/// Number of symbols of an encoded block
const BLOCK_ENCODED: usize = 8;

/// The padding symbol used to complete the last block
const PAD: u8 = b'=';

/// Length of the Base32 encoding, with padding, of a `decoded_len` bytes input
///
/// The result is always a multiple of 8, as the last block is completed with
/// the `=` padding symbol.
///
/// ```
/// use cryptoxide::constant_time::base32;
///
/// assert_eq!(base32::encoded_len(0), 0);
/// assert_eq!(base32::encoded_len(1), 8);
/// assert_eq!(base32::encoded_len(5), 8);
/// assert_eq!(base32::encoded_len(6), 16);
/// ```
pub const fn encoded_len(decoded_len: usize) -> usize {
    decoded_len.div_ceil(BLOCK_DECODED) * BLOCK_ENCODED
}

/// Length of the Base32 encoding, without padding, of a `decoded_len` bytes input
///
/// This is the number of symbols actually carrying data, i.e. the padding
/// symbols of [`encoded_len`] are not counted.
///
/// ```
/// use cryptoxide::constant_time::base32;
///
/// assert_eq!(base32::encoded_len_unpadded(0), 0);
/// assert_eq!(base32::encoded_len_unpadded(1), 2);
/// assert_eq!(base32::encoded_len_unpadded(5), 8);
/// assert_eq!(base32::encoded_len_unpadded(6), 10);
/// ```
pub const fn encoded_len_unpadded(decoded_len: usize) -> usize {
    (decoded_len * 8).div_ceil(5)
}

/// Number of data symbols needed by the last, possibly partial, block of
/// `rem` bytes, where `rem` is in `0..5`
const fn last_block_symbols(rem: usize) -> usize {
    encoded_len_unpadded(rem)
}

/// Map a 5 bits value to its symbol in the alphabet, in constant time
///
/// values 0 to 25 map to `A` to `Z`, and values 26 to 31 map to `2` to `7`.
/// The input is expected to be already reduced to 5 bits.
fn encode_symbol(value: u8) -> u8 {
    let is_letter = u64::ct_lt(value as u64, 26).to_mask() as u8;
    let letter = value.wrapping_add(b'A');
    let digit = value.wrapping_add(b'2'.wrapping_sub(26));
    (letter & is_letter) | (digit & !is_letter)
}

/// Map a symbol of the alphabet back to its 5 bits value, in constant time
///
/// Return the value along with the [`Choice`] of whether the symbol was part
/// of the alphabet at all; when it is not, the value returned is 0 and needs
/// to be discarded by the caller through the associated choice.
fn decode_symbol(symbol: u8) -> (Choice, u8) {
    let is_letter = in_range(symbol, b'A', b'Z');
    let is_digit = in_range(symbol, b'2', b'7');
    let letter_mask = is_letter.to_mask() as u8;
    let digit_mask = is_digit.to_mask() as u8;

    let letter = symbol.wrapping_sub(b'A');
    let digit = symbol.wrapping_sub(b'2').wrapping_add(26);

    let value = (letter & letter_mask) | (digit & digit_mask);
    (is_letter | is_digit, value)
}

/// Constant time `low <= value && value <= high`
fn in_range(value: u8, low: u8, high: u8) -> Choice {
    let value = value as u64;
    u64::ct_ge(value, low as u64) & u64::ct_le(value, high as u64)
}

/// Turn a block of 5 bytes (40 bits) into 8 symbols of 5 bits each
fn encode_block(input: &[u8; BLOCK_DECODED]) -> [u8; BLOCK_ENCODED] {
    let [b0, b1, b2, b3, b4] = *input;
    let values = [
        b0 >> 3,
        ((b0 << 2) | (b1 >> 6)) & 0x1f,
        (b1 >> 1) & 0x1f,
        ((b1 << 4) | (b2 >> 4)) & 0x1f,
        ((b2 << 1) | (b3 >> 7)) & 0x1f,
        (b3 >> 2) & 0x1f,
        ((b3 << 3) | (b4 >> 5)) & 0x1f,
        b4 & 0x1f,
    ];
    let mut out = [0; BLOCK_ENCODED];
    for (o, v) in out.iter_mut().zip(values.iter()) {
        *o = encode_symbol(*v);
    }
    out
}

/// Turn a block of 8 values of 5 bits each (40 bits) into 5 bytes
///
/// Each value is expected to be already reduced to 5 bits.
fn decode_block(values: &[u8; BLOCK_ENCODED]) -> [u8; BLOCK_DECODED] {
    let [v0, v1, v2, v3, v4, v5, v6, v7] = *values;
    [
        (v0 << 3) | (v1 >> 2),
        (v1 << 6) | (v2 << 1) | (v3 >> 4),
        (v3 << 4) | (v4 >> 1),
        (v4 << 7) | (v5 << 2) | (v6 >> 3),
        (v6 << 5) | v7,
    ]
}

/// Encode `input` into `output`, `output` being either exactly the padded or
/// the unpadded encoded length of `input`
///
/// The padding, if any, is not written here: the caller pre-fills the output
/// with the padding symbol.
fn encode_raw(input: &[u8], output: &mut [u8]) {
    let blocks = input.len() / BLOCK_DECODED;
    let rem = input.len() % BLOCK_DECODED;

    for i in 0..blocks {
        let mut block = [0; BLOCK_DECODED];
        block.copy_from_slice(&input[i * BLOCK_DECODED..(i + 1) * BLOCK_DECODED]);
        let symbols = encode_block(&block);
        output[i * BLOCK_ENCODED..(i + 1) * BLOCK_ENCODED].copy_from_slice(&symbols);
    }

    if rem > 0 {
        // the missing bytes of the last block are considered zero, and only
        // the symbols carrying data bits are written to the output
        let mut block = [0; BLOCK_DECODED];
        block[..rem].copy_from_slice(&input[blocks * BLOCK_DECODED..]);
        let symbols = encode_block(&block);
        let nb = last_block_symbols(rem);
        let start = blocks * BLOCK_ENCODED;
        output[start..start + nb].copy_from_slice(&symbols[..nb]);
    }
}

/// Decode `input` into `output`, `input` being either exactly the padded or
/// the unpadded encoded length of `output`
///
/// Return whether the input was a valid canonical encoding; when it is not,
/// the output is filled with a placeholder value that need to be discarded.
fn decode_raw(input: &[u8], output: &mut [u8], padded: bool) -> Choice {
    let blocks = output.len() / BLOCK_DECODED;
    let rem = output.len() % BLOCK_DECODED;
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

    if rem > 0 {
        let nb = last_block_symbols(rem);
        let start = blocks * BLOCK_ENCODED;

        // the symbols carrying data bits, the missing ones being considered zero
        let mut values = [0; BLOCK_ENCODED];
        for (v, symbol) in values.iter_mut().zip(input[start..start + nb].iter()) {
            let (ok, value) = decode_symbol(*symbol);
            valid = valid & ok;
            *v = value;
        }

        // the padding symbols, when the encoding is padded
        if padded {
            for symbol in input[start + nb..].iter() {
                valid = valid & symbol.ct_eq(PAD);
            }
        }

        let bytes = decode_block(&values);
        output[blocks * BLOCK_DECODED..].copy_from_slice(&bytes[..rem]);

        // the bits of the last symbol that are not part of any output byte
        // end up in the bytes of the block that are dropped, and need to be
        // zero for the encoding to be canonical
        valid = valid & (&bytes[rem..]).ct_zero();
    }

    valid
}

/// Encode a `N` bytes input into its `M` symbols Base32 padded representation
///
/// `M` need to be [`encoded_len`]`(N)`, which is checked at compilation time.
///
/// ```
/// use cryptoxide::constant_time::base32;
///
/// assert_eq!(&base32::encode::<3, 8>(b"foo"), b"MZXW6===");
/// ```
pub fn encode<const N: usize, const M: usize>(input: &[u8; N]) -> [u8; M] {
    const { assert!(M == encoded_len(N), "base32: invalid encoded output size") }
    let mut output = [PAD; M];
    encode_raw(input, &mut output);
    output
}

/// Encode a bytes input slice into its symbols Base32 padded representation.
///
/// `output.len()` need to be [`encoded_len`]`(input.len())`, which is checked at runtime.
pub fn encode_slice(input: &[u8], output: &mut [u8]) {
    assert_eq!(
        output.len(),
        encoded_len(input.len()),
        "base32: invalid encoded output size"
    );
    encode_raw(input, output)
}

/// Encode a `N` bytes input into its `M` symbols Base32 representation, without padding
///
/// `M` need to be [`encoded_len_unpadded`]`(N)`, which is checked at compilation time.
///
/// ```
/// use cryptoxide::constant_time::base32;
///
/// assert_eq!(&base32::encode_unpadded::<3, 5>(b"foo"), b"MZXW6");
/// ```
pub fn encode_unpadded<const N: usize, const M: usize>(input: &[u8; N]) -> [u8; M] {
    const {
        assert!(
            M == encoded_len_unpadded(N),
            "base32: invalid encoded output size"
        )
    }
    let mut output = [0; M];
    encode_raw(input, &mut output);
    output
}

/// Encode a bytes input slice into its symbols Base32 representation, without padding
///
/// `output.len()` need to be [`encoded_len_unpadded`]`(input.len())`, which is checked at runtime.
pub fn encode_unpadded_slice(input: &[u8], output: &mut [u8]) {
    assert_eq!(
        output.len(),
        encoded_len_unpadded(input.len()),
        "base32: invalid encoded output size"
    );
    encode_raw(input, output)
}

/// Decode a `N` symbols padded Base32 input into its `M` bytes representation
///
/// `N` need to be [`encoded_len`]`(M)`, which is checked at compilation time.
///
/// The decoding is strict: any symbol outside of the alphabet, any padding
/// symbol not at the expected place, or any non zero trailing bit in the last
/// symbol, makes the returned [`CtOption`] absent. The bytes carried by an
/// absent result are unspecified and need to be discarded.
///
/// ```
/// use cryptoxide::constant_time::base32;
///
/// let decoded = base32::decode::<8, 3>(b"MZXW6===");
/// assert_eq!(decoded.into_option(), Some(*b"foo"));
///
/// let invalid = base32::decode::<8, 3>(b"MZXW6!==");
/// assert_eq!(invalid.into_option(), None);
/// ```
pub fn decode<const N: usize, const M: usize>(input: &[u8; N]) -> CtOption<[u8; M]> {
    const { assert!(N == encoded_len(M), "base32: invalid encoded input size") }
    let mut output = [0; M];
    let valid = decode_raw(input, &mut output, true);
    (valid, output).into()
}

/// Decode padded Base32 input slice into its output slice.
///
/// `len(input)` need to be [`encoded_len`]`(output.len())`, which is asserted at runtime.
///
/// The decoding is strict: any symbol outside of the alphabet, any padding
/// symbol not at the expected place, or any non zero trailing bit in the last
/// symbol, makes the returned [`CtOption`] absent. The bytes carried by an
/// absent result are unspecified and need to be discarded.
pub fn decode_slice(input: &[u8], output: &mut [u8]) -> Choice {
    assert_eq!(
        input.len(),
        encoded_len(output.len()),
        "base32: invalid encoded input size"
    );
    decode_raw(input, output, true)
}

/// Decode a `N` symbols unpadded Base32 input into its `M` bytes representation
///
/// `N` need to be [`encoded_len_unpadded`]`(M)`, which is checked at compilation time.
///
/// The decoding is strict, in the same way as [`decode`], except that no
/// padding symbol is expected at all.
///
/// ```
/// use cryptoxide::constant_time::base32;
///
/// let decoded = base32::decode_unpadded::<5, 3>(b"MZXW6");
/// assert_eq!(decoded.into_option(), Some(*b"foo"));
/// ```
pub fn decode_unpadded<const N: usize, const M: usize>(input: &[u8; N]) -> CtOption<[u8; M]> {
    const {
        assert!(
            N == encoded_len_unpadded(M),
            "base32: invalid encoded input size"
        )
    }
    let mut output = [0; M];
    let valid = decode_raw(input, &mut output, false);
    (valid, output).into()
}

/// Decode unpadded Base32 input slice into its output slice.
///
/// `N` need to be [`encoded_len_unpadded`]`(M)`, which is asserted at runtime.
///
/// The decoding is strict, in the same way as [`decode`], except that no
/// padding symbol is expected at all.
pub fn decode_unpadded_slice(input: &[u8], output: &mut [u8]) -> Choice {
    assert_eq!(
        input.len(),
        encoded_len_unpadded(output.len()),
        "base32: invalid encoded input size"
    );
    decode_raw(input, output, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4648 §10 test vectors
    const VECTORS: [(&[u8], &str); 7] = [
        (b"", ""),
        (b"f", "MY======"),
        (b"fo", "MZXQ===="),
        (b"foo", "MZXW6==="),
        (b"foob", "MZXW6YQ="),
        (b"fooba", "MZXW6YTB"),
        (b"foobar", "MZXW6YTBOI======"),
    ];

    #[test]
    fn rfc4648_encode() {
        assert_eq!(&encode::<0, 0>(b""), VECTORS[0].1.as_bytes());
        assert_eq!(&encode::<1, 8>(b"f"), VECTORS[1].1.as_bytes());
        assert_eq!(&encode::<2, 8>(b"fo"), VECTORS[2].1.as_bytes());
        assert_eq!(&encode::<3, 8>(b"foo"), VECTORS[3].1.as_bytes());
        assert_eq!(&encode::<4, 8>(b"foob"), VECTORS[4].1.as_bytes());
        assert_eq!(&encode::<5, 8>(b"fooba"), VECTORS[5].1.as_bytes());
        assert_eq!(&encode::<6, 16>(b"foobar"), VECTORS[6].1.as_bytes());
    }

    #[test]
    fn rfc4648_decode() {
        assert_eq!(decode::<0, 0>(b"").into_option(), Some(*b""));
        assert_eq!(decode::<8, 1>(b"MY======").into_option(), Some(*b"f"));
        assert_eq!(decode::<8, 2>(b"MZXQ====").into_option(), Some(*b"fo"));
        assert_eq!(decode::<8, 3>(b"MZXW6===").into_option(), Some(*b"foo"));
        assert_eq!(decode::<8, 4>(b"MZXW6YQ=").into_option(), Some(*b"foob"));
        assert_eq!(decode::<8, 5>(b"MZXW6YTB").into_option(), Some(*b"fooba"));
        assert_eq!(
            decode::<16, 6>(b"MZXW6YTBOI======").into_option(),
            Some(*b"foobar")
        );
    }

    #[test]
    fn rfc4648_unpadded() {
        assert_eq!(&encode_unpadded::<1, 2>(b"f"), b"MY");
        assert_eq!(&encode_unpadded::<2, 4>(b"fo"), b"MZXQ");
        assert_eq!(&encode_unpadded::<3, 5>(b"foo"), b"MZXW6");
        assert_eq!(&encode_unpadded::<4, 7>(b"foob"), b"MZXW6YQ");
        assert_eq!(&encode_unpadded::<5, 8>(b"fooba"), b"MZXW6YTB");
        assert_eq!(&encode_unpadded::<6, 10>(b"foobar"), b"MZXW6YTBOI");

        assert_eq!(decode_unpadded::<2, 1>(b"MY").into_option(), Some(*b"f"));
        assert_eq!(decode_unpadded::<4, 2>(b"MZXQ").into_option(), Some(*b"fo"));
        assert_eq!(
            decode_unpadded::<5, 3>(b"MZXW6").into_option(),
            Some(*b"foo")
        );
        assert_eq!(
            decode_unpadded::<7, 4>(b"MZXW6YQ").into_option(),
            Some(*b"foob")
        );
        assert_eq!(
            decode_unpadded::<8, 5>(b"MZXW6YTB").into_option(),
            Some(*b"fooba")
        );
        assert_eq!(
            decode_unpadded::<10, 6>(b"MZXW6YTBOI").into_option(),
            Some(*b"foobar")
        );
    }

    #[test]
    fn alphabet() {
        // every value of the alphabet, in order, is 5 blocks worth of bits
        let all: [u8; 20] = [
            0x00, 0x44, 0x32, 0x14, 0xc7, 0x42, 0x54, 0xb6, 0x35, 0xcf, 0x84, 0x65, 0x3a, 0x56,
            0xd7, 0xc6, 0x75, 0xbe, 0x77, 0xdf,
        ];
        let encoded = encode::<20, 32>(&all);
        assert_eq!(&encoded, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
        assert_eq!(decode::<32, 20>(&encoded).into_option(), Some(all));

        // and each symbol individually maps back and forth
        for (value, symbol) in encoded.iter().enumerate() {
            assert_eq!(encode_symbol(value as u8), *symbol);
            let (ok, decoded) = decode_symbol(*symbol);
            assert!(ok.is_true());
            assert_eq!(decoded as usize, value);
        }
    }

    #[test]
    fn roundtrip() {
        // an arbitrary 25 bytes input, exercising all the block remainders
        let input: [u8; 25] = [
            0xde, 0xad, 0xbe, 0xef, 0x00, 0xff, 0x01, 0x10, 0x7f, 0x80, 0x55, 0xaa, 0x12, 0x34,
            0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b,
        ];

        macro_rules! roundtrip {
            ($m:expr, $n:expr, $nu:expr) => {
                let mut chunk = [0; $m];
                chunk.copy_from_slice(&input[..$m]);

                {
                    let encoded = encode::<$m, $n>(&chunk);
                    let decoded = decode::<$n, $m>(&encoded).into_option();
                    assert_eq!(decoded, Some(chunk));
                }

                {
                    let encoded = encode_unpadded::<$m, $nu>(&chunk);
                    assert_eq!(
                        decode_unpadded::<$nu, $m>(&encoded).into_option(),
                        Some(chunk)
                    );
                }

                {
                    let mut encoded = [0; $n];
                    let mut decoded = [0; $m];
                    encode_slice(&chunk, &mut encoded);
                    decode_slice(&encoded, &mut decoded);
                    assert_eq!(decoded, chunk)
                }
            };
        }

        roundtrip!(1, 8, 2);
        roundtrip!(2, 8, 4);
        roundtrip!(3, 8, 5);
        roundtrip!(4, 8, 7);
        roundtrip!(5, 8, 8);
        roundtrip!(6, 16, 10);
        roundtrip!(7, 16, 12);
        roundtrip!(8, 16, 13);
        roundtrip!(9, 16, 15);
        roundtrip!(10, 16, 16);
        roundtrip!(16, 32, 26);
        roundtrip!(25, 40, 40);
    }

    #[test]
    fn invalid_symbol() {
        // characters outside of the alphabet
        for symbol in [b'0', b'1', b'8', b'9', b'a', b'z', b'@', b'[', b'!', 0xff] {
            let (ok, _) = decode_symbol(symbol);
            assert!(ok.is_false(), "{} should not be in the alphabet", symbol);
        }

        assert!(decode::<8, 3>(b"MZXW1===").into_option().is_none());
        assert!(decode::<8, 3>(b"mzxw6===").into_option().is_none());
        assert!(decode::<8, 5>(b"MZXW6YT!").into_option().is_none());
        assert!(decode_unpadded::<5, 3>(b"MZXW=").into_option().is_none());
    }

    #[test]
    fn invalid_padding() {
        // the padding needs to be exactly where the output size dictates
        assert!(decode::<8, 3>(b"MZXW6===").into_option().is_some());
        assert!(decode::<8, 3>(b"MZXW6==A").into_option().is_none());
        assert!(decode::<8, 3>(b"MZXW6Y==").into_option().is_none());
        assert!(decode::<8, 4>(b"MZXW6YQ=").into_option().is_some());
        assert!(decode::<8, 4>(b"MZXW6YQA").into_option().is_none());
        assert!(decode::<8, 4>(b"MZXW6Y==").into_option().is_none());
        // a fully padded block is not a valid encoding of any size
        assert!(decode::<8, 1>(b"========").into_option().is_none());
    }

    #[test]
    fn non_canonical() {
        // "MY======" decodes to "f", and the 2 unused bits of 'Y' are zero;
        // the 3 other symbols sharing the same data bits have some set
        assert!(decode::<8, 1>(b"MY======").into_option().is_some());
        for symbol in [b'Z', b'2', b'3'] {
            let mut encoded = *b"MY======";
            encoded[1] = symbol;
            assert!(
                decode::<8, 1>(&encoded).into_option().is_none(),
                "trailing bits of {} should be rejected",
                symbol as char
            );
        }

        // same for the other remainders: 4, 1 and 3 unused bits respectively
        assert!(decode::<8, 2>(b"MZXR====").into_option().is_none());
        assert!(decode::<8, 3>(b"MZXW7===").into_option().is_none());
        assert!(decode::<8, 4>(b"MZXW6YR=").into_option().is_none());

        // and without padding
        assert!(decode_unpadded::<2, 1>(b"MZ").into_option().is_none());
        assert!(decode_unpadded::<5, 3>(b"MZXW7").into_option().is_none());
    }

    #[test]
    fn invalid_output_is_present_and_discardable() {
        // an invalid input still produces a fully written output, so that the
        // caller can carry it through a constant time computation
        let (present, output) = decode::<8, 3>(b"MZXW6!==").into_parts();
        assert!(present.is_false());
        assert_eq!(output.len(), 3);
    }
}
