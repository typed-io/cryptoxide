//! Constant time Base64 encoding and decoding, as defined by
//! [RFC 4648 §4](https://datatracker.ietf.org/doc/html/rfc4648#section-4)
//!
//! The alphabet is the standard one: `A`-`Z` for the values 0 to 25, `a`-`z`
//! for the values 26 to 51, `0`-`9` for the values 52 to 61, `+` for 62 and
//! `/` for 63, with `=` used as padding character.
//!
//! Every function here works on fixed size buffers: the length of the input
//! `N` and the length of the output `M` are const generic parameters, and
//! their relation is checked at compilation time. Use [`encoded_len`] (or
//! [`encoded_len_unpadded`]) to compute the encoded size associated with a
//! given decoded size:
//!
//! ```
//! use cryptoxide::constant_time::base64;
//!
//! const SECRET_LEN: usize = 6;
//! const ENCODED_LEN: usize = base64::encoded_len(SECRET_LEN);
//!
//! let encoded: [u8; ENCODED_LEN] = base64::encode(b"foobar");
//! assert_eq!(&encoded, b"Zm9vYmFy");
//!
//! let decoded = base64::decode::<ENCODED_LEN, SECRET_LEN>(&encoded);
//! assert_eq!(decoded.into_option(), Some(*b"foobar"));
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
//! Note that decoding is strict: only the standard alphabet is accepted (not
//! the URL and filename safe one using `-` and `_`), the padding needs to be
//! exactly the one expected for the output size, and the unused bits of the
//! last symbol need to be zero (i.e. only the canonical encoding of a given
//! byte string decodes successfully).

use super::{Choice, CtEqual, CtGreater, CtLesser, CtOption, CtZero};

/// Number of bytes of an unencoded block
const BLOCK_DECODED: usize = 3;

/// Number of symbols of an encoded block
const BLOCK_ENCODED: usize = 4;

/// The padding symbol used to complete the last block
const PAD: u8 = b'=';

/// Length of the Base64 encoding, with padding, of a `decoded_len` bytes input
///
/// The result is always a multiple of 4, as the last block is completed with
/// the `=` padding symbol.
///
/// ```
/// use cryptoxide::constant_time::base64;
///
/// assert_eq!(base64::encoded_len(0), 0);
/// assert_eq!(base64::encoded_len(1), 4);
/// assert_eq!(base64::encoded_len(3), 4);
/// assert_eq!(base64::encoded_len(4), 8);
/// ```
pub const fn encoded_len(decoded_len: usize) -> usize {
    decoded_len.div_ceil(BLOCK_DECODED) * BLOCK_ENCODED
}

/// Length of the Base64 encoding, without padding, of a `decoded_len` bytes input
///
/// This is the number of symbols actually carrying data, i.e. the padding
/// symbols of [`encoded_len`] are not counted.
///
/// ```
/// use cryptoxide::constant_time::base64;
///
/// assert_eq!(base64::encoded_len_unpadded(0), 0);
/// assert_eq!(base64::encoded_len_unpadded(1), 2);
/// assert_eq!(base64::encoded_len_unpadded(2), 3);
/// assert_eq!(base64::encoded_len_unpadded(3), 4);
/// assert_eq!(base64::encoded_len_unpadded(4), 6);
/// ```
pub const fn encoded_len_unpadded(decoded_len: usize) -> usize {
    (decoded_len * 8).div_ceil(6)
}

/// Number of data symbols needed by the last, possibly partial, block of
/// `rem` bytes, where `rem` is in `0..3`
const fn last_block_symbols(rem: usize) -> usize {
    encoded_len_unpadded(rem)
}

/// Map a 6 bits value to its symbol in the alphabet, in constant time
///
/// values 0 to 25 map to `A` to `Z`, values 26 to 51 map to `a` to `z`,
/// values 52 to 61 map to `0` to `9`, and 62 and 63 map to `+` and `/`.
/// The input is expected to be already reduced to 6 bits.
fn encode_symbol(value: u8) -> u8 {
    let is_upper = in_range(value, 0, 25).to_mask() as u8;
    let is_lower = in_range(value, 26, 51).to_mask() as u8;
    let is_digit = in_range(value, 52, 61).to_mask() as u8;
    let is_plus = value.ct_eq(62).to_mask() as u8;
    let is_slash = value.ct_eq(63).to_mask() as u8;

    let upper = value.wrapping_add(b'A');
    let lower = value.wrapping_add(b'a').wrapping_sub(26);
    let digit = value.wrapping_add(b'0').wrapping_sub(52);

    (upper & is_upper)
        | (lower & is_lower)
        | (digit & is_digit)
        | (b'+' & is_plus)
        | (b'/' & is_slash)
}

/// Map a symbol of the alphabet back to its 6 bits value, in constant time
///
/// Return the value along with the [`Choice`] of whether the symbol was part
/// of the alphabet at all; when it is not, the value returned is 0 and needs
/// to be discarded by the caller through the associated choice.
fn decode_symbol(symbol: u8) -> (Choice, u8) {
    let is_upper = in_range(symbol, b'A', b'Z');
    let is_lower = in_range(symbol, b'a', b'z');
    let is_digit = in_range(symbol, b'0', b'9');
    let is_plus = symbol.ct_eq(b'+');
    let is_slash = symbol.ct_eq(b'/');

    let upper = symbol.wrapping_sub(b'A');
    let lower = symbol.wrapping_sub(b'a').wrapping_add(26);
    let digit = symbol.wrapping_sub(b'0').wrapping_add(52);

    let value = (upper & is_upper.to_mask() as u8)
        | (lower & is_lower.to_mask() as u8)
        | (digit & is_digit.to_mask() as u8)
        | (62 & is_plus.to_mask() as u8)
        | (63 & is_slash.to_mask() as u8);
    (is_upper | is_lower | is_digit | is_plus | is_slash, value)
}

/// Constant time `low <= value && value <= high`
fn in_range(value: u8, low: u8, high: u8) -> Choice {
    let value = value as u64;
    u64::ct_ge(value, low as u64) & u64::ct_le(value, high as u64)
}

/// Turn a block of 3 bytes (24 bits) into 4 symbols of 6 bits each
fn encode_block(input: &[u8; BLOCK_DECODED]) -> [u8; BLOCK_ENCODED] {
    let [b0, b1, b2] = *input;
    let values = [
        b0 >> 2,
        ((b0 << 4) | (b1 >> 4)) & 0x3f,
        ((b1 << 2) | (b2 >> 6)) & 0x3f,
        b2 & 0x3f,
    ];
    let mut out = [0; BLOCK_ENCODED];
    for (o, v) in out.iter_mut().zip(values.iter()) {
        *o = encode_symbol(*v);
    }
    out
}

/// Turn a block of 4 values of 6 bits each (24 bits) into 3 bytes
///
/// Each value is expected to be already reduced to 6 bits.
fn decode_block(values: &[u8; BLOCK_ENCODED]) -> [u8; BLOCK_DECODED] {
    let [v0, v1, v2, v3] = *values;
    [(v0 << 2) | (v1 >> 4), (v1 << 4) | (v2 >> 2), (v2 << 6) | v3]
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

/// Encode a `N` bytes input into its `M` symbols Base64 padded representation
///
/// `M` need to be [`encoded_len`]`(N)`, which is checked at compilation time.
///
/// ```
/// use cryptoxide::constant_time::base64;
///
/// assert_eq!(&base64::encode::<4, 8>(b"foob"), b"Zm9vYg==");
/// ```
pub fn encode<const N: usize, const M: usize>(input: &[u8; N]) -> [u8; M] {
    const { assert!(M == encoded_len(N), "base64: invalid encoded output size") }
    let mut output = [PAD; M];
    encode_raw(input, &mut output);
    output
}

/// Encode a bytes input slice into its symbols Base64 padded representation.
///
/// `output.len()` need to be [`encoded_len`]`(input.len())`, which is checked at runtime.
pub fn encode_slice(input: &[u8], output: &mut [u8]) {
    assert_eq!(
        output.len(),
        encoded_len(input.len()),
        "base64: invalid encoded output size"
    );
    output.fill(PAD);
    encode_raw(input, output)
}

/// Encode a `N` bytes input into its `M` symbols Base64 representation, without padding
///
/// `M` need to be [`encoded_len_unpadded`]`(N)`, which is checked at compilation time.
///
/// ```
/// use cryptoxide::constant_time::base64;
///
/// assert_eq!(&base64::encode_unpadded::<4, 6>(b"foob"), b"Zm9vYg");
/// ```
pub fn encode_unpadded<const N: usize, const M: usize>(input: &[u8; N]) -> [u8; M] {
    const {
        assert!(
            M == encoded_len_unpadded(N),
            "base64: invalid encoded output size"
        )
    }
    let mut output = [0; M];
    encode_raw(input, &mut output);
    output
}

/// Encode a bytes input slice into its symbols Base64 representation, without padding
///
/// `output.len()` need to be [`encoded_len_unpadded`]`(input.len())`, which is checked at runtime.
pub fn encode_unpadded_slice(input: &[u8], output: &mut [u8]) {
    assert_eq!(
        output.len(),
        encoded_len_unpadded(input.len()),
        "base64: invalid encoded output size"
    );
    encode_raw(input, output)
}

/// Decode a `N` symbols padded Base64 input into its `M` bytes representation
///
/// `N` need to be [`encoded_len`]`(M)`, which is checked at compilation time.
///
/// The decoding is strict: any symbol outside of the alphabet, any padding
/// symbol not at the expected place, or any non zero trailing bit in the last
/// symbol, makes the returned [`CtOption`] absent. The bytes carried by an
/// absent result are unspecified and need to be discarded.
///
/// ```
/// use cryptoxide::constant_time::base64;
///
/// let decoded = base64::decode::<8, 4>(b"Zm9vYg==");
/// assert_eq!(decoded.into_option(), Some(*b"foob"));
///
/// let invalid = base64::decode::<8, 4>(b"Zm9v-g==");
/// assert_eq!(invalid.into_option(), None);
/// ```
pub fn decode<const N: usize, const M: usize>(input: &[u8; N]) -> CtOption<[u8; M]> {
    const { assert!(N == encoded_len(M), "base64: invalid encoded input size") }
    let mut output = [0; M];
    let valid = decode_raw(input, &mut output, true);
    (valid, output).into()
}

/// Decode padded Base64 input slice into its output slice.
///
/// `input.len()` need to be [`encoded_len`]`(output.len())`, which is asserted at runtime.
///
/// The decoding is strict: any symbol outside of the alphabet, any padding
/// symbol not at the expected place, or any non zero trailing bit in the last
/// symbol, makes the returned [`Choice`] false. The bytes written to the
/// output on failure are unspecified and need to be discarded.
pub fn decode_slice(input: &[u8], output: &mut [u8]) -> Choice {
    assert_eq!(
        input.len(),
        encoded_len(output.len()),
        "base64: invalid encoded input size"
    );
    decode_raw(input, output, true)
}

/// Decode a `N` symbols unpadded Base64 input into its `M` bytes representation
///
/// `N` need to be [`encoded_len_unpadded`]`(M)`, which is checked at compilation time.
///
/// The decoding is strict, in the same way as [`decode`], except that no
/// padding symbol is expected at all.
///
/// ```
/// use cryptoxide::constant_time::base64;
///
/// let decoded = base64::decode_unpadded::<6, 4>(b"Zm9vYg");
/// assert_eq!(decoded.into_option(), Some(*b"foob"));
/// ```
pub fn decode_unpadded<const N: usize, const M: usize>(input: &[u8; N]) -> CtOption<[u8; M]> {
    const {
        assert!(
            N == encoded_len_unpadded(M),
            "base64: invalid encoded input size"
        )
    }
    let mut output = [0; M];
    let valid = decode_raw(input, &mut output, false);
    (valid, output).into()
}

/// Decode unpadded Base64 input slice into its output slice.
///
/// `input.len()` need to be [`encoded_len_unpadded`]`(output.len())`, which is asserted at runtime.
///
/// The decoding is strict, in the same way as [`decode_slice`], except that no
/// padding symbol is expected at all.
pub fn decode_unpadded_slice(input: &[u8], output: &mut [u8]) -> Choice {
    assert_eq!(
        input.len(),
        encoded_len_unpadded(output.len()),
        "base64: invalid encoded input size"
    );
    decode_raw(input, output, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4648 §10 test vectors
    const VECTORS: [(&[u8], &str); 7] = [
        (b"", ""),
        (b"f", "Zg=="),
        (b"fo", "Zm8="),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg=="),
        (b"fooba", "Zm9vYmE="),
        (b"foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn rfc4648_encode() {
        assert_eq!(&encode::<0, 0>(b""), VECTORS[0].1.as_bytes());
        assert_eq!(&encode::<1, 4>(b"f"), VECTORS[1].1.as_bytes());
        assert_eq!(&encode::<2, 4>(b"fo"), VECTORS[2].1.as_bytes());
        assert_eq!(&encode::<3, 4>(b"foo"), VECTORS[3].1.as_bytes());
        assert_eq!(&encode::<4, 8>(b"foob"), VECTORS[4].1.as_bytes());
        assert_eq!(&encode::<5, 8>(b"fooba"), VECTORS[5].1.as_bytes());
        assert_eq!(&encode::<6, 8>(b"foobar"), VECTORS[6].1.as_bytes());
    }

    #[test]
    fn rfc4648_decode() {
        assert_eq!(decode::<0, 0>(b"").into_option(), Some(*b""));
        assert_eq!(decode::<4, 1>(b"Zg==").into_option(), Some(*b"f"));
        assert_eq!(decode::<4, 2>(b"Zm8=").into_option(), Some(*b"fo"));
        assert_eq!(decode::<4, 3>(b"Zm9v").into_option(), Some(*b"foo"));
        assert_eq!(decode::<8, 4>(b"Zm9vYg==").into_option(), Some(*b"foob"));
        assert_eq!(decode::<8, 5>(b"Zm9vYmE=").into_option(), Some(*b"fooba"));
        assert_eq!(decode::<8, 6>(b"Zm9vYmFy").into_option(), Some(*b"foobar"));
    }

    #[test]
    fn rfc4648_unpadded() {
        assert_eq!(&encode_unpadded::<1, 2>(b"f"), b"Zg");
        assert_eq!(&encode_unpadded::<2, 3>(b"fo"), b"Zm8");
        assert_eq!(&encode_unpadded::<3, 4>(b"foo"), b"Zm9v");
        assert_eq!(&encode_unpadded::<4, 6>(b"foob"), b"Zm9vYg");
        assert_eq!(&encode_unpadded::<5, 7>(b"fooba"), b"Zm9vYmE");
        assert_eq!(&encode_unpadded::<6, 8>(b"foobar"), b"Zm9vYmFy");

        assert_eq!(decode_unpadded::<2, 1>(b"Zg").into_option(), Some(*b"f"));
        assert_eq!(decode_unpadded::<3, 2>(b"Zm8").into_option(), Some(*b"fo"));
        assert_eq!(
            decode_unpadded::<4, 3>(b"Zm9v").into_option(),
            Some(*b"foo")
        );
        assert_eq!(
            decode_unpadded::<6, 4>(b"Zm9vYg").into_option(),
            Some(*b"foob")
        );
        assert_eq!(
            decode_unpadded::<7, 5>(b"Zm9vYmE").into_option(),
            Some(*b"fooba")
        );
        assert_eq!(
            decode_unpadded::<8, 6>(b"Zm9vYmFy").into_option(),
            Some(*b"foobar")
        );
    }

    #[test]
    fn alphabet() {
        // every value of the alphabet, in order, is 16 blocks worth of bits
        let all: [u8; 48] = [
            0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8b, 0x30, 0xd3, 0x8f, 0x41, 0x14,
            0x93, 0x51, 0x55, 0x97, 0x61, 0x96, 0x9b, 0x71, 0xd7, 0x9f, 0x82, 0x18, 0xa3, 0x92,
            0x59, 0xa7, 0xa2, 0x9a, 0xab, 0xb2, 0xdb, 0xaf, 0xc3, 0x1c, 0xb3, 0xd3, 0x5d, 0xb7,
            0xe3, 0x9e, 0xbb, 0xf3, 0xdf, 0xbf,
        ];
        let encoded = encode::<48, 64>(&all);
        assert_eq!(
            &encoded,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        );
        assert_eq!(decode::<64, 48>(&encoded).into_option(), Some(all));

        // and each symbol individually maps back and forth
        for (value, symbol) in encoded.iter().enumerate() {
            assert_eq!(encode_symbol(value as u8), *symbol);
            let (ok, decoded) = decode_symbol(*symbol);
            assert!(ok.is_true());
            assert_eq!(decoded as usize, value);
        }
    }

    #[test]
    fn decode_symbol_exhaustive() {
        // exactly the 64 symbols of the alphabet are accepted, out of the 256
        // possible bytes, and the rejected ones decode to the value 0
        let mut accepted = 0;
        for symbol in 0..=255u8 {
            let (ok, value) = decode_symbol(symbol);
            if ok.is_true() {
                accepted += 1;
                assert_eq!(encode_symbol(value), symbol);
            } else {
                assert_eq!(value, 0);
            }
        }
        assert_eq!(accepted, 64);
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
                    assert_eq!(encoded, encode::<$m, $n>(&chunk));
                    assert!(decode_slice(&encoded, &mut decoded).is_true());
                    assert_eq!(decoded, chunk);
                }

                {
                    let mut encoded = [0; $nu];
                    let mut decoded = [0; $m];
                    encode_unpadded_slice(&chunk, &mut encoded);
                    assert_eq!(encoded, encode_unpadded::<$m, $nu>(&chunk));
                    assert!(decode_unpadded_slice(&encoded, &mut decoded).is_true());
                    assert_eq!(decoded, chunk);
                }
            };
        }

        roundtrip!(1, 4, 2);
        roundtrip!(2, 4, 3);
        roundtrip!(3, 4, 4);
        roundtrip!(4, 8, 6);
        roundtrip!(5, 8, 7);
        roundtrip!(6, 8, 8);
        roundtrip!(7, 12, 10);
        roundtrip!(16, 24, 22);
        roundtrip!(25, 36, 34);
    }

    #[test]
    fn invalid_symbol() {
        // characters outside of the alphabet, including the URL safe ones and
        // the ones sitting between `+` and `/`
        for symbol in [
            b'-', b'_', b',', b'.', b'=', b' ', b'@', b'[', b'`', b'{', b':', b'*', 0x00, 0x80,
            0xff,
        ] {
            let (ok, _) = decode_symbol(symbol);
            assert!(ok.is_false(), "{} should not be in the alphabet", symbol);
        }

        assert!(decode::<4, 3>(b"Zm9-").into_option().is_none());
        assert!(decode::<4, 3>(b"Zm9_").into_option().is_none());
        assert!(decode::<8, 6>(b"Zm9vYmF!").into_option().is_none());
        assert!(decode_unpadded::<3, 2>(b"Zm=").into_option().is_none());
    }

    #[test]
    fn invalid_padding() {
        // the padding needs to be exactly where the output size dictates
        assert!(decode::<4, 1>(b"Zg==").into_option().is_some());
        assert!(decode::<4, 1>(b"Zg=A").into_option().is_none());
        assert!(decode::<4, 1>(b"Zm8=").into_option().is_none());
        assert!(decode::<4, 2>(b"Zm8=").into_option().is_some());
        assert!(decode::<4, 2>(b"Zm8A").into_option().is_none());
        assert!(decode::<4, 2>(b"Zg==").into_option().is_none());
        // a fully padded block is not a valid encoding of any size
        assert!(decode::<4, 1>(b"====").into_option().is_none());

        let mut out = [0; 1];
        assert!(decode_slice(b"Zg=A", &mut out).is_false());
    }

    #[test]
    fn non_canonical() {
        // "Zg==" decodes to "f", and the 4 unused bits of 'g' are zero; the
        // 15 other symbols sharing the same data bits have some set
        assert!(decode::<4, 1>(b"Zg==").into_option().is_some());
        for symbol in b'h'..=b'v' {
            let mut encoded = *b"Zg==";
            encoded[1] = symbol;
            assert!(
                decode::<4, 1>(&encoded).into_option().is_none(),
                "trailing bits of {} should be rejected",
                symbol as char
            );
        }

        // same for the 2 unused bits of the other remainder
        assert!(decode::<4, 2>(b"Zm8=").into_option().is_some());
        for symbol in [b'9', b'+', b'/'] {
            let mut encoded = *b"Zm8=";
            encoded[2] = symbol;
            assert!(
                decode::<4, 2>(&encoded).into_option().is_none(),
                "trailing bits of {} should be rejected",
                symbol as char
            );
        }

        // and without padding
        assert!(decode_unpadded::<2, 1>(b"Zh").into_option().is_none());
        assert!(decode_unpadded::<3, 2>(b"Zm9").into_option().is_none());
        let mut out = [0; 2];
        assert!(decode_unpadded_slice(b"Zm9", &mut out).is_false());
    }

    #[test]
    fn invalid_output_is_present_and_discardable() {
        // an invalid input still produces a fully written output, so that the
        // caller can carry it through a constant time computation
        let (present, output) = decode::<4, 3>(b"Zm9!").into_parts();
        assert!(present.is_false());
        assert_eq!(output.len(), 3);
    }
}
