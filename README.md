# Cryptoxide

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![APACHE-2 licensed][apache2-badge]][apache2-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/cryptoxide.svg
[crates-url]: https://crates.io/crates/cryptoxide
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[apache2-badge]: https://img.shields.io/badge/license-APACHE--2-blue.svg
[mit-url]: https://github.com/typed-io/cryptoxide/blob/master/LICENSE-MIT
[apache2-url]: https://github.com/typed-io/cryptoxide/blob/master/LICENSE-APACHE
[actions-badge]: https://github.com/typed-io/cryptoxide/workflows/CI/badge.svg
[actions-url]: https://github.com/typed-io/cryptoxide/actions?query=workflow%3ACI+branch%3Amaster

[API Docs](https://docs.rs/cryptoxide/latest/cryptoxide)

A pure Rust implementation of various modern cryptographic algorithms, which has no dependencies
and no foreign code (specially C or assembly code). This is compatible with WASM and embedded devices.

This crates package aims to support as many architectures as possible with as
little dependencies as possible.

Disclaimer: There are no warranties in use as everything is cryptographically-related

## Overview

Cryptoxide is a cryptographic crates aiming at providing good quality and
efficient pure-rust implementation of popular cryptographic algorithms.

It provides various common algorithms in the following categories :

* Cryptographic digests: SHA1, SHA2, SHA3, Kekkak, Blake2, Ripemd160
* Message Authentication Code (MAC): HMAC, Poly1305
* Symmetric ciphers: Salsa, Chacha
* Authenticated Encryption (AE): ChachaPoly1305
* Key Derivation Function (KDF): Pbkdf2, HKDF, Scrypt

Our main goals is to provide a library that is usable in a wide array of
contextes, by supporting many platforms, but only by providing a bare bone and
close to rust core APIs.

cryptoxide has zero dependencies, and will remain dependency free. As much as
possible we rely on rust primitives, `core` only apis and in few places rely on
`alloc` to get dymamic memory functionalities until we can remove them (when
const-generic is stable).

## Fork information

This is a fork of [Rust-Crypto by DaGenix](https://github.com/DaGenix/rust-crypto), to
which we owe a debt of gratitude for starting some good quality pure Rust implementations
of various cryptographic algorithms.

Notable differences with the original sources:

* Maintained.
* Extended ED25519 support for extended secret key (64 bytes) support.
* Proper implementation of ChaChaPoly1305 (according to spec).
* Many cryptographic algorithms removed: AES, Blowfish, Fortuna, RC4, RIPEMD160, Whirlpool, MD5.

## Running benches

normally:

    cargo +nightly bench --features with-bench

or with all the cpu capability enabled:

    RUSTFLAGS="-C target_cpu=native" cargo +nightly bench --features with-bench

## supported compiler versions

| Rust    | `test` |
| ------- | :----: |
| stable  |   ✓    |
| beta    |   ✓    |
| nightly |   ✓    |

We will always aim to support the current stable version at a minimum. However,
it is likely that older versions of the Rust compiler are also supported.

# License

This project is licensed under either of the following licenses:

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)
