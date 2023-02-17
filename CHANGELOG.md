# 0.4.4

* fix legacy blake2b and blake2s `output_bits` interface returning a value 8 times bigger.

# 0.4.3

* add Argon2 support (RFC9106)
* compilation fixes without AVX flags

# 0.4.2

* add some extra odd size legacy blake2b contextes (and some missing one)

# 0.4.1

* add some extra legacy blake2b contextes between 256 and 384 bits

# 0.4.0

* add a new simpler and more individual APIs for hashing in hashing
* optimise and reorganise curve25519 and ed25519
* optimise various hashing algorithms: sha1, sha3, ripemd160

# 0.3.5

* Add some const qualifier in Sha1 and Sha2
* Revert partially some curve25519 interface changes

# 0.3.4

* Documentation and examples for all modules
* Unpublish some internals arithmetic from curve25519

# 0.3.3

* Add Scrypt
* Add SHA1 despite unsecure in hashing context, since it is still used a lot in other context

# 0.3.2

* Fix blake2 block size specified in bits instead of the expected value in bytes, that
  will result in bug when using with HMAC

# 0.3.1

* remove unnecessary inline attribute on macro (lint warning)

# 0.3.0

* remove SymmetricCipher trait in favor of using simple function associated with the cipher.
* remove Buffer abstraction
* cargo clippy pass

# 0.2.1

* fix bug in blake2 difference between `new_keyed` and `reset_with_key` when key is empty

# 0.2.0

* Rewrite and optimise Blake2 for AVX and AVX2
* Rewrite and optimise Sha2 for AVX and AVX2
* Optimise ChaCha for AVX and AVX2
* Rewrite SHA3 interface to have specific instance for each size

# 0.1.3

* Add salsa20
* CI related changes
* reformat modules

# 0.1.2

* Add incremental streaming interface for Chacha20Poly1305

# 0.1.1

* add some tests
* add CI
* code tweak in Chacha20Poly1305

# 0.1.0

* initial commit, source from dagenix/rust-crypto cleanup, streamlined for modern algorithms, fix to work with wasm
