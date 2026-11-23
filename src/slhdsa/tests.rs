use super::testvectors::*;
use super::*;
use crate::hashing::sha3_256;

// Signing with the `s` parameter sets takes tens of seconds per signature
// without optimisations, so those tests only run by default on an optimised
// build, `cargo test --release`; `--include-ignored` runs them regardless.
macro_rules! slow {
    () => {
        "signing an `s` parameter set is slow without optimisations, run with --release"
    };
}

macro_rules! parameter_set_tests {
    ($($set:ident, $keygen_vectors:ident, $sign_vectors:ident,
     $t_keygen:ident, $t_sign:ident, $t_roundtrip:ident $(, #[$slow:meta])?;)*) => {$(
        // Key generation against the ACVP vectors
        #[test]
        fn $t_keygen() {
            use $set::*;
            for (i, v) in $keygen_vectors.iter().enumerate() {
                let (vk, sk) = keypair(&v.seed);
                assert_eq!(vk.bytes(), &v.vk, "verifying key of vector {}", i);
                assert_eq!(sk.bytes(), &v.sk, "signing key of vector {}", i);
                assert_eq!(sk.verifying_key().bytes(), vk.bytes());
            }
        }

        // Signing against the ACVP vectors, through the internal, pure and pre
        // hash interfaces, in both the deterministic and the hedged variant,
        // followed by the verification of what was produced.
        #[test]
        $(#[$slow])?
        fn $t_sign() {
            use $set::*;
            const N: usize = RANDOMIZER_LENGTH;
            for (i, v) in $sign_vectors.iter().enumerate() {
                let sk = SigningKey::from_bytes(v.sk);
                let vk = sk.verifying_key();
                let sig = match v.interface {
                    Interface::Internal => {
                        let opt_rand = v.rnd.unwrap_or(sk.bytes()[2 * N..3 * N].try_into().unwrap());
                        let mut sig = [0u8; Signature::LENGTH];
                        sign_internal::<N, Params>(sk.bytes(), &[v.message], &opt_rand, &mut sig);
                        assert!(verify_internal::<N, Params>(vk.bytes(), &[v.message], &sig));
                        Signature::from_bytes(sig)
                    }
                    Interface::Pure => {
                        let sig = match v.rnd {
                            Some(rnd) => sk.sign(v.message, v.context, &rnd).unwrap(),
                            None => sk.sign_deterministic(v.message, v.context).unwrap(),
                        };
                        assert!(vk.verify(v.message, v.context, &sig), "vector {}", i);
                        sig
                    }
                    Interface::PreHash(ph) => {
                        let sig = match v.rnd {
                            Some(rnd) => sk.sign_prehash(ph, v.message, v.context, &rnd).unwrap(),
                            None => sk.sign_prehash_deterministic(ph, v.message, v.context).unwrap(),
                        };
                        assert!(vk.verify_prehash(ph, v.message, v.context, &sig), "vector {}", i);
                        sig
                    }
                };
                assert_eq!(
                    sha3_256(sig.as_ref()),
                    v.signature_sha3_256,
                    "signature of vector {} ({:?})",
                    i,
                    v.interface
                );
            }
        }

        #[test]
        $(#[$slow])?
        fn $t_roundtrip() {
            use $set::*;
            let (vk, sk) = keypair(&[7u8; SEED_LENGTH]);
            let message = [1u8; 100];
            let context = [2u8; 7];
            let rnd = [3u8; RANDOMIZER_LENGTH];

            let sig = sk.sign(&message, &context, &rnd).unwrap();
            assert!(vk.verify(&message, &context, &sig));

            // neither a different message nor a different context verifies,
            // nor the signature as one of the pre hash variant
            assert!(!vk.verify(&message[..99], &context, &sig));
            assert!(!vk.verify(&message, &context[..6], &sig));
            assert!(!vk.verify(&message, b"", &sig));
            assert!(!vk.verify_prehash(PreHash::Sha256, &message, &context, &sig));

            // a change to any part of the signature is caught: the randomizer,
            // the FORS signature, the bottom and the top XMSS signatures
            let n = RANDOMIZER_LENGTH;
            for pos in [0, n, n + 1000, Signature::LENGTH - 1000, Signature::LENGTH - 1] {
                let mut bytes = *sig.bytes();
                bytes[pos] ^= 0x01;
                assert!(!vk.verify(&message, &context, &Signature::from_bytes(bytes)), "{}", pos);
            }

            // a different key does not verify it either
            let (other, _) = keypair(&[8u8; SEED_LENGTH]);
            assert!(!other.verify(&message, &context, &sig));

            // the context is limited to 255 bytes
            let too_long = [0u8; MAX_CONTEXT_LENGTH + 1];
            assert_eq!(
                sk.sign(&message, &too_long, &rnd).err(),
                Some(SigningError::InvalidContextLength)
            );
            assert!(!vk.verify(&message, &too_long, &sig));
        }
    )*};
}

parameter_set_tests! {
    sha2_128s, KEYGEN_SHA2_128S, SIGGEN_SHA2_128S, keygen_sha2_128s, sign_sha2_128s, roundtrip_sha2_128s, #[cfg_attr(debug_assertions, ignore = slow!())];
    sha2_128f, KEYGEN_SHA2_128F, SIGGEN_SHA2_128F, keygen_sha2_128f, sign_sha2_128f, roundtrip_sha2_128f;
    sha2_192s, KEYGEN_SHA2_192S, SIGGEN_SHA2_192S, keygen_sha2_192s, sign_sha2_192s, roundtrip_sha2_192s, #[cfg_attr(debug_assertions, ignore = slow!())];
    sha2_192f, KEYGEN_SHA2_192F, SIGGEN_SHA2_192F, keygen_sha2_192f, sign_sha2_192f, roundtrip_sha2_192f;
    sha2_256s, KEYGEN_SHA2_256S, SIGGEN_SHA2_256S, keygen_sha2_256s, sign_sha2_256s, roundtrip_sha2_256s, #[cfg_attr(debug_assertions, ignore = slow!())];
    sha2_256f, KEYGEN_SHA2_256F, SIGGEN_SHA2_256F, keygen_sha2_256f, sign_sha2_256f, roundtrip_sha2_256f;
    shake_128s, KEYGEN_SHAKE_128S, SIGGEN_SHAKE_128S, keygen_shake_128s, sign_shake_128s, roundtrip_shake_128s, #[cfg_attr(debug_assertions, ignore = slow!())];
    shake_128f, KEYGEN_SHAKE_128F, SIGGEN_SHAKE_128F, keygen_shake_128f, sign_shake_128f, roundtrip_shake_128f;
    shake_192s, KEYGEN_SHAKE_192S, SIGGEN_SHAKE_192S, keygen_shake_192s, sign_shake_192s, roundtrip_shake_192s, #[cfg_attr(debug_assertions, ignore = slow!())];
    shake_192f, KEYGEN_SHAKE_192F, SIGGEN_SHAKE_192F, keygen_shake_192f, sign_shake_192f, roundtrip_shake_192f;
    shake_256s, KEYGEN_SHAKE_256S, SIGGEN_SHAKE_256S, keygen_shake_256s, sign_shake_256s, roundtrip_shake_256s, #[cfg_attr(debug_assertions, ignore = slow!())];
    shake_256f, KEYGEN_SHAKE_256F, SIGGEN_SHAKE_256F, keygen_shake_256f, sign_shake_256f, roundtrip_shake_256f;
}
