use super::testvectors::*;
use super::*;
use crate::hashing::sha3_256;

macro_rules! parameter_set_tests {
    ($vk:ident, $sk:ident, $sigt:ident, $keypair:ident,
     $keygen_vectors:ident, $sign_vectors:ident,
     $eta_bits:literal, $omega:literal, $k:literal,
     $t_keygen:ident, $t_sign:ident, $t_roundtrip:ident,
     $t_tamper:ident, $t_bad_hint:ident, $t_input_checks:ident) => {
        // Key generation against the ACVP vectors, the produced keys being
        // compared through their SHA3-256 digest.
        #[test]
        fn $t_keygen() {
            for (i, v) in $keygen_vectors.iter().enumerate() {
                let (vk, sk) = $keypair(&v.xi);
                assert_eq!(
                    sha3_256(vk.as_ref()),
                    v.vk_sha3_256,
                    "verifying key of vector {}",
                    i
                );
                assert_eq!(
                    sha3_256(sk.as_ref()),
                    v.sk_sha3_256,
                    "signing key of vector {}",
                    i
                );

                // whatever key generation produced must deserialise, and the
                // verifying key recomputed from the signing key must match
                let bytes = <[u8; $sk::LENGTH]>::try_from(*sk.bytes()).unwrap();
                assert!($sk::from_bytes(bytes).is_ok());
                assert_eq!(sk.verifying_key().as_ref(), vk.as_ref());
            }
        }

        // Signing against the ACVP vectors, in both the deterministic and the
        // hedged variant, followed by the verification of what was produced.
        #[test]
        fn $t_sign() {
            for (i, v) in $sign_vectors.iter().enumerate() {
                let sk = $sk::from_bytes(v.sk).expect("vector signing key");
                let vk = sk.verifying_key();
                assert_eq!(
                    sha3_256(vk.as_ref()),
                    v.vk_sha3_256,
                    "verifying key of vector {}",
                    i
                );

                let sig = match v.rnd {
                    Some(rnd) => sk.sign(v.message, v.context, &rnd).unwrap(),
                    None => sk.sign_deterministic(v.message, v.context).unwrap(),
                };
                assert_eq!(
                    sha3_256(sig.as_ref()),
                    v.signature_sha3_256,
                    "signature of vector {}",
                    i
                );
                assert!(vk.verify(v.message, v.context, &sig), "vector {}", i);
            }
        }

        #[test]
        fn $t_roundtrip() {
            for i in 0..2u8 {
                let (vk, sk) = $keypair(&[i; SEED_LENGTH]);
                let message = [i; 100];
                let context = [i.wrapping_add(0x40); 7];
                let rnd = [i.wrapping_add(0x80); RANDOMIZER_LENGTH];

                let sig = sk.sign(&message, &context, &rnd).unwrap();
                assert!(vk.verify(&message, &context, &sig));
                // the verifying key recomputed from the signing key is the same
                assert!(sk.verifying_key().verify(&message, &context, &sig));

                // neither a different message nor a different context verifies
                assert!(!vk.verify(&message[..99], &context, &sig));
                assert!(!vk.verify(&message, &context[..6], &sig));
                assert!(!vk.verify(&message, b"", &sig));

                // the deterministic variant repeats itself, and is exactly what
                // signing with an all zero rnd gives
                let a = sk.sign_deterministic(&message, &context).unwrap();
                let b = sk.sign_deterministic(&message, &context).unwrap();
                let z = sk
                    .sign(&message, &context, &[0u8; RANDOMIZER_LENGTH])
                    .unwrap();
                assert_eq!(a.as_ref(), b.as_ref());
                assert_eq!(a.as_ref(), z.as_ref());
                assert_ne!(a.as_ref(), sig.as_ref());
                assert!(vk.verify(&message, &context, &a));

                // the empty message and the empty context are both allowed
                let empty = sk.sign(b"", b"", &rnd).unwrap();
                assert!(vk.verify(b"", b"", &empty));

                // 255 bytes is the longest context there is
                let long = [i; MAX_CONTEXT_LENGTH];
                let sig = sk.sign(&message, &long, &rnd).unwrap();
                assert!(vk.verify(&message, &long, &sig));

                let too_long = [i; MAX_CONTEXT_LENGTH + 1];
                assert_eq!(
                    sk.sign(&message, &too_long, &rnd).err(),
                    Some(SigningError::InvalidContextLength)
                );
                assert!(!vk.verify(&message, &too_long, &sig));
            }
        }

        #[test]
        fn $t_tamper() {
            let (vk, sk) = $keypair(&[3u8; SEED_LENGTH]);
            let sig = sk
                .sign(b"message", b"context", &[4u8; RANDOMIZER_LENGTH])
                .unwrap();
            assert!(vk.verify(b"message", b"context", &sig));

            let good = <[u8; $sigt::LENGTH]>::try_from(sig.as_ref()).unwrap();
            // flipping a single bit breaks the signature wherever it falls: in
            // the commitment hash, in z, or in the hints
            for (part, at) in [
                ("commitment", 0),
                ("z", $sigt::LENGTH - ($omega + $k) - 1),
                ("hint", $sigt::LENGTH - 1),
            ] {
                let mut bytes = good;
                bytes[at] ^= 1;
                assert!(
                    !vk.verify(b"message", b"context", &$sigt::from(bytes)),
                    "tampered {}",
                    part
                );
            }

            // a z of the largest magnitude the encoding can hold is past the
            // norm bound that verification enforces
            let mut bytes = good;
            bytes[$sigt::LENGTH - ($omega + $k) - 1] = 0;
            assert!(!vk.verify(b"message", b"context", &$sigt::from(bytes)));

            // and a key that did not sign verifies nothing
            let (other, _) = $keypair(&[5u8; SEED_LENGTH]);
            assert!(!other.verify(b"message", b"context", &sig));
        }

        // The hint has exactly one valid encoding, and verification has to
        // reject every byte string that is not one (FIPS 204 Algorithm 21).
        #[test]
        fn $t_bad_hint() {
            let (vk, sk) = $keypair(&[6u8; SEED_LENGTH]);
            let sig = sk.sign(b"message", b"", &[7u8; RANDOMIZER_LENGTH]).unwrap();
            let good = <[u8; $sigt::LENGTH]>::try_from(sig.as_ref()).unwrap();

            // where the hint positions start, and where its k running totals do
            const HINT: usize = $sigt::LENGTH - ($omega + $k);
            const TOTALS: usize = $sigt::LENGTH - $k;

            let mut cases = [good; 4];
            // a running total that goes backwards
            cases[0][TOTALS] = 4;
            cases[0][TOTALS + 1] = 3;
            // a running total past omega
            cases[1][TOTALS] = ($omega + 1) as u8;
            // positions that do not strictly increase inside one polynomial
            cases[2][TOTALS..].fill(2);
            cases[2][HINT] = 7;
            cases[2][HINT + 1] = 7;
            // a non zero byte left in the padding after the last position
            cases[3][TOTALS..].fill(0);
            cases[3][HINT] = 1;

            for (i, bytes) in cases.iter().enumerate() {
                assert!(
                    !vk.verify(b"message", b"", &$sigt::from(*bytes)),
                    "malformed hint {}",
                    i
                );
            }
        }
    };
}

parameter_set_tests!(
    VerifyingKey44,
    SigningKey44,
    Signature44,
    keypair44,
    KEYGEN_44,
    SIGN_44,
    3,
    80,
    4,
    keygen_44,
    sign_44,
    roundtrip_44,
    tamper_44,
    bad_hint_44,
    input_checks_44
);

parameter_set_tests!(
    VerifyingKey65,
    SigningKey65,
    Signature65,
    keypair65,
    KEYGEN_65,
    SIGN_65,
    4,
    55,
    6,
    keygen_65,
    sign_65,
    roundtrip_65,
    tamper_65,
    bad_hint_65,
    input_checks_65
);

parameter_set_tests!(
    VerifyingKey87,
    SigningKey87,
    Signature87,
    keypair87,
    KEYGEN_87,
    SIGN_87,
    3,
    75,
    8,
    keygen_87,
    sign_87,
    roundtrip_87,
    tamper_87,
    bad_hint_87,
    input_checks_87
);

/// Every hash function the pre hash variant offers
const PREHASHES: [PreHash; 4] = [
    PreHash::Sha256,
    PreHash::Sha512,
    PreHash::Shake128,
    PreHash::Shake256,
];

// HashML-DSA (FIPS 204 section 5.4) against the ACVP pre hash vectors. Between
// them the two parameter sets below cover each of the four hash functions.
macro_rules! prehash_tests {
    ($sk:ident, $vectors:ident, $name:ident) => {
        #[test]
        fn $name() {
            for (i, v) in $vectors.iter().enumerate() {
                let sk = $sk::from_bytes(v.sk).expect("vector signing key");
                let vk = sk.verifying_key();

                let sig = match v.rnd {
                    Some(rnd) => sk
                        .sign_prehash(v.prehash, v.message, v.context, &rnd)
                        .unwrap(),
                    None => sk
                        .sign_prehash_deterministic(v.prehash, v.message, v.context)
                        .unwrap(),
                };
                assert_eq!(
                    sha3_256(sig.as_ref()),
                    v.signature_sha3_256,
                    "{:?} vector {}",
                    v.prehash,
                    i
                );
                assert!(vk.verify_prehash(v.prehash, v.message, v.context, &sig));

                // the pre hashed and the plain variant are domain separated
                assert!(!vk.verify(v.message, v.context, &sig));
                // and so are the hash functions from one another, through the
                // object identifier the message representative carries
                for other in PREHASHES {
                    if other != v.prehash {
                        assert!(
                            !vk.verify_prehash(other, v.message, v.context, &sig),
                            "{:?} accepted a {:?} signature",
                            other,
                            v.prehash
                        );
                    }
                }
            }
        }
    };
}

prehash_tests!(SigningKey44, SIGN_PREHASH_44, prehash_44);
prehash_tests!(SigningKey65, SIGN_PREHASH_65, prehash_65);

// The object identifiers all sit under nistAlgorithms.hashAlgs, ie.
// 2.16.840.1.101.3.4.2, whose DER encoding is the 06 09 60 86 48 01 65 03 04 02
// these all share; only the last arc tells the hash functions apart.
#[test]
fn prehash_object_identifiers() {
    for (ph, arc, digest) in [
        (PreHash::Sha256, 1, 32),
        (PreHash::Sha512, 3, 64),
        (PreHash::Shake128, 11, 32),
        (PreHash::Shake256, 12, 64),
    ] {
        let oid = ph.oid();
        assert_eq!(
            &oid[..10],
            &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02],
            "{:?}",
            ph
        );
        assert_eq!(oid[10], arc, "last arc of {:?}", ph);

        let mut buf = [0u8; PreHash::MAX_DIGEST];
        assert_eq!(ph.hash(b"abc", &mut buf).len(), digest, "{:?}", ph);
    }
}

// The three parameter sets must not agree on anything: the seed of key
// generation is domain separated by the dimensions (k, l).
#[test]
fn parameter_sets_are_separated() {
    // the leading rho of each verifying key comes from the same seed through a
    // different domain separator
    fn rho(vk: &[u8]) -> &[u8] {
        &vk[..32]
    }

    let (vk44, _) = keypair44(&[1u8; SEED_LENGTH]);
    let (vk65, _) = keypair65(&[1u8; SEED_LENGTH]);
    let (vk87, _) = keypair87(&[1u8; SEED_LENGTH]);

    assert_ne!(rho(vk44.as_ref()), rho(vk65.as_ref()));
    assert_ne!(rho(vk65.as_ref()), rho(vk87.as_ref()));
    assert_ne!(rho(vk44.as_ref()), rho(vk87.as_ref()));
}

// The lengths the parameter sets advertise are the ones of FIPS 204 Table 2.
#[test]
fn advertised_lengths() {
    assert_eq!(
        [
            VerifyingKey44::LENGTH,
            SigningKey44::LENGTH,
            Signature44::LENGTH
        ],
        [1312, 2560, 2420]
    );
    assert_eq!(
        [
            VerifyingKey65::LENGTH,
            SigningKey65::LENGTH,
            Signature65::LENGTH
        ],
        [1952, 4032, 3309]
    );
    assert_eq!(
        [
            VerifyingKey87::LENGTH,
            SigningKey87::LENGTH,
            Signature87::LENGTH
        ],
        [2592, 4896, 4627]
    );
}
