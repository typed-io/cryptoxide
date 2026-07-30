use super::testvectors::*;
use super::*;
use crate::constant_time::CtEqual;
use crate::hashing::{sha3_256, shake::Shake256};

macro_rules! parameter_set_tests {
    ($ek:ident, $dk:ident, $ct:ident,
     $keypair:ident, $encapsulate:ident, $decapsulate:ident,
     $keygen_vectors:ident, $encap_vector:ident,
     $t_keygen:ident, $t_encap:ident, $t_exchange:ident, $t_input_checks:ident) => {
        // Key generation against the ACVP vectors, the produced keys being
        // compared through their SHA3-256 digest.
        #[test]
        fn $t_keygen() {
            for (i, v) in $keygen_vectors.iter().enumerate() {
                let (ek, dk) = $keypair(&v.d, &v.z);
                assert_eq!(
                    sha3_256(ek.as_ref()),
                    v.ek_sha3_256,
                    "encapsulation key of vector {}",
                    i
                );
                assert_eq!(
                    sha3_256(dk.as_ref()),
                    v.dk_sha3_256,
                    "decapsulation key of vector {}",
                    i
                );
            }
        }

        // Encapsulation against an ACVP vector, followed by the decapsulation of
        // that same ciphertext. Deserialising the decapsulation key exercises
        // the hash check on a key known to be well formed.
        #[test]
        fn $t_encap() {
            let v = &$encap_vector;
            let dk = $dk::from_bytes(v.dk).unwrap();

            let (ct, secret) = $encapsulate(&dk.encapsulation_key(), &v.m);
            assert_eq!(ct.as_ref(), &v.c[..], "ciphertext");
            assert_eq!(secret.as_ref(), &v.k[..], "encapsulated secret");

            let secret = $decapsulate(&dk, &ct);
            assert_eq!(secret.as_ref(), &v.k[..], "decapsulated secret");
        }

        #[test]
        fn $t_exchange() {
            for i in 0..3u8 {
                let (ek, dk) = $keypair(&[i; 32], &[i.wrapping_add(0x40); 32]);
                let (ct, sender) = $encapsulate(&ek, &[i.wrapping_add(0x80); 32]);
                let receiver = $decapsulate(&dk, &ct);
                assert_eq!(sender.as_ref(), receiver.as_ref());
                assert!((&sender).ct_eq(&receiver).is_true());

                // the encapsulation key embedded in the decapsulation key is the
                // one key generation returned
                assert_eq!(dk.encapsulation_key().as_ref(), ek.as_ref());

                // tampering with the ciphertext triggers the implicit rejection:
                // decapsulation succeeds but returns J(z || c) instead
                let mut tampered = <[u8; $ct::LENGTH]>::try_from(ct.as_ref()).unwrap();
                tampered[3 * i as usize] ^= 1 << i;
                let rejected = $decapsulate(&dk, &$ct::from(tampered));
                assert_ne!(rejected.as_ref(), sender.as_ref());
                assert!((&sender).ct_ne(&rejected).is_true());

                let z = &dk.as_ref()[$dk::LENGTH - 32..];
                let expected: [u8; 32] = Shake256::new().update(z).update(&tampered).finalize();
                assert_eq!(rejected.as_ref(), &expected[..]);

                let bytes: [u8; SHARED_SECRET_LENGTH] = receiver.into();
                assert_eq!(&bytes[..], sender.as_ref());
            }
        }

        #[test]
        fn $t_input_checks() {
            let (ek, dk) = $keypair(&[5u8; 32], &[6u8; 32]);
            let mut ek_bytes = <[u8; $ek::LENGTH]>::try_from(ek.as_ref()).unwrap();
            let mut dk_bytes = <[u8; $dk::LENGTH]>::try_from(dk.as_ref()).unwrap();

            assert!($ek::from_bytes(ek_bytes).is_ok());
            assert!($dk::from_bytes(dk_bytes).is_ok());
            assert!($ek::try_from(&ek_bytes[..]).is_ok());
            assert!($dk::try_from(&dk_bytes[..]).is_ok());

            // a ciphertext is only ever checked for its length
            let ct_bytes = [0u8; $ct::LENGTH];
            assert!($ct::try_from(&ct_bytes[..]).is_ok());

            for short in [
                $ek::try_from(&ek_bytes[..$ek::LENGTH - 1]).err(),
                $dk::try_from(&dk_bytes[..$dk::LENGTH - 1]).err(),
                $ct::try_from(&ct_bytes[..$ct::LENGTH - 1]).err(),
            ] {
                assert_eq!(short, Some(Error::InvalidLength));
            }

            // 3329 = 0xd01 is the smallest value the 12 bits encoding can hold
            // that is not a canonical residue
            ek_bytes[0] = 0x01;
            ek_bytes[1] = (ek_bytes[1] & 0xf0) | 0x0d;
            assert_eq!($ek::from_bytes(ek_bytes).err(), Some(Error::InvalidModulus));

            // the embedded H(ek) sits right before the 32 trailing bytes of z
            dk_bytes[$dk::LENGTH - 33] ^= 1;
            assert_eq!($dk::from_bytes(dk_bytes).err(), Some(Error::InvalidHash));
        }
    };
}

parameter_set_tests!(
    EncapsulationKey512,
    DecapsulationKey512,
    Ciphertext512,
    keypair512,
    encapsulate512,
    decapsulate512,
    KEYGEN_512,
    ENCAP_512,
    keygen_512,
    encap_512,
    exchange_512,
    input_checks_512
);

parameter_set_tests!(
    EncapsulationKey768,
    DecapsulationKey768,
    Ciphertext768,
    keypair768,
    encapsulate768,
    decapsulate768,
    KEYGEN_768,
    ENCAP_768,
    keygen_768,
    encap_768,
    exchange_768,
    input_checks_768
);

parameter_set_tests!(
    EncapsulationKey1024,
    DecapsulationKey1024,
    Ciphertext1024,
    keypair1024,
    encapsulate1024,
    decapsulate1024,
    KEYGEN_1024,
    ENCAP_1024,
    keygen_1024,
    encap_1024,
    exchange_1024,
    input_checks_1024
);

// A ciphertext that the ACVP vectors modified after encapsulation: decapsulation
// must return the implicit rejection secret rather than fail.
#[test]
fn decap_modified_ciphertext_768() {
    let v = &DECAP_REJECT_768;
    let dk = DecapsulationKey768::from_bytes(v.dk).unwrap();
    let ct = Ciphertext768::from(v.c);
    assert_eq!(decapsulate768(&dk, &ct).as_ref(), &v.k[..]);
}

// The three parameter sets must not agree on anything: the seed of key
// generation is domain separated by k.
#[test]
fn parameter_sets_are_separated() {
    // the trailing rho of each key comes from the same seed through a different
    // domain separator
    fn rho(ek: &[u8]) -> &[u8] {
        &ek[ek.len() - 32..]
    }

    let (ek512, _) = keypair512(&[1u8; 32], &[2u8; 32]);
    let (ek768, _) = keypair768(&[1u8; 32], &[2u8; 32]);
    let (ek1024, _) = keypair1024(&[1u8; 32], &[2u8; 32]);

    assert_ne!(rho(ek512.as_ref()), rho(ek768.as_ref()));
    assert_ne!(rho(ek768.as_ref()), rho(ek1024.as_ref()));
}
