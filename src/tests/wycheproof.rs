use crate::{
    aes_gcm::{AesGcm128, AesGcm256, DecryptionResult, Tag},
    chacha20poly1305::ChaCha20Poly1305,
    hmac::Algorithm,
};
use serde_json::Value;
use std::vec::Vec;

type CaseTest = fn(&str, usize, &Value, &Value) -> bool;
const CASES_PER_GROUP: usize = 1;

fn run_file(file: &str, source: &str, check: CaseTest, per_group_limit: Option<usize>) {
    let document: Value = serde_json::from_str(source).unwrap();
    let groups = document["testGroups"].as_array().unwrap();
    let mut covered = 0;
    let mut skipped = 0;
    let mut visited = 0;

    for (group_index, group) in groups.iter().enumerate() {
        let tests = group["tests"].as_array().unwrap();
        for test in tests.iter().take(per_group_limit.unwrap_or(tests.len())) {
            visited += 1;
            if check(file, group_index, group, test) {
                covered += 1;
            } else {
                skipped += 1;
            }
        }
    }

    assert_eq!(
        covered + skipped,
        visited,
        "{file}: case accounting mismatch"
    );
    let total = document["numberOfTests"].as_u64().unwrap() as usize;
    if per_group_limit.is_none() {
        assert_eq!(visited, total, "{file}: not every test vector was visited");
    }
    println!("{file}: {covered} cases covered, {skipped} skipped ({visited}/{total} visited)");
}

fn skip_case(file: &str, group: usize, test: &Value, reason: &str) {
    println!("skip {file} group {group} tcId {}: {reason}", test["tcId"]);
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex string has an odd length");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(digits, 16).unwrap()
        })
        .collect()
}

fn bytes(value: &Value, field: &str) -> Vec<u8> {
    decode_hex(
        value
            .get(field)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing string field {field}")),
    )
}

fn optional_bytes(value: &Value, field: &str) -> Vec<u8> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(decode_hex)
        .unwrap_or_default()
}

fn assert_result(file: &str, group: usize, test: &Value, actual: bool) {
    match test["result"].as_str().unwrap() {
        "valid" => assert!(
            actual,
            "{file} group {group} tcId {} should be valid",
            test["tcId"]
        ),
        "invalid" => assert!(
            !actual,
            "{file} group {group} tcId {} should be invalid",
            test["tcId"]
        ),
        "acceptable" => {}
        result => panic!("unexpected Wycheproof result {result}"),
    }
}

fn check_aes_gcm(file: &str, group: usize, _: &Value, test: &Value) -> bool {
    let key = bytes(test, "key");
    let nonce = bytes(test, "iv");
    let tag = bytes(test, "tag");
    if key.len() != 16 && key.len() != 32 {
        skip_case(
            file,
            group,
            test,
            "AES-GCM API supports AES-128 and AES-256 keys",
        );
        return false;
    }
    if nonce.len() != 12 {
        skip_case(file, group, test, "AES-GCM API requires a 96-bit nonce");
        return false;
    }
    if tag.len() != 16 {
        skip_case(file, group, test, "AES-GCM API requires a 128-bit tag");
        return false;
    }

    let nonce: [u8; 12] = nonce.try_into().unwrap();
    let tag = Tag(tag.try_into().unwrap());
    let aad = optional_bytes(test, "aad");
    let ciphertext = bytes(test, "ct");
    let mut plaintext = vec![0; ciphertext.len()];
    let result = if key.len() == 16 {
        AesGcm128::new(&key.as_slice().try_into().unwrap()).decrypt(
            &nonce,
            &aad,
            &ciphertext,
            &mut plaintext,
            &tag,
        )
    } else {
        AesGcm256::new(&key.as_slice().try_into().unwrap()).decrypt(
            &nonce,
            &aad,
            &ciphertext,
            &mut plaintext,
            &tag,
        )
    };
    let actual = result == DecryptionResult::Match;
    if actual {
        assert_eq!(
            plaintext,
            bytes(test, "msg"),
            "{file} group {group} tcId {} plaintext mismatch",
            test["tcId"]
        );
    }
    assert_result(file, group, test, actual);
    true
}

fn check_aes_gmac(file: &str, group: usize, _: &Value, test: &Value) -> bool {
    let key = bytes(test, "key");
    let nonce = bytes(test, "iv");
    let tag = bytes(test, "tag");
    if key.len() != 16 && key.len() != 32 {
        skip_case(
            file,
            group,
            test,
            "AES-GCM API supports AES-128 and AES-256 keys",
        );
        return false;
    }
    if nonce.len() != 12 {
        skip_case(file, group, test, "AES-GCM API requires a 96-bit nonce");
        return false;
    }
    if tag.len() != 16 {
        skip_case(file, group, test, "AES-GCM API requires a 128-bit tag");
        return false;
    }

    let nonce: [u8; 12] = nonce.try_into().unwrap();
    let tag = Tag(tag.try_into().unwrap());
    let aad = bytes(test, "msg");
    let mut plaintext = [];
    let result = if key.len() == 16 {
        AesGcm128::new(&key.as_slice().try_into().unwrap()).decrypt(
            &nonce,
            &aad,
            &[],
            &mut plaintext,
            &tag,
        )
    } else {
        AesGcm256::new(&key.as_slice().try_into().unwrap()).decrypt(
            &nonce,
            &aad,
            &[],
            &mut plaintext,
            &tag,
        )
    };
    assert_result(file, group, test, result == DecryptionResult::Match);
    true
}

fn check_chacha20_poly1305(file: &str, group: usize, _: &Value, test: &Value) -> bool {
    let key = bytes(test, "key");
    let nonce = bytes(test, "iv");
    let tag = bytes(test, "tag");
    if key.len() != 32 {
        skip_case(
            file,
            group,
            test,
            "ChaCha20-Poly1305 API requires a 256-bit key",
        );
        return false;
    }
    if nonce.len() != 12 || tag.len() != 16 {
        skip_case(
            file,
            group,
            test,
            "ChaCha20-Poly1305 API requires a 96-bit nonce and a 128-bit tag",
        );
        return false;
    }

    let nonce: [u8; 12] = nonce.try_into().unwrap();
    let aad = optional_bytes(test, "aad");
    let ciphertext = bytes(test, "ct");
    let mut plaintext = vec![0; ciphertext.len()];
    let mut cipher = ChaCha20Poly1305::new(&key, &nonce, &aad);
    let actual = cipher.decrypt(&ciphertext, &mut plaintext, &tag);
    if actual {
        assert_eq!(
            plaintext,
            bytes(test, "msg"),
            "{file} group {group} tcId {} plaintext mismatch",
            test["tcId"]
        );
    }
    assert_result(file, group, test, actual);
    true
}

fn check_ed25519(file: &str, group: usize, group_data: &Value, test: &Value) -> bool {
    let public_key = bytes(&group_data["publicKey"], "pk");
    let signature = bytes(test, "sig");
    if public_key.len() != 32 || signature.len() != 64 {
        skip_case(
            file,
            group,
            test,
            "Ed25519 verify API requires a 32-byte key and a 64-byte signature",
        );
        return false;
    }

    let public_key: [u8; 32] = public_key.try_into().unwrap();
    let signature: [u8; 64] = signature.try_into().unwrap();
    let actual = crate::ed25519::verify(&bytes(test, "msg"), &public_key, &signature);
    assert_result(file, group, test, actual);
    true
}

fn check_hmac<D: Algorithm>(file: &str, group: usize, test: &Value) -> bool {
    let key = bytes(test, "key");
    let message = bytes(test, "msg");
    let tag = bytes(test, "tag");
    let mut actual = vec![0; D::OUTPUT_SIZE];
    let mut context = crate::hmac::Context::<D>::new(&key);
    context.update(&message);
    context.finalize_at(&mut actual);
    let matches = actual
        .get(..tag.len())
        .map(|computed| computed == tag.as_slice())
        .unwrap_or(false);
    assert_result(file, group, test, matches);
    true
}

fn check_hkdf<D: Algorithm>(file: &str, group: usize, test: &Value) -> bool {
    let size = test["size"].as_u64().unwrap() as usize;
    if size > 255 * D::OUTPUT_SIZE {
        skip_case(
            file,
            group,
            test,
            "HKDF expand API panics above the RFC output limit",
        );
        return false;
    }

    let salt = bytes(test, "salt");
    let ikm = bytes(test, "ikm");
    let info = bytes(test, "info");
    let mut prk = vec![0; D::OUTPUT_SIZE];
    crate::hkdf::extract::<D>(&salt, &ikm, &mut prk);
    let mut okm = vec![0; size];
    crate::hkdf::expand::<D>(&prk, &info, &mut okm);
    assert_result(file, group, test, okm == bytes(test, "okm"));
    true
}

fn check_pbkdf2<D: Algorithm>(file: &str, group: usize, test: &Value) -> bool {
    let password = bytes(test, "password");
    let salt = bytes(test, "salt");
    let iterations = test["iterationCount"].as_u64().unwrap() as u32;
    let size = test["dkLen"].as_u64().unwrap() as usize;
    let mut derived_key = vec![0; size];
    crate::pbkdf2::pbkdf2::<D>(&password, &salt, iterations, &mut derived_key);
    assert_result(file, group, test, derived_key == bytes(test, "dk"));
    true
}

macro_rules! hash_case {
    ($name:ident, $check:ident, $digest:ty) => {
        fn $name(file: &str, group: usize, _: &Value, test: &Value) -> bool {
            $check::<$digest>(file, group, test)
        }
    };
}

hash_case!(check_hmac_sha1, check_hmac, crate::hashing::sha1::Sha1);
hash_case!(check_hmac_sha224, check_hmac, crate::hashing::sha2::Sha224);
hash_case!(check_hmac_sha256, check_hmac, crate::hashing::sha2::Sha256);
hash_case!(check_hmac_sha384, check_hmac, crate::hashing::sha2::Sha384);
hash_case!(check_hmac_sha512, check_hmac, crate::hashing::sha2::Sha512);

hash_case!(check_hkdf_sha1, check_hkdf, crate::hashing::sha1::Sha1);
hash_case!(check_hkdf_sha256, check_hkdf, crate::hashing::sha2::Sha256);
hash_case!(check_hkdf_sha384, check_hkdf, crate::hashing::sha2::Sha384);
hash_case!(check_hkdf_sha512, check_hkdf, crate::hashing::sha2::Sha512);

hash_case!(check_pbkdf2_sha1, check_pbkdf2, crate::hashing::sha1::Sha1);
hash_case!(
    check_pbkdf2_sha256,
    check_pbkdf2,
    crate::hashing::sha2::Sha256
);
hash_case!(
    check_pbkdf2_sha384,
    check_pbkdf2,
    crate::hashing::sha2::Sha384
);
hash_case!(
    check_pbkdf2_sha512,
    check_pbkdf2,
    crate::hashing::sha2::Sha512
);

macro_rules! mldsa_verify_case {
    ($name:ident, $vk:ident, $sig:ident, $pk_len:literal, $sig_len:literal) => {
        fn $name(file: &str, group: usize, group_data: &Value, test: &Value) -> bool {
            let public_key = bytes(group_data, "publicKey");
            let signature = bytes(test, "sig");
            if public_key.len() != $pk_len || signature.len() != $sig_len {
                skip_case(
                    file,
                    group,
                    test,
                    "ML-DSA verify API requires fixed-size public keys and signatures",
                );
                return false;
            }

            let public_key: [u8; $pk_len] = public_key.try_into().unwrap();
            let signature: [u8; $sig_len] = signature.try_into().unwrap();
            let public_key = crate::mldsa::$vk::from_bytes(public_key);
            let signature = crate::mldsa::$sig::from_bytes(signature);
            let message = bytes(test, "msg");
            let context = optional_bytes(test, "ctx");
            assert_result(
                file,
                group,
                test,
                public_key.verify(&message, &context, &signature),
            );
            true
        }
    };
}

mldsa_verify_case!(
    check_mldsa_44_verify,
    VerifyingKey44,
    Signature44,
    1312,
    2420
);
mldsa_verify_case!(
    check_mldsa_65_verify,
    VerifyingKey65,
    Signature65,
    1952,
    3309
);
mldsa_verify_case!(
    check_mldsa_87_verify,
    VerifyingKey87,
    Signature87,
    2592,
    4627
);

macro_rules! mldsa_sign_seed_case {
    ($name:ident, $keypair:ident) => {
        fn $name(file: &str, group: usize, group_data: &Value, test: &Value) -> bool {
            if test.get("msg").and_then(Value::as_str).is_none() {
                skip_case(
                    file,
                    group,
                    test,
                    "ML-DSA signing API accepts messages, not the internal mu representative",
                );
                return false;
            }

            let seed = bytes(group_data, "privateSeed");
            if seed.len() != 32 {
                skip_case(
                    file,
                    group,
                    test,
                    "ML-DSA keypair API requires a 32-byte private seed",
                );
                return false;
            }
            let seed: [u8; 32] = seed.try_into().unwrap();
            let (public_key, signing_key) = crate::mldsa::$keypair(&seed);
            assert_eq!(
                public_key.bytes().as_slice(),
                bytes(group_data, "publicKey").as_slice(),
                "{file} group {group} generated public key mismatch"
            );

            let message = bytes(test, "msg");
            let context = optional_bytes(test, "ctx");
            let randomizer = optional_bytes(test, "rnd");
            let randomizer: [u8; 32] = if randomizer.is_empty() {
                [0; 32]
            } else {
                randomizer.try_into().unwrap()
            };
            match signing_key.sign(&message, &context, &randomizer) {
                Ok(signature) => {
                    assert_result(file, group, test, true);
                    assert_eq!(
                        signature.bytes().as_slice(),
                        bytes(test, "sig").as_slice(),
                        "{file} group {group} tcId {} signature mismatch",
                        test["tcId"]
                    );
                }
                Err(_) => assert_result(file, group, test, false),
            }
            true
        }
    };
}

mldsa_sign_seed_case!(check_mldsa_44_sign_seed, keypair44);
mldsa_sign_seed_case!(check_mldsa_65_sign_seed, keypair65);
mldsa_sign_seed_case!(check_mldsa_87_sign_seed, keypair87);

macro_rules! mlkem_case {
    ($name:ident, $ek:ident, $dk:ident, $ct:ident, $keypair:ident, $encapsulate:ident, $decapsulate:ident) => {
        fn $name(file: &str, group: usize, group_data: &Value, test: &Value) -> bool {
            match group_data["type"].as_str().unwrap() {
                "MLKEMKeyGen" => {
                    let seed = bytes(test, "seed");
                    if seed.len() != 64 {
                        skip_case(
                            file,
                            group,
                            test,
                            "ML-KEM keypair API requires two 32-byte seeds",
                        );
                        return false;
                    }
                    let d: [u8; 32] = seed[..32].try_into().unwrap();
                    let z: [u8; 32] = seed[32..].try_into().unwrap();
                    let (ek, dk) = crate::mlkem::$keypair(&d, &z);
                    assert_eq!(
                        ek.as_ref(),
                        bytes(test, "ek").as_slice(),
                        "{file} group {group} tcId {} encapsulation key mismatch",
                        test["tcId"]
                    );
                    assert_eq!(
                        dk.as_ref(),
                        bytes(test, "dk").as_slice(),
                        "{file} group {group} tcId {} decapsulation key mismatch",
                        test["tcId"]
                    );
                    true
                }
                "MLKEMEncapsTest" => {
                    let encoded_ek = bytes(test, "ek");
                    let ek = match crate::mlkem::$ek::try_from(encoded_ek.as_slice()) {
                        Ok(ek) => ek,
                        Err(_) => {
                            assert_result(file, group, test, false);
                            return true;
                        }
                    };
                    let message: [u8; 32] = bytes(test, "m").try_into().unwrap();
                    let (ciphertext, shared_secret) = crate::mlkem::$encapsulate(&ek, &message);
                    let matches = ciphertext.as_ref() == optional_bytes(test, "c").as_slice()
                        && shared_secret.as_ref() == optional_bytes(test, "K").as_slice();
                    assert_result(file, group, test, matches);
                    true
                }
                "MLKEMTest" => {
                    let seed = bytes(test, "seed");
                    if seed.len() != 64 {
                        skip_case(
                            file,
                            group,
                            test,
                            "ML-KEM keypair API requires two 32-byte seeds",
                        );
                        return false;
                    }
                    let d: [u8; 32] = seed[..32].try_into().unwrap();
                    let z: [u8; 32] = seed[32..].try_into().unwrap();
                    let (ek, dk) = crate::mlkem::$keypair(&d, &z);
                    assert_eq!(
                        ek.as_ref(),
                        bytes(test, "ek").as_slice(),
                        "{file} group {group} tcId {} encapsulation key mismatch",
                        test["tcId"]
                    );
                    let encoded_ct = bytes(test, "c");
                    let ciphertext = match crate::mlkem::$ct::try_from(encoded_ct.as_slice()) {
                        Ok(ciphertext) => ciphertext,
                        Err(_) => {
                            assert_result(file, group, test, false);
                            return true;
                        }
                    };
                    let shared_secret = crate::mlkem::$decapsulate(&dk, &ciphertext);
                    assert_eq!(
                        shared_secret.as_ref(),
                        bytes(test, "K").as_slice(),
                        "{file} group {group} tcId {} shared secret mismatch",
                        test["tcId"]
                    );
                    true
                }
                "MLKEMDecapsValidationTest" => {
                    let encoded_dk = bytes(test, "dk");
                    let dk = match crate::mlkem::$dk::try_from(encoded_dk.as_slice()) {
                        Ok(dk) => dk,
                        Err(_) => {
                            assert_result(file, group, test, false);
                            return true;
                        }
                    };
                    let encoded_ct = bytes(test, "c");
                    let ciphertext = match crate::mlkem::$ct::try_from(encoded_ct.as_slice()) {
                        Ok(ciphertext) => ciphertext,
                        Err(_) => {
                            assert_result(file, group, test, false);
                            return true;
                        }
                    };
                    assert_result(file, group, test, true);
                    assert_eq!(
                        dk.encapsulation_key().as_ref(),
                        bytes(test, "ek").as_slice(),
                        "{file} group {group} tcId {} encapsulation key mismatch",
                        test["tcId"]
                    );
                    let shared_secret = crate::mlkem::$decapsulate(&dk, &ciphertext);
                    assert_eq!(
                        shared_secret.as_ref(),
                        bytes(test, "K").as_slice(),
                        "{file} group {group} tcId {} shared secret mismatch",
                        test["tcId"]
                    );
                    true
                }
                kind => panic!("unexpected ML-KEM test type {kind}"),
            }
        }
    };
}

mlkem_case!(
    check_mlkem_512,
    EncapsulationKey512,
    DecapsulationKey512,
    Ciphertext512,
    keypair512,
    encapsulate512,
    decapsulate512
);
mlkem_case!(
    check_mlkem_768,
    EncapsulationKey768,
    DecapsulationKey768,
    Ciphertext768,
    keypair768,
    encapsulate768,
    decapsulate768
);
mlkem_case!(
    check_mlkem_1024,
    EncapsulationKey1024,
    DecapsulationKey1024,
    Ciphertext1024,
    keypair1024,
    encapsulate1024,
    decapsulate1024
);

fn check_x25519(file: &str, group: usize, _: &Value, test: &Value) -> bool {
    let private = bytes(test, "private");
    let public = bytes(test, "public");
    let secret = bytes(test, "shared");
    let private = match crate::x25519::SecretKey::try_from(private.as_slice()) {
        Ok(private) => private,
        Err(_) => {
            assert_result(file, group, test, false);
            return true;
        }
    };
    let public = match crate::x25519::PublicKey::try_from(public.as_slice()) {
        Ok(public) => public,
        Err(_) => {
            assert_result(file, group, test, false);
            return true;
        }
    };
    assert_eq!(
        crate::x25519::dh(&private, &public).as_ref(),
        secret.as_slice(),
        "{file} group {group} tcId {} shared secret mismatch",
        test["tcId"]
    );
    true
}

macro_rules! vector_tests {
    ($( $name:ident: $file:literal => $check:ident, )*) => {
        $(
            #[test]
            fn $name() {
                run_file(
                    $file,
                    include_str!(concat!("../../tests/wycheproof/testvectors_v1/", $file)),
                    $check,
                    Some(CASES_PER_GROUP),
                );
            }
        )*

        #[test]
        #[ignore = "Run all vectors with cargo test -- --ignored"]
        fn wycheproof_full_suite() {
            $(
                run_file(
                    $file,
                    include_str!(concat!("../../tests/wycheproof/testvectors_v1/", $file)),
                    $check,
                    None,
                );
            )*
        }
    };
}

vector_tests! {
    aes_gcm: "aes_gcm_test.json" => check_aes_gcm,
    aes_gmac: "aes_gmac_test.json" => check_aes_gmac,
    chacha20_poly1305: "chacha20_poly1305_test.json" => check_chacha20_poly1305,
    ed25519: "ed25519_test.json" => check_ed25519,
    hkdf_sha1: "hkdf_sha1_test.json" => check_hkdf_sha1,
    hkdf_sha256: "hkdf_sha256_test.json" => check_hkdf_sha256,
    hkdf_sha384: "hkdf_sha384_test.json" => check_hkdf_sha384,
    hkdf_sha512: "hkdf_sha512_test.json" => check_hkdf_sha512,
    hmac_sha1: "hmac_sha1_test.json" => check_hmac_sha1,
    hmac_sha224: "hmac_sha224_test.json" => check_hmac_sha224,
    hmac_sha256: "hmac_sha256_test.json" => check_hmac_sha256,
    hmac_sha384: "hmac_sha384_test.json" => check_hmac_sha384,
    hmac_sha512: "hmac_sha512_test.json" => check_hmac_sha512,
    mldsa_44_sign_seed: "mldsa_44_sign_seed_test.json" => check_mldsa_44_sign_seed,
    mldsa_44_verify: "mldsa_44_verify_test.json" => check_mldsa_44_verify,
    mldsa_65_sign_seed: "mldsa_65_sign_seed_test.json" => check_mldsa_65_sign_seed,
    mldsa_65_verify: "mldsa_65_verify_test.json" => check_mldsa_65_verify,
    mldsa_87_sign_seed: "mldsa_87_sign_seed_test.json" => check_mldsa_87_sign_seed,
    mldsa_87_verify: "mldsa_87_verify_test.json" => check_mldsa_87_verify,
    mlkem_512_encaps: "mlkem_512_encaps_test.json" => check_mlkem_512,
    mlkem_512_keygen_seed: "mlkem_512_keygen_seed_test.json" => check_mlkem_512,
    mlkem_512_semi_expanded_decaps: "mlkem_512_semi_expanded_decaps_test.json" => check_mlkem_512,
    mlkem_512: "mlkem_512_test.json" => check_mlkem_512,
    mlkem_768_encaps: "mlkem_768_encaps_test.json" => check_mlkem_768,
    mlkem_768_keygen_seed: "mlkem_768_keygen_seed_test.json" => check_mlkem_768,
    mlkem_768_semi_expanded_decaps: "mlkem_768_semi_expanded_decaps_test.json" => check_mlkem_768,
    mlkem_768: "mlkem_768_test.json" => check_mlkem_768,
    mlkem_1024_encaps: "mlkem_1024_encaps_test.json" => check_mlkem_1024,
    mlkem_1024_keygen_seed: "mlkem_1024_keygen_seed_test.json" => check_mlkem_1024,
    mlkem_1024_semi_expanded_decaps: "mlkem_1024_semi_expanded_decaps_test.json" => check_mlkem_1024,
    mlkem_1024: "mlkem_1024_test.json" => check_mlkem_1024,
    pbkdf2_hmacsha1: "pbkdf2_hmacsha1_test.json" => check_pbkdf2_sha1,
    pbkdf2_hmacsha256: "pbkdf2_hmacsha256_test.json" => check_pbkdf2_sha256,
    pbkdf2_hmacsha384: "pbkdf2_hmacsha384_test.json" => check_pbkdf2_sha384,
    pbkdf2_hmacsha512: "pbkdf2_hmacsha512_test.json" => check_pbkdf2_sha512,
    x25519: "x25519_test.json" => check_x25519,
}
