use coset::{CoseKeyBuilder, Label, RegisteredLabel};
use hmac::{Hmac, Mac};
use sha3::Digest;

pub mod aes;
pub mod cwt;
pub mod ecdh;
pub mod ed25519;
pub mod encrypt0;
pub mod k256;
pub mod kdf;
pub mod sign1;

pub use coset::{iana, CborSerializable, CoseKey};

pub const CBOR_TAG: [u8; 3] = [0xd9, 0xd9, 0xf7];
pub const ENCRYPT0_TAG: [u8; 1] = [0xd0];
pub const SIGN1_TAG: [u8; 1] = [0xd2];

pub fn format_error<T>(err: T) -> String
where
    T: std::fmt::Debug,
{
    format!("{:?}", err)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha3::Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha3_256_n<const N: usize>(array: [&[u8]; N]) -> [u8; 32] {
    let mut hasher = sha3::Sha3_256::new();
    for data in array {
        hasher.update(data);
    }
    hasher.finalize().into()
}

pub fn mac3_256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::KeyInit;

    let mut mac =
        Hmac::<sha3::Sha3_256>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn skip_prefix<'a>(tag: &'a [u8], data: &'a [u8]) -> &'a [u8] {
    if data.starts_with(tag) {
        &data[tag.len()..]
    } else {
        data
    }
}

pub fn cose_aes256_key(secret: [u8; 32], key_id: Vec<u8>) -> CoseKey {
    CoseKeyBuilder::new_symmetric_key(secret.into())
        .algorithm(iana::Algorithm::A256GCM)
        .key_id(key_id)
        .build()
}

pub fn get_cose_key_secret(key: CoseKey) -> Result<Vec<u8>, String> {
    let key_label = match key.kty {
        RegisteredLabel::Assigned(iana::KeyType::Symmetric) => {
            Label::Int(iana::SymmetricKeyParameter::K as i64)
        }
        RegisteredLabel::Assigned(iana::KeyType::OKP) => {
            Label::Int(iana::OkpKeyParameter::D as i64)
        }
        RegisteredLabel::Assigned(iana::KeyType::EC2) => {
            Label::Int(iana::Ec2KeyParameter::D as i64)
        }
        _ => {
            return Err("unsupported key type".to_string());
        }
    };

    for (label, value) in key.params {
        if label == key_label {
            return value
                .into_bytes()
                .map_err(|_| "invalid secret key".to_string());
        }
    }
    Err("missing secret key".to_string())
}

pub fn get_cose_key_public(key: CoseKey) -> Result<Vec<u8>, String> {
    let key_label = match key.kty {
        RegisteredLabel::Assigned(iana::KeyType::OKP) => {
            Label::Int(iana::OkpKeyParameter::X as i64)
        }
        RegisteredLabel::Assigned(iana::KeyType::EC2) => {
            Label::Int(iana::Ec2KeyParameter::X as i64)
        }
        _ => {
            return Err("unsupported key type".to_string());
        }
    };

    for (label, value) in key.params {
        if label == key_label {
            return value
                .into_bytes()
                .map_err(|_| "invalid public key".to_string());
        }
    }
    Err("missing public key".to_string())
}

#[cfg(test)]
mod test {
    use ciborium::Value;
    use coset::{Algorithm, CoseKeyBuilder};

    use super::*;

    #[test]
    fn hash_functions_work() {
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(sha3_256(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_eq!(
            hex::encode(keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
        assert_eq!(sha3_256_n([b"ab", b"c"]), sha3_256(b"abc"));
    }

    #[test]
    fn mac3_256_is_deterministic() {
        let key = b"test-key";
        let data = b"hello world";

        let mac1 = mac3_256(key, data);
        let mac2 = mac3_256(key, data);
        let mac3 = mac3_256(key, b"hello rust");

        assert_eq!(mac1, mac2);
        assert_ne!(mac1, mac3);
    }

    #[test]
    fn skip_prefix_works() {
        let data = [0xd9, 0xd9, 0xf7, 0x01, 0x02];
        assert_eq!(skip_prefix(&CBOR_TAG, &data), &[0x01, 0x02]);
        assert_eq!(skip_prefix(&SIGN1_TAG, &data), &data);
    }

    #[test]
    fn cose_aes256_key_works() {
        let secret = [7u8; 32];
        let key_id = b"kid-1".to_vec();
        let key = cose_aes256_key(secret, key_id.clone());

        assert_eq!(key.kty, RegisteredLabel::Assigned(iana::KeyType::Symmetric));
        assert_eq!(key.key_id, key_id);
        assert_eq!(key.alg, Some(Algorithm::Assigned(iana::Algorithm::A256GCM)));
    }

    #[test]
    fn get_cose_key_secret_works() {
        let secret = vec![1u8; 32];
        let key = CoseKeyBuilder::new_symmetric_key(secret.clone()).build();
        assert_eq!(get_cose_key_secret(key).unwrap(), secret);

        let mut okp = CoseKeyBuilder::new_okp_key().build();
        okp.params.push((
            Label::Int(iana::OkpKeyParameter::D as i64),
            Value::Bytes(vec![9, 8, 7]),
        ));
        assert_eq!(get_cose_key_secret(okp).unwrap(), vec![9, 8, 7]);

        let ec2 = CoseKeyBuilder::new_ec2_priv_key(
            iana::EllipticCurve::P_256,
            vec![2u8; 32],
            vec![3u8; 32],
            vec![4u8; 32],
        )
        .build();
        assert_eq!(get_cose_key_secret(ec2).unwrap(), vec![4u8; 32]);
    }

    #[test]
    fn get_cose_key_secret_errors() {
        let unsupported = CoseKeyBuilder::new_okp_key()
            .key_type(iana::KeyType::AKP)
            .build();
        assert_eq!(
            get_cose_key_secret(unsupported).unwrap_err(),
            "unsupported key type"
        );

        let missing = CoseKeyBuilder::new_okp_key().build();
        assert_eq!(
            get_cose_key_secret(missing).unwrap_err(),
            "missing secret key"
        );

        let mut invalid = CoseKeyBuilder::new_okp_key().build();
        invalid.params.push((
            Label::Int(iana::OkpKeyParameter::D as i64),
            Value::Bool(true),
        ));
        assert_eq!(
            get_cose_key_secret(invalid).unwrap_err(),
            "invalid secret key"
        );
    }

    #[test]
    fn get_cose_key_public_works() {
        let mut okp = CoseKeyBuilder::new_okp_key().build();
        okp.params.push((
            Label::Int(iana::OkpKeyParameter::X as i64),
            Value::Bytes(vec![1, 2, 3]),
        ));
        assert_eq!(get_cose_key_public(okp).unwrap(), vec![1, 2, 3]);

        let ec2 = CoseKeyBuilder::new_ec2_pub_key(
            iana::EllipticCurve::P_256,
            vec![2u8; 32],
            vec![3u8; 32],
        )
        .build();
        assert_eq!(get_cose_key_public(ec2).unwrap(), vec![2u8; 32]);
    }

    #[test]
    fn get_cose_key_public_errors() {
        let unsupported = CoseKeyBuilder::new_symmetric_key(vec![1, 2, 3]).build();
        assert_eq!(
            get_cose_key_public(unsupported).unwrap_err(),
            "unsupported key type"
        );

        let missing = CoseKeyBuilder::new_okp_key().build();
        assert_eq!(
            get_cose_key_public(missing).unwrap_err(),
            "missing public key"
        );

        let mut invalid = CoseKeyBuilder::new_okp_key().build();
        invalid.params.push((
            Label::Int(iana::OkpKeyParameter::X as i64),
            Value::Bool(false),
        ));
        assert_eq!(
            get_cose_key_public(invalid).unwrap_err(),
            "invalid public key"
        );
    }
}
