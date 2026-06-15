use hmac::{Mac, SimpleHmac};
use sha3::Digest;

pub mod aes;
pub mod cwt;
pub mod ecdh;
pub mod ed25519;
pub mod encrypt0;
pub mod k256;
pub mod kdf;
pub mod sign1;

pub use cose2::{iana, Key as CoseKey, Label, Value};

/// Compatibility trait for the COSE types this crate exposes.
///
/// `cose2` provides inherent `from_slice`/`to_vec` methods on its message and
/// key types. Keeping this trait avoids forcing downstream code to import a
/// serialization trait while using `cose2` as the backing implementation.
pub trait CborSerializable: Sized {
    fn from_slice(data: &[u8]) -> Result<Self, cose2::Error>;
    fn to_vec(&self) -> Result<Vec<u8>, cose2::Error>;
}

macro_rules! impl_cbor_serializable {
    ($ty:ty) => {
        impl CborSerializable for $ty {
            fn from_slice(data: &[u8]) -> Result<Self, cose2::Error> {
                <$ty>::from_slice(data)
            }

            fn to_vec(&self) -> Result<Vec<u8>, cose2::Error> {
                <$ty>::to_vec(self)
            }
        }
    };
}

impl_cbor_serializable!(cose2::Key);
impl_cbor_serializable!(cose2::Sign1Message);
impl_cbor_serializable!(cose2::Encrypt0Message);
impl_cbor_serializable!(cose2::KdfContext);
impl_cbor_serializable!(cose2::cwt::Claims);

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
        SimpleHmac::<sha3::Sha3_256>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn skip_prefix<'a>(tag: &[u8], data: &'a [u8]) -> &'a [u8] {
    if data.starts_with(tag) {
        &data[tag.len()..]
    } else {
        data
    }
}

pub fn cose_aes256_key(secret: [u8; 32], key_id: Vec<u8>) -> CoseKey {
    let mut key = CoseKey::new();
    key.set_kty(iana::KeyTypeSymmetric)
        .set_alg(iana::AlgorithmA256GCM)
        .set_kid(key_id);
    key.insert(iana::SymmetricKeyParameterK, secret.to_vec());
    key
}

pub fn get_cose_key_secret(key: CoseKey) -> Result<Vec<u8>, String> {
    let key_label = match key.kty().map_err(format_error)? {
        Some(Label::Int(iana::KeyTypeSymmetric)) => iana::SymmetricKeyParameterK,
        Some(Label::Int(iana::KeyTypeOKP)) => iana::OKPKeyParameterD,
        Some(Label::Int(iana::KeyTypeEC2)) => iana::EC2KeyParameterD,
        _ => {
            return Err("unsupported key type".to_string());
        }
    };

    match key
        .get_bytes(key_label)
        .map_err(|_| "invalid secret key".to_string())?
    {
        Some(value) => Ok(value.to_vec()),
        None => Err("missing secret key".to_string()),
    }
}

pub fn get_cose_key_public(key: CoseKey) -> Result<Vec<u8>, String> {
    let key_label = match key.kty().map_err(format_error)? {
        Some(Label::Int(iana::KeyTypeOKP)) => iana::OKPKeyParameterX,
        Some(Label::Int(iana::KeyTypeEC2)) => iana::EC2KeyParameterX,
        _ => {
            return Err("unsupported key type".to_string());
        }
    };

    match key
        .get_bytes(key_label)
        .map_err(|_| "invalid public key".to_string())?
    {
        Some(value) => Ok(value.to_vec()),
        None => Err("missing public key".to_string()),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn symmetric_key(secret: Vec<u8>) -> CoseKey {
        let mut key = CoseKey::new();
        key.set_kty(iana::KeyTypeSymmetric);
        key.insert(iana::SymmetricKeyParameterK, secret);
        key
    }

    fn okp_key() -> CoseKey {
        let mut key = CoseKey::new();
        key.set_kty(iana::KeyTypeOKP);
        key
    }

    fn ec2_key(x: Vec<u8>, y: Vec<u8>, d: Option<Vec<u8>>) -> CoseKey {
        let mut key = CoseKey::new();
        key.set_kty(iana::KeyTypeEC2);
        key.insert(iana::EC2KeyParameterCrv, iana::EllipticCurveP_256);
        key.insert(iana::EC2KeyParameterX, x);
        key.insert(iana::EC2KeyParameterY, y);
        if let Some(d) = d {
            key.insert(iana::EC2KeyParameterD, d);
        }
        key
    }

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

        assert_eq!(key.kty().unwrap(), Some(Label::Int(iana::KeyTypeSymmetric)));
        assert_eq!(key.kid().unwrap(), Some(key_id.as_slice()));
        assert_eq!(key.alg().unwrap(), Some(Label::Int(iana::AlgorithmA256GCM)));
    }

    #[test]
    fn get_cose_key_secret_works() {
        let secret = vec![1u8; 32];
        let key = symmetric_key(secret.clone());
        assert_eq!(get_cose_key_secret(key).unwrap(), secret);

        let mut okp = okp_key();
        okp.insert(iana::OKPKeyParameterD, Value::Bytes(vec![9, 8, 7]));
        assert_eq!(get_cose_key_secret(okp).unwrap(), vec![9, 8, 7]);

        let ec2 = ec2_key(vec![2u8; 32], vec![3u8; 32], Some(vec![4u8; 32]));
        assert_eq!(get_cose_key_secret(ec2).unwrap(), vec![4u8; 32]);
    }

    #[test]
    fn get_cose_key_secret_errors() {
        let mut unsupported = CoseKey::new();
        unsupported.set_kty(iana::KeyTypeRSA);
        assert_eq!(
            get_cose_key_secret(unsupported).unwrap_err(),
            "unsupported key type"
        );

        let missing = okp_key();
        assert_eq!(
            get_cose_key_secret(missing).unwrap_err(),
            "missing secret key"
        );

        let mut invalid = okp_key();
        invalid.insert(iana::OKPKeyParameterD, Value::Bool(true));
        assert_eq!(
            get_cose_key_secret(invalid).unwrap_err(),
            "invalid secret key"
        );
    }

    #[test]
    fn get_cose_key_public_works() {
        let mut okp = okp_key();
        okp.insert(iana::OKPKeyParameterX, Value::Bytes(vec![1, 2, 3]));
        assert_eq!(get_cose_key_public(okp).unwrap(), vec![1, 2, 3]);

        let ec2 = ec2_key(vec![2u8; 32], vec![3u8; 32], None);
        assert_eq!(get_cose_key_public(ec2).unwrap(), vec![2u8; 32]);
    }

    #[test]
    fn get_cose_key_public_errors() {
        let unsupported = symmetric_key(vec![1, 2, 3]);
        assert_eq!(
            get_cose_key_public(unsupported).unwrap_err(),
            "unsupported key type"
        );

        let missing = okp_key();
        assert_eq!(
            get_cose_key_public(missing).unwrap_err(),
            "missing public key"
        );

        let mut invalid = okp_key();
        invalid.insert(iana::OKPKeyParameterX, Value::Bool(false));
        assert_eq!(
            get_cose_key_public(invalid).unwrap_err(),
            "invalid public key"
        );
    }
}
