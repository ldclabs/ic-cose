use coset::{iana, Algorithm, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder};

use super::{ecdsa, ed25519};

pub use iana::Algorithm::{EdDSA, ES256K};
const ALG_ED25519: Algorithm = Algorithm::Assigned(EdDSA);
const ALG_SECP256K1: Algorithm = Algorithm::Assigned(ES256K);

/// algorithm: EdDSA | ES256K
pub fn cose_sign1(
    payload: Vec<u8>,
    alg: iana::Algorithm,
    key_id: Option<Vec<u8>>,
) -> Result<CoseSign1, String> {
    let mut protected = HeaderBuilder::new().algorithm(alg);
    if let Some(key_id) = key_id {
        protected = protected.key_id(key_id);
    }

    Ok(CoseSign1Builder::new()
        .protected(protected.build())
        .payload(payload)
        .build())
}

pub fn cose_sign1_from(
    sign1_bytes: &[u8],
    aad: &[u8],
    secp256k1_pub_keys: &[ecdsa::VerifyingKey],
    ed25519_pub_keys: &[ed25519::VerifyingKey],
) -> Result<CoseSign1, String> {
    let cs1 = CoseSign1::from_slice(sign1_bytes)
        .map_err(|err| format!("invalid COSE sign1 token: {}", err))?;

    match &cs1.protected.header.alg {
        Some(ALG_SECP256K1) if !secp256k1_pub_keys.is_empty() => {
            // let secp256k1_pub_keys: Vec<ecdsa::VerifyingKey> = secp256k1_pub_keys
            //     .iter()
            //     .map(|key| ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(format_error))
            //     .collect::<Result<_, _>>()?;

            ecdsa::secp256k1_verify_any(secp256k1_pub_keys, &cs1.tbs_data(aad), &cs1.signature)?;
        }
        Some(ALG_ED25519) if !ed25519_pub_keys.is_empty() => {
            // let ed25519_pub_keys: Vec<ed25519::VerifyingKey> = ed25519_pub_keys
            //     .iter()
            //     .map(|key| ed25519::VerifyingKey::from_bytes(key).map_err(format_error))
            //     .collect::<Result<_, _>>()?;

            ed25519::ed25519_verify_any(ed25519_pub_keys, &cs1.tbs_data(aad), &cs1.signature)?;
        }
        alg => {
            Err(format!("unsupported algorithm: {:?}", alg))?;
        }
    }
    Ok(cs1)
}
