use coset::{iana, Algorithm, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder};

use super::{ed25519, k256};

pub use iana::Algorithm::{EdDSA, ES256K};
const ALG_ED25519: Algorithm = Algorithm::Assigned(EdDSA);
const ALG_SECP256K1: Algorithm = Algorithm::Assigned(ES256K);

/// Creates a COSE_Sign1 structure with the given payload and algorithm.
///
/// # Arguments
/// * `payload` - The data to be signed/protected
/// * `alg` - The signing algorithm to use (EdDSA or ES256K)
/// * `key_id` - Optional key identifier for the signing key
///
/// # Returns
/// A CoseSign1 structure ready for signing
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

/// Verifies and parses a COSE_Sign1 structure from bytes.
///
/// # Arguments
/// * `sign1_bytes` - Raw COSE_Sign1 bytes to parse
/// * `aad` - Additional authenticated data for verification
/// * `secp256k1_pub_keys` - List of secp256k1 public keys for ECDSA verification
/// * `ed25519_pub_keys` - List of Ed25519 public keys for EdDSA verification
///
/// # Returns
/// Parsed CoseSign1 if verification succeeds with any provided key
/// Error if parsing fails or no matching key verifies the signature
pub fn cose_sign1_from(
    sign1_bytes: &[u8],
    aad: &[u8],
    secp256k1_pub_keys: &[k256::ecdsa::VerifyingKey],
    ed25519_pub_keys: &[ed25519::VerifyingKey],
) -> Result<CoseSign1, String> {
    let cs1 = CoseSign1::from_slice(sign1_bytes)
        .map_err(|err| format!("invalid COSE sign1 token: {}", err))?;

    match &cs1.protected.header.alg {
        Some(ALG_SECP256K1) if !secp256k1_pub_keys.is_empty() => {
            k256::secp256k1_verify_ecdsa_any(
                secp256k1_pub_keys,
                &cs1.tbs_data(aad),
                &cs1.signature,
            )?;
        }
        Some(ALG_ED25519) if !ed25519_pub_keys.is_empty() => {
            ed25519::ed25519_verify_any(ed25519_pub_keys, &cs1.tbs_data(aad), &cs1.signature)?;
        }
        alg => {
            Err(format!("unsupported algorithm: {:?}", alg))?;
        }
    }
    Ok(cs1)
}

#[cfg(test)]
mod test {
    use super::*;
    use candid::Principal;
    use hex::decode;

    #[test]
    fn cose_sign1_from_works() {
        // root public key
        let pk =
            decode("8fbb003d3f662fa0ea23b27681f53ef46cd5ba4ce887f569e9c60342cc766642").unwrap();
        let pk: [u8; 32] = pk.try_into().unwrap();
        let pk = ed25519::VerifyingKey::from_bytes(&pk).unwrap();
        let subject =
            Principal::from_text("i2gam-uue3y-uxwyd-mzyhb-nirhd-hz3l4-2hw3f-4fzvw-lpvvc-dqdrg-7qe")
                .unwrap();
        // from schnorr_sign_identity API
        let data = decode("8443a10127a0589ca801781b35336379672d79796161612d61616161702d61687075612d63616902783f693267616d2d75756533792d75787779642d6d7a7968622d6e697268642d687a336c342d32687733662d34667a76772d6c707676632d64716472672d3771650366746573746572041a66d11526051a66d10716061a66d10716075029420f3d16231d2de11fb7c33bbe971e096d4e616d6573706163652e2a3a5f5840bc6f9f4305a19a4a3952388cb8667e340ead39878d1ada1b671fe9b81f1c2db1c479508e5c9c20e17f5168a0587f5c049047317f4bb5c8b8f2c84e05fce6c806").unwrap();
        let res = cose_sign1_from(&data, subject.as_slice(), &[], &[pk]).unwrap();
        println!("{:?}", res);

        assert_eq!(res.payload, Some(decode("a801781b35336379672d79796161612d61616161702d61687075612d63616902783f693267616d2d75756533792d75787779642d6d7a7968622d6e697268642d687a336c342d32687733662d34667a76772d6c707676632d64716472672d3771650366746573746572041a66d11526051a66d10716061a66d10716075029420f3d16231d2de11fb7c33bbe971e096d4e616d6573706163652e2a3a5f").unwrap()));
    }
}
