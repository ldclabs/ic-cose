use ic_cdk::api::management_canister::ecdsa;
use ic_cose_types::{format_error, types::PublicKeyOutput};
use ic_crypto_extended_bip32::{DerivationIndex, DerivationPath, ExtendedBip32DerivationOutput};
use serde_bytes::ByteBuf;

/// Returns a valid extended BIP-32 derivation path from an Account (Principal + subaccount)
pub fn derive_public_key(
    ecdsa_public_key: &PublicKeyOutput,
    derivation_path: Vec<Vec<u8>>,
) -> Result<PublicKeyOutput, String> {
    let ExtendedBip32DerivationOutput {
        derived_public_key,
        derived_chain_code,
    } = DerivationPath::new(derivation_path.into_iter().map(DerivationIndex).collect())
        .public_key_derivation(&ecdsa_public_key.public_key, &ecdsa_public_key.chain_code)
        .map_err(format_error)?;
    Ok(PublicKeyOutput {
        public_key: ByteBuf::from(derived_public_key),
        chain_code: ByteBuf::from(derived_chain_code),
    })
}

pub async fn sign_with_ecdsa(
    key_name: String,
    derivation_path: Vec<Vec<u8>>,
    message_hash: Vec<u8>,
) -> Result<Vec<u8>, String> {
    if message_hash.len() != 32 {
        return Err("message must be 32 bytes".to_string());
    }

    let args = ecdsa::SignWithEcdsaArgument {
        message_hash,
        derivation_path,
        key_id: ecdsa::EcdsaKeyId {
            curve: ecdsa::EcdsaCurve::Secp256k1,
            name: key_name,
        },
    };

    let (response,): (ecdsa::SignWithEcdsaResponse,) = ecdsa::sign_with_ecdsa(args)
        .await
        .map_err(|err| format!("sign_with_ecdsa failed {:?}", err))?;

    Ok(response.signature)
}

pub async fn ecdsa_public_key(
    key_name: String,
    derivation_path: Vec<Vec<u8>>,
) -> Result<PublicKeyOutput, String> {
    let args = ecdsa::EcdsaPublicKeyArgument {
        canister_id: None,
        derivation_path,
        key_id: ecdsa::EcdsaKeyId {
            curve: ecdsa::EcdsaCurve::Secp256k1,
            name: key_name,
        },
    };

    let (response,): (ecdsa::EcdsaPublicKeyResponse,) = ecdsa::ecdsa_public_key(args)
        .await
        .map_err(|err| format!("ecdsa_public_key failed {:?}", err))?;

    Ok(PublicKeyOutput {
        public_key: ByteBuf::from(response.public_key),
        chain_code: ByteBuf::from(response.chain_code),
    })
}
