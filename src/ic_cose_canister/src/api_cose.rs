use ic_cose_types::{
    cose::{
        cose_aes256_key, ecdh::ecdh_x25519, encrypt0::cose_encrypt0, format_error, mac3_256,
        CborSerializable,
    },
    types::{
        CosePath, ECDHInput, ECDHOutput, PublicKeyInput, PublicKeyOutput, SchnorrAlgorithm,
        SignIdentityInput, SignInput,
    },
    validate_key, MILLISECONDS,
};
use serde_bytes::{ByteArray, ByteBuf};

use crate::{is_authenticated, rand_bytes, store};

#[ic_cdk::query]
fn ecdsa_public_key(input: Option<PublicKeyInput>) -> Result<PublicKeyOutput, String> {
    let caller = ic_cdk::caller();
    match input {
        Some(input) => store::ns::ecdsa_public_key(&caller, input.ns, input.derivation_path),
        None => store::state::with(|s| {
            s.ecdsa_public_key
                .as_ref()
                .cloned()
                .ok_or_else(|| "failed to retrieve ECDSA public key".to_string())
        }),
    }
}

#[ic_cdk::update(guard = "is_authenticated")]
async fn ecdsa_sign(input: SignInput) -> Result<ByteBuf, String> {
    let caller = ic_cdk::caller();
    store::ns::ecdsa_sign_with(&caller, input.ns, input.derivation_path, input.message).await
}

#[ic_cdk::query]
fn schnorr_public_key(
    algorithm: SchnorrAlgorithm,
    input: Option<PublicKeyInput>,
) -> Result<PublicKeyOutput, String> {
    let caller = ic_cdk::caller();
    match input {
        Some(input) => {
            store::ns::schnorr_public_key(&caller, algorithm, input.ns, input.derivation_path)
        }
        None => store::state::with(|s| match algorithm {
            SchnorrAlgorithm::Bip340Secp256k1 => s
                .schnorr_secp256k1_public_key
                .as_ref()
                .cloned()
                .ok_or_else(|| "failed to retrieve schnorr secp256k1 public key".to_string()),
            SchnorrAlgorithm::Ed25519 => s
                .schnorr_ed25519_public_key
                .as_ref()
                .cloned()
                .ok_or_else(|| "failed to retrieve schnorr ed25519 public key".to_string()),
        }),
    }
}

#[ic_cdk::update(guard = "is_authenticated")]
async fn schnorr_sign(algorithm: SchnorrAlgorithm, input: SignInput) -> Result<ByteBuf, String> {
    let caller = ic_cdk::caller();
    store::ns::schnorr_sign_with(
        &caller,
        algorithm,
        input.ns,
        input.derivation_path,
        input.message,
    )
    .await
}

#[ic_cdk::update(guard = "is_authenticated")]
async fn schnorr_sign_identity(
    algorithm: SchnorrAlgorithm,
    input: SignIdentityInput,
) -> Result<ByteBuf, String> {
    validate_key(&input.ns)?;

    let caller = ic_cdk::caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::sign_identity(&caller, input.ns, input.audience, now_ms, algorithm).await
}

/// ecdh_encrypted_cose_key returns a permanent partial KEK encrypted with ECDH.
/// It should be used with a local partial key to derive a full KEK.
#[ic_cdk::update(guard = "is_authenticated")]
async fn ecdh_cose_encrypted_key(
    path: CosePath,
    ecdh: ECDHInput,
) -> Result<ECDHOutput<ByteBuf>, String> {
    path.validate()?;

    let caller = ic_cdk::caller();
    let key_id = path.key_id.clone();
    let spk = store::SettingPathKey::from_path(path.into(), caller);
    store::ns::with(&spk.0, |ns| {
        if !ns.has_setting_kek_permission(&caller, &spk) {
            Err("no permission".to_string())?;
        }
        Ok(())
    })?;

    let aad = spk.2.as_slice();
    let kek = store::ns::inner_schnorr_kek(&spk, &key_id).await?;
    let kek = cose_aes256_key(kek, key_id.into_vec());
    let kek = kek.to_vec().map_err(format_error)?;

    let secret_key: [u8; 32] = rand_bytes().await?;
    let secret_key = mac3_256(&secret_key, ecdh.nonce.as_ref());
    let (shared_secret, public_key) = ecdh_x25519(secret_key, *ecdh.public_key);
    let key = cose_encrypt0(&kek, shared_secret.as_bytes(), aad, *ecdh.nonce, None)?;
    Ok(ECDHOutput {
        payload: key,
        public_key: public_key.to_bytes().into(),
    })
}

#[ic_cdk::update(guard = "is_authenticated")]
async fn vetkd_public_key(path: CosePath) -> Result<ByteBuf, String> {
    path.validate()?;

    let caller = ic_cdk::caller();
    let spk = store::SettingPathKey::from_path(path.into(), caller);
    store::ns::with(&spk.0, |ns| {
        if !ns.has_setting_kek_permission(&caller, &spk) {
            Err("no permission".to_string())?;
        }
        Ok(())
    })?;

    let pk = store::ns::inner_vetkd_public_key(&spk).await?;
    Ok(ByteBuf::from(pk))
}

#[ic_cdk::update(guard = "is_authenticated")]
async fn vetkd_encrypted_key(path: CosePath, public_key: ByteArray<48>) -> Result<ByteBuf, String> {
    path.validate()?;

    let caller = ic_cdk::caller();
    let key_id = path.key_id.clone();
    let spk = store::SettingPathKey::from_path(path.into(), caller);
    store::ns::with(&spk.0, |ns| {
        if !ns.has_setting_kek_permission(&caller, &spk) {
            Err("no permission".to_string())?;
        }
        Ok(())
    })?;

    let ek = store::ns::inner_vetkd_encrypted_key(
        &spk,
        key_id.into_vec(),
        public_key.into_array().into(),
    )
    .await?;
    Ok(ByteBuf::from(ek))
}
