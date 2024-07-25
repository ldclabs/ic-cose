use ic_cose_types::{
    cose::{
        cose_aes256_key, ecdh::ecdh_x25519, encrypt0::cose_encrypt0, format_error, mac3_256,
        CborSerializable,
    },
    types::{CosePath, ECDHInput, ECDHOutput, PublicKeyInput, PublicKeyOutput, SignInput},
    validate_key, MILLISECONDS,
};
use serde_bytes::ByteBuf;

use crate::{is_authenticated, rand_bytes, store};

#[ic_cdk::query]
fn ecdsa_public_key(input: Option<PublicKeyInput>) -> Result<PublicKeyOutput, String> {
    let caller = ic_cdk::caller();
    match input {
        Some(input) => store::ns::ecdsa_public_key(&caller, input.ns, input.derivation_path),
        None => store::state::with(|s| {
            s.ecdsa_public_key
                .as_ref()
                .map(|k| PublicKeyOutput {
                    public_key: ByteBuf::from(k.public_key.clone()),
                    chain_code: ByteBuf::from(k.chain_code.clone()),
                })
                .ok_or_else(|| "failed to retrieve ECDSA public key".to_string())
        }),
    }
}

#[ic_cdk::update(guard = "is_authenticated")]
async fn ecdsa_sign(input: SignInput) -> Result<ByteBuf, String> {
    let caller = ic_cdk::caller();
    store::ns::ecdsa_sign(&caller, input.ns, input.derivation_path, input.message).await
}

#[ic_cdk::query]
fn schnorr_public_key(
    _algorithm: String,
    _input: Option<PublicKeyInput>,
) -> Result<PublicKeyOutput, String> {
    Err("not implemented".to_string())
}

#[ic_cdk::update(guard = "is_authenticated")]
async fn schnorr_sign(_algorithm: String, _input: SignInput) -> Result<ByteBuf, String> {
    Err("not implemented".to_string())
}

#[ic_cdk::update(guard = "is_authenticated")]
async fn sign_identity(
    namespace: String,
    audience: String,
    _algorithm: Option<String>,
) -> Result<ByteBuf, String> {
    validate_key(&namespace)?;
    let caller = ic_cdk::caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::ecdsa_sign_identity(&caller, namespace, audience, now_ms).await
}

#[ic_cdk::update(guard = "is_authenticated")]
async fn ecdh_encrypted_cose_key(
    path: CosePath,
    ecdh: ECDHInput,
) -> Result<ECDHOutput<ByteBuf>, String> {
    path.validate()?;
    let partial_key = ecdh.partial_key.ok_or("missing partial key")?;

    let caller = ic_cdk::caller();
    let spk = store::SettingPathKey::from_path(path.into(), caller);
    let iv = store::ns::with(&spk.0, |ns| {
        if !ns.has_setting_kek_permission(&caller, &spk) {
            Err("no permission".to_string())?;
        }
        Ok(ns.iv.to_vec())
    })?;

    let aad = spk.2.as_slice();
    let kek = store::ns::inner_ecdsa_setting_kek(&spk, &iv, partial_key.as_ref()).await?;
    let kek = cose_aes256_key(kek);
    let kek = kek.to_vec().map_err(format_error)?;

    let secret_key = rand_bytes().await;
    let secret_key = mac3_256(&secret_key, ecdh.nonce.as_ref());
    let (shared_secret, public_key) = ecdh_x25519(secret_key, *ecdh.public_key);
    let key = cose_encrypt0(&kek, shared_secret.as_bytes(), aad, *ecdh.nonce)?;
    Ok(ECDHOutput {
        payload: key,
        public_key: public_key.to_bytes().into(),
    })
}
