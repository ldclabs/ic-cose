use ic_cose_types::{cose::*, crypto::ecdh_x25519, format_error, mac3_256};
use serde_bytes::ByteBuf;

use crate::{rand_bytes, store};

#[ic_cdk::query]
fn ecdsa_public_key(input: PublicKeyInput) -> Result<ByteBuf, String> {
    let caller = ic_cdk::caller();
    store::ns::ecdsa_public_key(&caller, input.ns, input.derivation_path)
}

#[ic_cdk::update]
async fn ecdsa_sign(input: SignInput) -> Result<ByteBuf, String> {
    let caller = ic_cdk::caller();
    store::ns::ecdsa_sign(&caller, input.ns, input.derivation_path, input.message).await
}

#[ic_cdk::query]
fn schnorr_public_key(_input: PublicKeyInput) -> Result<ByteBuf, String> {
    Err("not implemented".to_string())
}

#[ic_cdk::update]
async fn schnorr_sign(_input: SignInput) -> Result<ByteBuf, String> {
    Err("not implemented".to_string())
}

// #[ic_cdk::update]
// async fn ecdh_public_key(path: SettingPathInput, ecdh: ECDHInput) -> Result<ByteN<32>, String> {
//     path.validate()?;
//     let caller = ic_cdk::caller();
//     let spk = store::SettingPathKey::from_path(path.into(), caller);
//     store::ns::ecdh_public_key(&caller, &spk, &ecdh).await
// }

#[ic_cdk::update]
async fn ecdh_encrypted_cose_key(
    path: SettingPathInput,
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
