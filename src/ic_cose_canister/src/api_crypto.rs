use ic_cose_types::{cose::*, format_error, ByteN};
use serde_bytes::ByteBuf;

use crate::store;

#[ic_cdk::update]
async fn ecdsa_sign(input: SignInput) -> Result<ByteBuf, String> {
    let caller = ic_cdk::caller();
    store::ns::ecdsa_sign(
        &caller,
        input.namespace,
        input.derivation_path,
        input.message,
    )
    .await
}

#[ic_cdk::update]
async fn schnorr_sign(_input: SignInput) -> Result<ByteBuf, String> {
    Err("not implemented".to_string())
}

#[ic_cdk::update]
async fn ecdh_public_key(path: SettingPathInput, ecdh: ECDHInput) -> Result<ByteN<32>, String> {
    path.validate()?;
    let caller = ic_cdk::caller();
    let spk = store::SettingPathKey::from_path(path.into(), caller);
    store::ns::ecdh_public_key(&caller, &spk, &ecdh).await
}

#[ic_cdk::update]
async fn ecdh_encrypted_cose_key(
    path: SettingPathInput,
    ecdh: ECDHInput,
) -> Result<ByteBuf, String> {
    path.validate()?;
    let partial_key = ecdh.partial_key.ok_or("missing partial key")?;

    let caller = ic_cdk::caller();
    let spk = store::SettingPathKey::from_path(path.into(), caller);
    store::ns::with(&spk.0, |ns| {
        if !ns.has_setting_kek_permission(&caller, &spk) {
            Err("no permission".to_string())?;
        }
        Ok(())
    })?;

    let aad = spk.2.as_slice();
    let (shared_secret, _) = store::ns::inner_ecdh_x25519_static_secret(&spk, &ecdh).await?;
    let kek = store::ns::inner_ecdsa_setting_kek(&spk, partial_key.as_ref()).await?;
    let key = cose_aes256_key(kek);
    let key = key.to_vec().map_err(format_error)?;
    cose_encrypt0(&key, shared_secret.as_bytes(), aad, *ecdh.nonce)
}
