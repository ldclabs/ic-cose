use ic_cose_types::{
    cose::{
        ecdh::ecdh_x25519,
        encrypt0::{cose_decrypt0, cose_encrypt0},
        format_error, get_cose_key_secret, mac3_256, CborSerializable, CoseKey,
    },
    types::{setting::*, ECDHInput, ECDHOutput},
    OwnedRef, MILLISECONDS,
};

use crate::{is_authenticated, rand_bytes, store};

#[ic_cdk::update(guard = "is_authenticated")]
async fn ecdh_get_setting(
    path: SettingPath,
    ecdh: ECDHInput,
) -> Result<ECDHOutput<SettingInfo>, String> {
    path.validate()?;

    let caller = ic_cdk::caller();
    let subject = path.subject.unwrap_or(caller);
    let spk = store::SettingPathKey::from_path(path, subject);
    let (mut info, iv) = store::ns::get_setting(&caller, &spk)?;

    let aad = spk.2.as_slice();
    let payload = info.payload.as_ref().ok_or("missing payload")?;
    let data = match info.dek {
        None => OwnedRef::Ref(payload),
        Some(ref dek) => {
            let partial_key = ecdh.partial_key.ok_or("missing partial key")?;
            let key = store::ns::inner_ecdsa_setting_kek(&spk, &iv, partial_key.as_ref()).await?;
            let key = cose_decrypt0(dek, &key, aad)?;
            let key = CoseKey::from_slice(&key).map_err(format_error)?;
            let key = get_cose_key_secret(key)?;
            OwnedRef::Owned(cose_decrypt0(payload, &key, aad)?)
        }
    };

    let secret_key = rand_bytes().await;
    let secret_key = mac3_256(&secret_key, ecdh.nonce.as_ref());
    let (shared_secret, public_key) = ecdh_x25519(secret_key, *ecdh.public_key);
    let payload = cose_encrypt0(data.as_ref(), shared_secret.as_bytes(), aad, *ecdh.nonce)?;
    info.payload = Some(payload);
    Ok(ECDHOutput {
        payload: info,
        public_key: public_key.to_bytes().into(),
    })
}

#[ic_cdk::update(guard = "is_authenticated")]
async fn create_setting(
    path: SettingPath,
    input: CreateSettingInput,
) -> Result<CreateSettingOutput, String> {
    path.validate()?;
    input.validate()?;

    let caller = ic_cdk::caller();
    let subject = path.subject.unwrap_or(caller);
    let spk = store::SettingPathKey::from_path(path, subject);
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::create_setting(&caller, &spk, input, now_ms)
}

#[ic_cdk::update(guard = "is_authenticated")]
async fn update_setting_info(
    path: SettingPath,
    input: UpdateSettingInfoInput,
) -> Result<UpdateSettingOutput, String> {
    path.validate()?;
    input.validate()?;

    let caller = ic_cdk::caller();
    let subject = path.subject.unwrap_or(caller);
    let spk = store::SettingPathKey::from_path(path, subject);
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::update_setting_info(&caller, &spk, input, now_ms)
}

#[ic_cdk::update(guard = "is_authenticated")]
async fn update_setting_payload(
    path: SettingPath,
    input: UpdateSettingPayloadInput,
) -> Result<UpdateSettingOutput, String> {
    path.validate()?;
    input.validate()?;

    let caller = ic_cdk::caller();
    let subject = path.subject.unwrap_or(caller);
    let spk = store::SettingPathKey::from_path(path, subject);
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::update_setting_payload(&caller, &spk, input, now_ms)
}
