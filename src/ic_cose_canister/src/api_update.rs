use ic_cose_types::{crypto::*, setting::*, MILLISECONDS};
use serde_bytes::ByteBuf;

use crate::{rand_bytes, store};

#[ic_cdk::update]
async fn ecdsa_sign(input: SignInput) -> Result<ByteBuf, String> {
    if !store::ns::can_read(&ic_cdk::caller(), &input.namespace) {
        Err("no permission".to_string())?;
    }

    store::ns::ecdsa_sign(input.namespace, input.derivation_path, input.message).await
}

#[ic_cdk::update]
async fn schnorr_sign(_input: SignInput) -> Result<ByteBuf, String> {
    Err("not implemented".to_string())
}

#[ic_cdk::update]
async fn ecdh_public_key(path: SettingPath, ecdh: ECDHInput) -> Result<ByteBuf, String> {
    path.validate()?;
    let caller = ic_cdk::caller();
    let spk = store::SettingPathKey::from_path(path, caller);
    store::ns::get_setting_info(&caller, &spk)?;
    let (_, pk) = store::ns::ecdh_x25519_static_secret(&spk, &ecdh).await?;

    Ok(ByteBuf::from(pk.to_bytes()))
}

#[ic_cdk::update]
async fn get_setting(path: SettingPath, ecdh: Option<ECDHInput>) -> Result<SettingInfo, String> {
    path.validate()?;

    let caller = ic_cdk::caller();
    let subject = path.subject.unwrap_or(caller);
    let spk = store::SettingPathKey::from_path(path, subject);
    let (mut info, payload, dek) = store::ns::get_setting(&caller, &spk)?;

    match ecdh {
        None => {
            if dek.is_none() {
                info.payload = Some(payload);
                Ok(info)
            } else {
                Err("missing ECDH for encrypted paylod".to_string())
            }
        }
        Some(ecdh) => {
            let secret_key = rand_bytes().await;
            let secret_key = mac3_256(&secret_key, ecdh.nonce.as_ref());
            let (secret_key, public_key) = ecdh_x25519(secret_key, *ecdh.public_key);

            let kek = if dek.is_some() {
                let partial_key = ecdh.partial_key.ok_or("missing partial key")?;
                let key = store::ns::ecdsa_setting_kek(&spk, partial_key.as_ref()).await?;
                Some(key)
            } else {
                None
            };

            let payload = cose_re_encrypt(secret_key.to_bytes(), payload, kek, dek).await?;
            info.payload = Some(payload);
            info.public_key = Some(ByteBuf::from(public_key.to_bytes()));
            Ok(info)
        }
    }
}

#[ic_cdk::update]
async fn create_setting(
    path: SettingPath,
    input: CreateSettingInput,
    ecdh: Option<ECDHInput>,
) -> Result<CreateSettingOutput, String> {
    path.validate()?;
    input.validate()?;
    if input.payload.is_some() && ecdh.is_some() {
        Err("can not encrypt payload when creating setting".to_string())?;
    }

    let caller = ic_cdk::caller();
    let subject = path.subject.unwrap_or(caller);
    let spk = store::SettingPathKey::from_path(path, subject);
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    let mut output = store::ns::create_setting(&caller, &spk, input, now_ms)?;
    if let Some(ecdh) = ecdh {
        let (_, pk) = store::ns::ecdh_x25519_static_secret(&spk, &ecdh).await?;
        output.public_key = Some(pk.to_bytes().into());
    }
    Ok(output)
}

#[ic_cdk::update]
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

#[ic_cdk::update]
async fn update_setting_payload(
    path: SettingPath,
    input: UpdateSettingPayloadInput,
    ecdh: Option<ECDHInput>,
) -> Result<UpdateSettingOutput, String> {
    path.validate()?;
    input.validate()?;

    let caller = ic_cdk::caller();
    let subject = path.subject.unwrap_or(caller);
    let spk = store::SettingPathKey::from_path(path, subject);
    Err("not implemented".to_string())
}