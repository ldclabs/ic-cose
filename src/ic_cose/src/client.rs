use candid::Principal;
use ic_agent::Agent;
use ic_cose_types::{
    cose::{
        ecdh::ecdh_x25519, encrypt0::cose_decrypt0, get_cose_key_secret, CborSerializable, CoseKey,
    },
    types::namespace::*,
    types::setting::*,
    types::{
        state::StateInfo, ECDHInput, ECDHOutput, PublicKeyInput, PublicKeyOutput, SchnorrAlgorithm,
        SettingPath, SignDelegationInput, SignDelegationOutput, SignIdentityInput, SignInput,
        SignedDelegation,
    },
};
use serde_bytes::{ByteArray, ByteBuf};
use std::{collections::BTreeSet, sync::Arc};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    agent::{query_call, update_call},
    rand_bytes,
};

#[derive(Clone)]
pub struct Client {
    agent: Arc<Agent>,
    pub canister: Principal,
}

impl Client {
    pub fn new(agent: Arc<Agent>, canister: Principal) -> Client {
        Client { agent, canister }
    }

    pub async fn get_state(&self) -> Result<StateInfo, String> {
        query_call(&self.agent, &self.canister, "state_get_info", ()).await?
    }

    /// the caller of agent should be canister controller
    pub async fn admin_add_managers(&self, args: BTreeSet<Principal>) -> Result<(), String> {
        update_call(&self.agent, &self.canister, "admin_add_managers", (args,)).await?
    }

    /// the caller of agent should be canister controller
    pub async fn admin_remove_managers(&self, args: BTreeSet<Principal>) -> Result<(), String> {
        update_call(
            &self.agent,
            &self.canister,
            "admin_remove_managers",
            (args,),
        )
        .await?
    }

    /// the caller of agent should be canister controller
    pub async fn admin_add_auditors(&self, args: BTreeSet<Principal>) -> Result<(), String> {
        update_call(&self.agent, &self.canister, "admin_add_auditors", (args,)).await?
    }

    /// the caller of agent should be canister controller
    pub async fn admin_remove_auditors(&self, args: BTreeSet<Principal>) -> Result<(), String> {
        update_call(
            &self.agent,
            &self.canister,
            "admin_remove_auditors",
            (args,),
        )
        .await?
    }

    /// the caller of agent should be canister controller
    pub async fn admin_add_allowed_apis(&self, args: BTreeSet<String>) -> Result<(), String> {
        update_call(
            &self.agent,
            &self.canister,
            "admin_add_allowed_apis",
            (args,),
        )
        .await?
    }

    /// the caller of agent should be canister controller
    pub async fn admin_remove_allowed_apis(&self, args: BTreeSet<String>) -> Result<(), String> {
        update_call(
            &self.agent,
            &self.canister,
            "admin_remove_allowed_apis",
            (args,),
        )
        .await?
    }

    /// the caller of agent should be canister controller
    pub async fn admin_create_namespace(
        &self,
        args: CreateNamespaceInput,
    ) -> Result<NamespaceInfo, String> {
        update_call(
            &self.agent,
            &self.canister,
            "admin_create_namespace",
            (args,),
        )
        .await?
    }

    pub async fn admin_list_namespace(
        &self,
        prev: Option<String>,
        take: Option<u32>,
    ) -> Result<Vec<NamespaceInfo>, String> {
        query_call(
            &self.agent,
            &self.canister,
            "admin_list_namespace",
            (prev, take),
        )
        .await?
    }

    pub async fn ecdsa_public_key(
        &self,
        args: Option<PublicKeyInput>,
    ) -> Result<PublicKeyOutput, String> {
        query_call(&self.agent, &self.canister, "ecdsa_public_key", (args,)).await?
    }

    pub async fn ecdsa_sign(&self, args: SignInput) -> Result<ByteBuf, String> {
        update_call(&self.agent, &self.canister, "ecdsa_sign", (args,)).await?
    }

    pub async fn schnorr_public_key(
        &self,
        algorithm: SchnorrAlgorithm,
        input: Option<PublicKeyInput>,
    ) -> Result<PublicKeyOutput, String> {
        query_call(
            &self.agent,
            &self.canister,
            "schnorr_public_key",
            (algorithm, input),
        )
        .await?
    }

    pub async fn schnorr_sign(
        &self,
        algorithm: SchnorrAlgorithm,
        input: SignInput,
    ) -> Result<ByteBuf, String> {
        update_call(
            &self.agent,
            &self.canister,
            "schnorr_sign",
            (algorithm, input),
        )
        .await?
    }

    pub async fn schnorr_sign_identity(
        &self,
        algorithm: SchnorrAlgorithm,
        input: SignIdentityInput,
    ) -> Result<ByteBuf, String> {
        update_call(
            &self.agent,
            &self.canister,
            "schnorr_sign_identity",
            (algorithm, input),
        )
        .await?
    }

    pub async fn ecdh_cose_encrypted_key(
        &self,
        path: SettingPath,
        ecdh: ECDHInput,
    ) -> Result<ECDHOutput<ByteBuf>, String> {
        update_call(
            &self.agent,
            &self.canister,
            "ecdh_cose_encrypted_key",
            (path, ecdh),
        )
        .await?
    }

    pub async fn get_cose_encrypted_key(&self, path: SettingPath) -> Result<[u8; 32], String> {
        let nonce: [u8; 12] = rand_bytes();
        let secret: [u8; 32] = rand_bytes();
        let secret = StaticSecret::from(secret);
        let public = PublicKey::from(&secret);
        let subject = if let Some(subject) = path.subject {
            subject
        } else {
            self.agent.get_principal()?
        };
        let res = self
            .ecdh_cose_encrypted_key(
                path,
                ECDHInput {
                    nonce: nonce.into(),
                    public_key: public.to_bytes().into(),
                },
            )
            .await?;

        let (shared_secret, _) = ecdh_x25519(secret.to_bytes(), *res.public_key);
        let add = subject.as_slice();
        let kek = cose_decrypt0(&res.payload, &shared_secret.to_bytes(), add)?;
        let key =
            CoseKey::from_slice(&kek).map_err(|err| format!("invalid COSE key: {:?}", err))?;
        let secret = get_cose_key_secret(key)?;
        secret.try_into().map_err(|val: Vec<u8>| {
            format!("invalid COSE secret, expected 32 bytes, got {}", val.len())
        })
    }

    pub async fn vetkd_public_key(&self, path: SettingPath) -> Result<ByteBuf, String> {
        update_call(&self.agent, &self.canister, "vetkd_public_key", (path,)).await?
    }

    pub async fn vetkd_encrypted_key(
        &self,
        path: SettingPath,
        public_key: ByteArray<48>,
    ) -> Result<ByteBuf, String> {
        update_call(
            &self.agent,
            &self.canister,
            "vetkd_encrypted_key",
            (path, public_key),
        )
        .await?
    }

    pub async fn namespace_get_fixed_identity(
        &self,
        namespace: String,
        name: String,
    ) -> Result<Principal, String> {
        query_call(
            &self.agent,
            &self.canister,
            "namespace_get_fixed_identity",
            (namespace, name),
        )
        .await?
    }

    pub async fn namespace_get_delegators(
        &self,
        namespace: String,
        name: String,
    ) -> Result<BTreeSet<Principal>, String> {
        query_call(
            &self.agent,
            &self.canister,
            "namespace_get_delegators",
            (namespace, name),
        )
        .await?
    }

    pub async fn namespace_add_delegator(
        &self,
        input: NamespaceDelegatorsInput,
    ) -> Result<BTreeSet<Principal>, String> {
        update_call(
            &self.agent,
            &self.canister,
            "namespace_add_delegator",
            (input,),
        )
        .await?
    }

    pub async fn namespace_remove_delegator(
        &self,
        input: NamespaceDelegatorsInput,
    ) -> Result<(), String> {
        update_call(
            &self.agent,
            &self.canister,
            "namespace_remove_delegator",
            (input,),
        )
        .await?
    }

    pub async fn namespace_sign_delegation(
        &self,
        input: SignDelegationInput,
    ) -> Result<SignDelegationOutput, String> {
        update_call(
            &self.agent,
            &self.canister,
            "namespace_remove_delegator",
            (input,),
        )
        .await?
    }

    pub async fn get_delegation(
        &self,
        seed: ByteBuf,
        pubkey: ByteBuf,
        expiration: u64,
    ) -> Result<SignedDelegation, String> {
        query_call(
            &self.agent,
            &self.canister,
            "get_delegation",
            (seed, pubkey, expiration),
        )
        .await?
    }

    pub async fn namespace_get_info(&self, namespace: String) -> Result<NamespaceInfo, String> {
        query_call(
            &self.agent,
            &self.canister,
            "namespace_get_info",
            (namespace,),
        )
        .await?
    }

    pub async fn namespace_list_setting_keys(
        &self,
        namespace: String,
        user_owned: bool,
        subject: Option<Principal>,
    ) -> Result<NamespaceInfo, String> {
        query_call(
            &self.agent,
            &self.canister,
            "namespace_list_setting_keys",
            (namespace, user_owned, subject),
        )
        .await?
    }

    pub async fn namespace_update_info(&self, args: UpdateNamespaceInput) -> Result<(), String> {
        update_call(
            &self.agent,
            &self.canister,
            "namespace_update_info",
            (args,),
        )
        .await?
    }

    pub async fn namespace_delete(&self, namespace: String) -> Result<(), String> {
        update_call(
            &self.agent,
            &self.canister,
            "namespace_delete",
            (namespace,),
        )
        .await?
    }

    pub async fn namespace_add_managers(
        &self,
        namespace: String,
        args: BTreeSet<Principal>,
    ) -> Result<(), String> {
        update_call(
            &self.agent,
            &self.canister,
            "namespace_add_managers",
            (namespace, args),
        )
        .await?
    }

    pub async fn namespace_remove_managers(
        &self,
        namespace: String,
        args: BTreeSet<Principal>,
    ) -> Result<(), String> {
        update_call(
            &self.agent,
            &self.canister,
            "namespace_remove_managers",
            (namespace, args),
        )
        .await?
    }

    pub async fn namespace_add_auditors(
        &self,
        namespace: String,
        args: BTreeSet<Principal>,
    ) -> Result<(), String> {
        update_call(
            &self.agent,
            &self.canister,
            "namespace_add_auditors",
            (namespace, args),
        )
        .await?
    }

    pub async fn namespace_remove_auditors(
        &self,
        namespace: String,
        args: BTreeSet<Principal>,
    ) -> Result<(), String> {
        update_call(
            &self.agent,
            &self.canister,
            "namespace_remove_auditors",
            (namespace, args),
        )
        .await?
    }

    pub async fn namespace_add_users(
        &self,
        namespace: String,
        args: BTreeSet<Principal>,
    ) -> Result<(), String> {
        update_call(
            &self.agent,
            &self.canister,
            "namespace_add_users",
            (namespace, args),
        )
        .await?
    }

    pub async fn namespace_remove_users(
        &self,
        namespace: String,
        args: BTreeSet<Principal>,
    ) -> Result<(), String> {
        update_call(
            &self.agent,
            &self.canister,
            "namespace_remove_users",
            (namespace, args),
        )
        .await?
    }

    pub async fn namespace_top_up(&self, namespace: String, cycles: u128) -> Result<u128, String> {
        update_call(
            &self.agent,
            &self.canister,
            "namespace_top_up",
            (namespace, cycles),
        )
        .await?
    }

    pub async fn setting_get_info(&self, path: SettingPath) -> Result<SettingInfo, String> {
        query_call(&self.agent, &self.canister, "setting_get_info", (path,)).await?
    }

    pub async fn setting_get(&self, path: SettingPath) -> Result<SettingInfo, String> {
        query_call(&self.agent, &self.canister, "setting_get", (path,)).await?
    }

    pub async fn setting_get_archived_payload(
        &self,
        path: SettingPath,
    ) -> Result<SettingArchivedPayload, String> {
        query_call(
            &self.agent,
            &self.canister,
            "setting_get_archived_payload",
            (path,),
        )
        .await?
    }

    pub async fn setting_create(
        &self,
        path: SettingPath,
        input: CreateSettingInput,
    ) -> Result<CreateSettingOutput, String> {
        update_call(&self.agent, &self.canister, "setting_create", (path, input)).await?
    }

    pub async fn setting_update_info(
        &self,
        path: SettingPath,
        input: UpdateSettingInfoInput,
    ) -> Result<UpdateSettingOutput, String> {
        update_call(
            &self.agent,
            &self.canister,
            "setting_update_info",
            (path, input),
        )
        .await?
    }

    pub async fn setting_update_payload(
        &self,
        path: SettingPath,
        input: UpdateSettingPayloadInput,
    ) -> Result<UpdateSettingOutput, String> {
        update_call(
            &self.agent,
            &self.canister,
            "setting_update_payload",
            (path, input),
        )
        .await?
    }

    pub async fn setting_add_readers(
        &self,
        path: SettingPath,
        args: BTreeSet<Principal>,
    ) -> Result<(), String> {
        update_call(
            &self.agent,
            &self.canister,
            "setting_add_readers",
            (path, args),
        )
        .await?
    }

    pub async fn setting_remove_readers(
        &self,
        path: SettingPath,
        args: BTreeSet<Principal>,
    ) -> Result<(), String> {
        update_call(
            &self.agent,
            &self.canister,
            "setting_remove_readers",
            (path, args),
        )
        .await?
    }

    pub async fn setting_delete(&self, path: SettingPath) -> Result<(), String> {
        update_call(&self.agent, &self.canister, "setting_delete", (path,)).await?
    }
}
