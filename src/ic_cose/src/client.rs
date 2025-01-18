use async_trait::async_trait;
use candid::{
    utils::{encode_args, ArgumentEncoder},
    CandidType, Decode, Principal,
};
use ic_agent::Agent;
use ic_cose_types::{
    cose::{
        ecdh::ecdh_x25519, encrypt0::cose_decrypt0, get_cose_key_secret, CborSerializable, CoseKey,
    },
    format_error,
    types::namespace::*,
    types::setting::*,
    types::{
        state::StateInfo, ECDHInput, ECDHOutput, PublicKeyInput, PublicKeyOutput, SchnorrAlgorithm,
        SettingPath, SignDelegationInput, SignDelegationOutput, SignIdentityInput, SignInput,
        SignedDelegation,
    },
    BoxError, CanisterCaller,
};
use serde_bytes::{ByteArray, ByteBuf};
use std::{collections::BTreeSet, sync::Arc};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::rand_bytes;

#[derive(Clone)]
pub struct Client {
    agent: Arc<Agent>,
    canister: Principal,
}

impl Client {
    pub fn new(agent: Arc<Agent>, canister: Principal) -> Client {
        Client { agent, canister }
    }
}

impl CoseSDK for Client {
    fn canister(&self) -> &Principal {
        &self.canister
    }
}

impl CanisterCaller for Client {
    async fn canister_query<
        In: ArgumentEncoder + Send,
        Out: CandidType + for<'a> candid::Deserialize<'a>,
    >(
        &self,
        canister: &Principal,
        method: &str,
        args: In,
    ) -> Result<Out, BoxError> {
        let input = encode_args(args)?;
        let res = self
            .agent
            .query(canister, method)
            .with_arg(input)
            .call()
            .await?;
        let output = Decode!(res.as_slice(), Out)?;
        Ok(output)
    }

    async fn canister_update<
        In: ArgumentEncoder + Send,
        Out: CandidType + for<'a> candid::Deserialize<'a>,
    >(
        &self,
        canister: &Principal,
        method: &str,
        args: In,
    ) -> Result<Out, BoxError> {
        let input = encode_args(args)?;
        let res = self
            .agent
            .update(canister, method)
            .with_arg(input)
            .call_and_wait()
            .await?;
        let output = Decode!(res.as_slice(), Out)?;
        Ok(output)
    }
}

#[async_trait]
pub trait CoseSDK: CanisterCaller + Sized {
    fn canister(&self) -> &Principal;

    async fn get_state(&self) -> Result<StateInfo, String> {
        self.canister_query(self.canister(), "state_get_info", ())
            .await
            .map_err(format_error)?
    }

    /// the caller of agent should be canister controller
    async fn admin_add_managers(&self, args: &BTreeSet<Principal>) -> Result<(), String> {
        self.canister_update(self.canister(), "admin_add_managers", (args,))
            .await
            .map_err(format_error)?
    }

    /// the caller of agent should be canister controller
    async fn admin_remove_managers(&self, args: &BTreeSet<Principal>) -> Result<(), String> {
        self.canister_update(self.canister(), "admin_remove_managers", (args,))
            .await
            .map_err(format_error)?
    }

    /// the caller of agent should be canister controller
    async fn admin_add_auditors(&self, args: &BTreeSet<Principal>) -> Result<(), String> {
        self.canister_update(self.canister(), "admin_add_auditors", (args,))
            .await
            .map_err(format_error)?
    }

    /// the caller of agent should be canister controller
    async fn admin_remove_auditors(&self, args: &BTreeSet<Principal>) -> Result<(), String> {
        self.canister_update(self.canister(), "admin_remove_auditors", (args,))
            .await
            .map_err(format_error)?
    }

    /// the caller of agent should be canister controller
    async fn admin_add_allowed_apis(&self, args: &BTreeSet<String>) -> Result<(), String> {
        self.canister_update(self.canister(), "admin_add_allowed_apis", (args,))
            .await
            .map_err(format_error)?
    }

    /// the caller of agent should be canister controller
    async fn admin_remove_allowed_apis(&self, args: &BTreeSet<String>) -> Result<(), String> {
        self.canister_update(self.canister(), "admin_remove_allowed_apis", (args,))
            .await
            .map_err(format_error)?
    }

    /// the caller of agent should be canister controller
    async fn admin_create_namespace(
        &self,
        args: &CreateNamespaceInput,
    ) -> Result<NamespaceInfo, String> {
        self.canister_update(self.canister(), "admin_create_namespace", (args,))
            .await
            .map_err(format_error)?
    }

    async fn admin_list_namespace(
        &self,
        prev: Option<&str>,
        take: Option<u32>,
    ) -> Result<Vec<NamespaceInfo>, String> {
        self.canister_update(self.canister(), "admin_list_namespace", (prev, take))
            .await
            .map_err(format_error)?
    }

    async fn ecdsa_public_key(
        &self,
        args: Option<&PublicKeyInput>,
    ) -> Result<PublicKeyOutput, String> {
        self.canister_query(self.canister(), "ecdsa_public_key", (args,))
            .await
            .map_err(format_error)?
    }

    async fn ecdsa_sign(&self, args: &SignInput) -> Result<ByteBuf, String> {
        self.canister_update(self.canister(), "ecdsa_sign", (args,))
            .await
            .map_err(format_error)?
    }

    async fn schnorr_public_key(
        &self,
        algorithm: &SchnorrAlgorithm,
        input: Option<PublicKeyInput>,
    ) -> Result<PublicKeyOutput, String> {
        self.canister_query(self.canister(), "schnorr_public_key", (algorithm, input))
            .await
            .map_err(format_error)?
    }

    async fn schnorr_sign(
        &self,
        algorithm: &SchnorrAlgorithm,
        input: &SignInput,
    ) -> Result<ByteBuf, String> {
        self.canister_update(self.canister(), "schnorr_sign", (algorithm, input))
            .await
            .map_err(format_error)?
    }

    async fn schnorr_sign_identity(
        &self,
        algorithm: &SchnorrAlgorithm,
        input: &SignIdentityInput,
    ) -> Result<ByteBuf, String> {
        self.canister_update(self.canister(), "schnorr_sign_identity", (algorithm, input))
            .await
            .map_err(format_error)?
    }

    async fn ecdh_cose_encrypted_key(
        &self,
        path: &SettingPath,
        ecdh: &ECDHInput,
    ) -> Result<ECDHOutput<ByteBuf>, String> {
        self.canister_update(self.canister(), "ecdh_cose_encrypted_key", (path, ecdh))
            .await
            .map_err(format_error)?
    }

    async fn get_cose_encrypted_key(&self, path: &SettingPath) -> Result<ByteArray<32>, String> {
        let nonce: [u8; 12] = rand_bytes();
        let secret: [u8; 32] = rand_bytes();
        let secret = StaticSecret::from(secret);
        let public = PublicKey::from(&secret);
        let subject = path
            .subject
            .ok_or_else(|| "subject is required for get_cose_encrypted_key".to_string())?;
        let res = self
            .ecdh_cose_encrypted_key(
                path,
                &ECDHInput {
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
        let secret: [u8; 32] = secret.try_into().map_err(|val: Vec<u8>| {
            format!("invalid COSE secret, expected 32 bytes, got {}", val.len())
        })?;
        Ok(secret.into())
    }

    async fn vetkd_public_key(&self, path: &SettingPath) -> Result<ByteBuf, String> {
        self.canister_update(self.canister(), "vetkd_public_key", (path,))
            .await
            .map_err(format_error)?
    }

    async fn vetkd_encrypted_key(
        &self,
        path: &SettingPath,
        public_key: &ByteArray<48>,
    ) -> Result<ByteBuf, String> {
        self.canister_update(self.canister(), "vetkd_encrypted_key", (path, public_key))
            .await
            .map_err(format_error)?
    }

    async fn namespace_get_fixed_identity(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Principal, String> {
        self.canister_query(
            self.canister(),
            "namespace_get_fixed_identity",
            (namespace, name),
        )
        .await
        .map_err(format_error)?
    }

    async fn namespace_get_delegators(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<BTreeSet<Principal>, String> {
        self.canister_query(
            self.canister(),
            "namespace_get_delegators",
            (namespace, name),
        )
        .await
        .map_err(format_error)?
    }

    async fn namespace_add_delegator(
        &self,
        input: &NamespaceDelegatorsInput,
    ) -> Result<BTreeSet<Principal>, String> {
        self.canister_update(self.canister(), "namespace_add_delegator", (input,))
            .await
            .map_err(format_error)?
    }

    async fn namespace_remove_delegator(
        &self,
        input: &NamespaceDelegatorsInput,
    ) -> Result<(), String> {
        self.canister_update(self.canister(), "namespace_remove_delegator", (input,))
            .await
            .map_err(format_error)?
    }

    async fn namespace_sign_delegation(
        &self,
        input: &SignDelegationInput,
    ) -> Result<SignDelegationOutput, String> {
        self.canister_update(self.canister(), "namespace_sign_delegation", (input,))
            .await
            .map_err(format_error)?
    }

    async fn get_delegation(
        &self,
        seed: &ByteBuf,
        pubkey: &ByteBuf,
        expiration: u64,
    ) -> Result<SignedDelegation, String> {
        self.canister_query(
            self.canister(),
            "get_delegation",
            (seed, pubkey, expiration),
        )
        .await
        .map_err(format_error)?
    }

    async fn namespace_get_info(&self, namespace: &str) -> Result<NamespaceInfo, String> {
        self.canister_query(self.canister(), "namespace_get_info", (namespace,))
            .await
            .map_err(format_error)?
    }

    async fn namespace_list_setting_keys(
        &self,
        namespace: &str,
        user_owned: bool,
        subject: Option<Principal>,
    ) -> Result<NamespaceInfo, String> {
        self.canister_query(
            self.canister(),
            "namespace_list_setting_keys",
            (namespace, user_owned, subject),
        )
        .await
        .map_err(format_error)?
    }

    async fn namespace_update_info(&self, args: &UpdateNamespaceInput) -> Result<(), String> {
        self.canister_update(self.canister(), "namespace_update_info", (args,))
            .await
            .map_err(format_error)?
    }

    async fn namespace_delete(&self, namespace: &str) -> Result<(), String> {
        self.canister_update(self.canister(), "namespace_delete", (namespace,))
            .await
            .map_err(format_error)?
    }

    async fn namespace_add_managers(
        &self,
        namespace: &str,
        args: &BTreeSet<Principal>,
    ) -> Result<(), String> {
        self.canister_update(self.canister(), "namespace_add_managers", (namespace, args))
            .await
            .map_err(format_error)?
    }

    async fn namespace_remove_managers(
        &self,
        namespace: &str,
        args: &BTreeSet<Principal>,
    ) -> Result<(), String> {
        self.canister_update(
            self.canister(),
            "namespace_remove_managers",
            (namespace, args),
        )
        .await
        .map_err(format_error)?
    }

    async fn namespace_add_auditors(
        &self,
        namespace: &str,
        args: &BTreeSet<Principal>,
    ) -> Result<(), String> {
        self.canister_update(self.canister(), "namespace_add_auditors", (namespace, args))
            .await
            .map_err(format_error)?
    }

    async fn namespace_remove_auditors(
        &self,
        namespace: &str,
        args: &BTreeSet<Principal>,
    ) -> Result<(), String> {
        self.canister_update(
            self.canister(),
            "namespace_remove_auditors",
            (namespace, args),
        )
        .await
        .map_err(format_error)?
    }

    async fn namespace_add_users(
        &self,
        namespace: &str,
        args: &BTreeSet<Principal>,
    ) -> Result<(), String> {
        self.canister_update(self.canister(), "namespace_add_users", (namespace, args))
            .await
            .map_err(format_error)?
    }

    async fn namespace_remove_users(
        &self,
        namespace: &str,
        args: &BTreeSet<Principal>,
    ) -> Result<(), String> {
        self.canister_update(self.canister(), "namespace_remove_users", (namespace, args))
            .await
            .map_err(format_error)?
    }

    async fn namespace_is_member(
        &self,
        namespace: &str,
        kind: &str,
        user: &Principal,
    ) -> Result<bool, String> {
        self.canister_query(
            self.canister(),
            "namespace_is_member",
            (namespace, kind, user),
        )
        .await
        .map_err(format_error)?
    }

    async fn namespace_top_up(&self, namespace: &str, cycles: u128) -> Result<u128, String> {
        self.canister_update(self.canister(), "namespace_top_up", (namespace, cycles))
            .await
            .map_err(format_error)?
    }

    async fn setting_get_info(&self, path: &SettingPath) -> Result<SettingInfo, String> {
        self.canister_query(self.canister(), "setting_get_info", (path,))
            .await
            .map_err(format_error)?
    }

    async fn setting_get(&self, path: &SettingPath) -> Result<SettingInfo, String> {
        self.canister_query(self.canister(), "setting_get", (path,))
            .await
            .map_err(format_error)?
    }

    async fn setting_get_archived_payload(
        &self,
        path: &SettingPath,
    ) -> Result<SettingArchivedPayload, String> {
        self.canister_query(self.canister(), "setting_get_archived_payload", (path,))
            .await
            .map_err(format_error)?
    }

    async fn setting_create(
        &self,
        path: &SettingPath,
        input: &CreateSettingInput,
    ) -> Result<CreateSettingOutput, String> {
        self.canister_update(self.canister(), "setting_create", (path, input))
            .await
            .map_err(format_error)?
    }

    async fn setting_update_info(
        &self,
        path: &SettingPath,
        input: &UpdateSettingInfoInput,
    ) -> Result<UpdateSettingOutput, String> {
        self.canister_update(self.canister(), "setting_update_info", (path, input))
            .await
            .map_err(format_error)?
    }

    async fn setting_update_payload(
        &self,
        path: &SettingPath,
        input: &UpdateSettingPayloadInput,
    ) -> Result<UpdateSettingOutput, String> {
        self.canister_update(self.canister(), "setting_update_payload", (path, input))
            .await
            .map_err(format_error)?
    }

    async fn setting_add_readers(
        &self,
        path: &SettingPath,
        args: &BTreeSet<Principal>,
    ) -> Result<(), String> {
        self.canister_update(self.canister(), "setting_add_readers", (path, args))
            .await
            .map_err(format_error)?
    }

    async fn setting_remove_readers(
        &self,
        path: &SettingPath,
        args: &BTreeSet<Principal>,
    ) -> Result<(), String> {
        self.canister_update(self.canister(), "setting_remove_readers", (path, args))
            .await
            .map_err(format_error)?
    }

    async fn setting_delete(&self, path: &SettingPath) -> Result<(), String> {
        self.canister_update(self.canister(), "setting_delete", (path,))
            .await
            .map_err(format_error)?
    }
}
