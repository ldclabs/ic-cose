use async_trait::async_trait;
use candid::{
    utils::{encode_args, ArgumentEncoder},
    CandidType, Decode, Principal,
};
use futures::try_join;
use ic_agent::Agent;
use ic_auth_types::{SignInResponse, SignedDelegation};
use ic_cose_types::{
    cose::{ecdh::try_ecdh_x25519, encrypt0::cose_decrypt0, get_cose_key_secret, CoseKey},
    format_error,
    types::namespace::*,
    types::setting::*,
    types::{
        state::StateInfo, ECDHInput, ECDHOutput, PublicKeyInput, PublicKeyOutput, SchnorrAlgorithm,
        SettingPath, SignDelegationInput, SignIdentityInput, SignInput,
    },
    BoxError, CanisterCaller,
};
use serde_bytes::{ByteArray, ByteBuf};
use std::{collections::BTreeSet, sync::Arc};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::rand_bytes;
use crate::vetkeys::{DerivedPublicKey, EncryptedVetKey, TransportSecretKey, VetKey};

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

/// Calls a query method whose Candid reply is `Result<T, String>`.
async fn query<C, In, T>(sdk: &C, method: &str, args: In) -> Result<T, String>
where
    C: CoseSDK + Sync,
    In: ArgumentEncoder + Send,
    T: CandidType + for<'a> candid::Deserialize<'a>,
{
    sdk.canister_query::<In, Result<T, String>>(sdk.canister(), method, args)
        .await
        .map_err(format_error)?
}

/// Calls an update method whose Candid reply is `Result<T, String>`.
async fn update<C, In, T>(sdk: &C, method: &str, args: In) -> Result<T, String>
where
    C: CoseSDK + Sync,
    In: ArgumentEncoder + Send,
    T: CandidType + for<'a> candid::Deserialize<'a>,
{
    sdk.canister_update::<In, Result<T, String>>(sdk.canister(), method, args)
        .await
        .map_err(format_error)?
}

#[async_trait]
pub trait CoseSDK: CanisterCaller + Sized {
    fn canister(&self) -> &Principal;

    async fn get_state(&self) -> Result<StateInfo, String> {
        query(self, "state_get_info", ()).await
    }

    /// the caller of agent should be canister controller
    async fn admin_add_managers(&self, args: &BTreeSet<Principal>) -> Result<(), String> {
        update(self, "admin_add_managers", (args,)).await
    }

    /// the caller of agent should be canister controller
    async fn admin_remove_managers(&self, args: &BTreeSet<Principal>) -> Result<(), String> {
        update(self, "admin_remove_managers", (args,)).await
    }

    /// the caller of agent should be canister controller
    async fn admin_add_auditors(&self, args: &BTreeSet<Principal>) -> Result<(), String> {
        update(self, "admin_add_auditors", (args,)).await
    }

    /// the caller of agent should be canister controller
    async fn admin_remove_auditors(&self, args: &BTreeSet<Principal>) -> Result<(), String> {
        update(self, "admin_remove_auditors", (args,)).await
    }

    /// the caller of agent should be canister controller
    async fn admin_add_allowed_apis(&self, args: &BTreeSet<String>) -> Result<(), String> {
        update(self, "admin_add_allowed_apis", (args,)).await
    }

    /// the caller of agent should be canister controller
    async fn admin_remove_allowed_apis(&self, args: &BTreeSet<String>) -> Result<(), String> {
        update(self, "admin_remove_allowed_apis", (args,)).await
    }

    /// the caller of agent should be canister controller
    async fn admin_create_namespace(
        &self,
        args: &CreateNamespaceInput,
    ) -> Result<NamespaceInfo, String> {
        update(self, "admin_create_namespace", (args,)).await
    }

    async fn admin_list_namespace(
        &self,
        prev: Option<&str>,
        take: Option<u32>,
    ) -> Result<Vec<NamespaceInfo>, String> {
        update(self, "admin_list_namespace", (prev, take)).await
    }

    async fn ecdsa_public_key(
        &self,
        args: Option<&PublicKeyInput>,
    ) -> Result<PublicKeyOutput, String> {
        query(self, "ecdsa_public_key", (args,)).await
    }

    async fn ecdsa_sign(&self, args: &SignInput) -> Result<ByteBuf, String> {
        update(self, "ecdsa_sign", (args,)).await
    }

    async fn schnorr_public_key(
        &self,
        algorithm: &SchnorrAlgorithm,
        input: Option<PublicKeyInput>,
    ) -> Result<PublicKeyOutput, String> {
        query(self, "schnorr_public_key", (algorithm, input)).await
    }

    async fn schnorr_sign(
        &self,
        algorithm: &SchnorrAlgorithm,
        input: &SignInput,
    ) -> Result<ByteBuf, String> {
        update(self, "schnorr_sign", (algorithm, input)).await
    }

    async fn schnorr_sign_identity(
        &self,
        algorithm: &SchnorrAlgorithm,
        input: &SignIdentityInput,
    ) -> Result<ByteBuf, String> {
        update(self, "schnorr_sign_identity", (algorithm, input)).await
    }

    async fn ecdh_cose_encrypted_key(
        &self,
        path: &SettingPath,
        ecdh: &ECDHInput,
    ) -> Result<ECDHOutput<ByteBuf>, String> {
        update(self, "ecdh_cose_encrypted_key", (path, ecdh)).await
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

        let (shared_secret, _) = try_ecdh_x25519(secret.to_bytes(), *res.public_key)?;
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
        update(self, "vetkd_public_key", (path,)).await
    }

    async fn vetkd_encrypted_key(
        &self,
        path: &SettingPath,
        transport_public_key: &ByteBuf,
    ) -> Result<ByteBuf, String> {
        update(self, "vetkd_encrypted_key", (path, transport_public_key)).await
    }

    async fn vetkey(&self, path: &SettingPath) -> Result<(VetKey, DerivedPublicKey), String> {
        let seed: [u8; 32] = rand_bytes();
        let tsk = TransportSecretKey::from_seed(seed.into())?;
        let tpk = tsk.public_key().into();

        let (pk, ek) = try_join!(
            self.vetkd_public_key(path),
            self.vetkd_encrypted_key(path, &tpk)
        )?;
        let dpk = DerivedPublicKey::deserialize(&pk).map_err(|err| format!("{err:?}"))?;
        let evk = EncryptedVetKey::deserialize(&ek).map_err(|err| format!("{err:?}"))?;
        let vk = evk.decrypt_and_verify(&tsk, &dpk, &path.key)?;
        Ok((vk, dpk))
    }

    async fn namespace_get_fixed_identity(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Principal, String> {
        query(self, "namespace_get_fixed_identity", (namespace, name)).await
    }

    async fn namespace_get_delegators(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<BTreeSet<Principal>, String> {
        query(self, "namespace_get_delegators", (namespace, name)).await
    }

    async fn namespace_add_delegator(
        &self,
        input: &NamespaceDelegatorsInput,
    ) -> Result<BTreeSet<Principal>, String> {
        update(self, "namespace_add_delegator", (input,)).await
    }

    async fn namespace_remove_delegator(
        &self,
        input: &NamespaceDelegatorsInput,
    ) -> Result<(), String> {
        update(self, "namespace_remove_delegator", (input,)).await
    }

    async fn namespace_sign_delegation(
        &self,
        input: &SignDelegationInput,
    ) -> Result<SignInResponse, String> {
        update(self, "namespace_sign_delegation", (input,)).await
    }

    async fn get_delegation(
        &self,
        seed: &ByteBuf,
        pubkey: &ByteBuf,
        expiration: u64,
    ) -> Result<SignedDelegation, String> {
        query(self, "get_delegation", (seed, pubkey, expiration)).await
    }

    async fn namespace_get_info(&self, namespace: &str) -> Result<NamespaceInfo, String> {
        query(self, "namespace_get_info", (namespace,)).await
    }

    async fn namespace_get_info_v2(
        &self,
        namespace: &str,
        with_members: bool,
    ) -> Result<NamespaceInfo, String> {
        query(self, "namespace_get_info_v2", (namespace, with_members)).await
    }

    async fn namespace_list_members(
        &self,
        namespace: &str,
        kind: &str,
        prev: Option<Principal>,
        take: Option<u32>,
    ) -> Result<Vec<Principal>, String> {
        query(
            self,
            "namespace_list_members",
            (namespace, kind, prev, take),
        )
        .await
    }

    async fn namespace_list_fixed_identity_names(
        &self,
        namespace: &str,
        prev: Option<&str>,
        take: Option<u32>,
    ) -> Result<Vec<String>, String> {
        query(
            self,
            "namespace_list_fixed_identity_names",
            (namespace, prev, take),
        )
        .await
    }

    /// Lists a page after the exclusive `(subject, key)` cursor. Keep the same
    /// namespace, ownership and subject filter while walking subsequent pages.
    async fn namespace_list_setting_keys_v2(
        &self,
        namespace: &str,
        user_owned: bool,
        subject: Option<Principal>,
        prev: Option<(Principal, ByteBuf)>,
        take: Option<u32>,
    ) -> Result<Vec<(Principal, ByteBuf)>, String> {
        query(
            self,
            "namespace_list_setting_keys_v2",
            (namespace, user_owned, subject, prev, take),
        )
        .await
    }

    /// Lists the `(subject, key)` pairs of a namespace's settings.
    async fn namespace_list_setting_keys(
        &self,
        namespace: &str,
        user_owned: bool,
        subject: Option<Principal>,
    ) -> Result<Vec<(Principal, ByteBuf)>, String> {
        query(
            self,
            "namespace_list_setting_keys",
            (namespace, user_owned, subject),
        )
        .await
    }

    async fn namespace_update_info(&self, args: &UpdateNamespaceInput) -> Result<(), String> {
        update(self, "namespace_update_info", (args,)).await
    }

    async fn namespace_delete(&self, namespace: &str) -> Result<(), String> {
        update(self, "namespace_delete", (namespace,)).await
    }

    async fn namespace_add_managers(
        &self,
        namespace: &str,
        args: &BTreeSet<Principal>,
    ) -> Result<(), String> {
        update(self, "namespace_add_managers", (namespace, args)).await
    }

    async fn namespace_remove_managers(
        &self,
        namespace: &str,
        args: &BTreeSet<Principal>,
    ) -> Result<(), String> {
        update(self, "namespace_remove_managers", (namespace, args)).await
    }

    async fn namespace_add_auditors(
        &self,
        namespace: &str,
        args: &BTreeSet<Principal>,
    ) -> Result<(), String> {
        update(self, "namespace_add_auditors", (namespace, args)).await
    }

    async fn namespace_remove_auditors(
        &self,
        namespace: &str,
        args: &BTreeSet<Principal>,
    ) -> Result<(), String> {
        update(self, "namespace_remove_auditors", (namespace, args)).await
    }

    async fn namespace_add_users(
        &self,
        namespace: &str,
        args: &BTreeSet<Principal>,
    ) -> Result<(), String> {
        update(self, "namespace_add_users", (namespace, args)).await
    }

    async fn namespace_remove_users(
        &self,
        namespace: &str,
        args: &BTreeSet<Principal>,
    ) -> Result<(), String> {
        update(self, "namespace_remove_users", (namespace, args)).await
    }

    async fn namespace_is_member(
        &self,
        namespace: &str,
        kind: &str,
        user: &Principal,
    ) -> Result<bool, String> {
        query(self, "namespace_is_member", (namespace, kind, user)).await
    }

    /// Adds cycles to a namespace's gas balance.
    ///
    /// The canister only credits cycles that were *attached* to the call, which
    /// an ingress call cannot do and [`CanisterCaller`] has no way to express.
    /// Reaching this endpoint through this trait therefore always fails with
    /// "insufficient cycles"; a top-up must be sent from a canister that
    /// attaches the cycles to the call itself.
    async fn namespace_top_up(&self, namespace: &str, cycles: u128) -> Result<u128, String> {
        update(self, "namespace_top_up", (namespace, cycles)).await
    }

    async fn setting_get_info(&self, path: &SettingPath) -> Result<SettingInfo, String> {
        query(self, "setting_get_info", (path,)).await
    }

    async fn setting_get(&self, path: &SettingPath) -> Result<SettingInfo, String> {
        query(self, "setting_get", (path,)).await
    }

    /// Reads a setting through replicated execution and a certified update reply.
    async fn setting_get_consensus(&self, path: &SettingPath) -> Result<SettingInfo, String> {
        update(self, "setting_get", (path,)).await
    }

    async fn setting_get_archived_payload(
        &self,
        path: &SettingPath,
    ) -> Result<SettingArchivedPayload, String> {
        query(self, "setting_get_archived_payload", (path,)).await
    }

    async fn setting_create(
        &self,
        path: &SettingPath,
        input: &CreateSettingInput,
    ) -> Result<CreateSettingOutput, String> {
        update(self, "setting_create", (path, input)).await
    }

    async fn setting_update_info(
        &self,
        path: &SettingPath,
        input: &UpdateSettingInfoInput,
    ) -> Result<UpdateSettingOutput, String> {
        update(self, "setting_update_info", (path, input)).await
    }

    async fn setting_update_payload(
        &self,
        path: &SettingPath,
        input: &UpdateSettingPayloadInput,
    ) -> Result<UpdateSettingOutput, String> {
        update(self, "setting_update_payload", (path, input)).await
    }

    async fn setting_add_readers(
        &self,
        path: &SettingPath,
        args: &BTreeSet<Principal>,
    ) -> Result<(), String> {
        update(self, "setting_add_readers", (path, args)).await
    }

    async fn setting_remove_readers(
        &self,
        path: &SettingPath,
        args: &BTreeSet<Principal>,
    ) -> Result<(), String> {
        update(self, "setting_remove_readers", (path, args)).await
    }

    async fn setting_delete(&self, path: &SettingPath) -> Result<(), String> {
        update(self, "setting_delete", (path,)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use candid::{decode_args, encode_args, encode_one};
    use http::{Response, StatusCode};
    use ic_agent::{agent::HttpService, AgentError};
    use ic_auth_types::{ByteBufB64, Delegation};
    use ic_cose_types::cose::{cose_aes256_key, ecdh::ecdh_x25519, encrypt0::cose_encrypt0, iana};
    use ic_transport_types::{QueryResponse, ReplyResponse};
    use std::{
        collections::{BTreeMap, VecDeque},
        io,
        sync::{Mutex, MutexGuard},
    };

    #[derive(Debug, PartialEq, Eq)]
    enum CallKind {
        Query,
        Update,
    }

    #[derive(Debug)]
    struct CallRecord {
        kind: CallKind,
        canister: Principal,
        method: String,
        args: Vec<u8>,
    }

    type MockResponses = Arc<Mutex<VecDeque<Result<Vec<u8>, String>>>>;

    #[derive(Clone)]
    struct MockCose {
        canister: Principal,
        calls: Arc<Mutex<Vec<CallRecord>>>,
        responses: MockResponses,
        ecdh_mode: Arc<Mutex<EcdhMode>>,
    }

    #[derive(Clone, Copy)]
    enum EcdhMode {
        Valid,
        InvalidCoseKey,
        ShortSecret,
    }

    impl MockCose {
        fn new() -> Self {
            Self {
                canister: Principal::management_canister(),
                calls: Arc::new(Mutex::new(Vec::new())),
                responses: Arc::new(Mutex::new(VecDeque::new())),
                ecdh_mode: Arc::new(Mutex::new(EcdhMode::Valid)),
            }
        }

        fn respond<T: CandidType>(&self, value: T) {
            self.responses
                .lock()
                .unwrap()
                .push_back(Ok(encode_one(Ok::<T, String>(value)).unwrap()));
        }

        fn respond_err(&self, err: &str) {
            self.responses
                .lock()
                .unwrap()
                .push_back(Err(err.to_string()));
        }

        fn calls(&self) -> MutexGuard<'_, Vec<CallRecord>> {
            self.calls.lock().unwrap()
        }

        fn set_ecdh_mode(&self, mode: EcdhMode) {
            *self.ecdh_mode.lock().unwrap() = mode;
        }

        fn next_response(&self, method: &str, args: &[u8]) -> Result<Vec<u8>, BoxError> {
            if method == "ecdh_cose_encrypted_key" {
                let (path, ecdh): (SettingPath, ECDHInput) = decode_args(args)?;
                let subject = path.subject.expect("test path has subject");
                let server_secret = [8u8; 32];
                let (shared_secret, server_public) = ecdh_x25519(server_secret, *ecdh.public_key);
                let cose_key = match *self.ecdh_mode.lock().unwrap() {
                    EcdhMode::Valid => cose_aes256_key([9u8; 32], b"kid".to_vec())
                        .to_vec()
                        .unwrap(),
                    EcdhMode::InvalidCoseKey => vec![1, 2, 3],
                    EcdhMode::ShortSecret => {
                        let mut key = CoseKey::new();
                        key.set_kty(iana::KeyTypeSymmetric);
                        key.insert(iana::SymmetricKeyParameterK, vec![9u8; 31]);
                        key.to_vec().unwrap()
                    }
                };
                let payload = cose_encrypt0(
                    &cose_key,
                    shared_secret.as_bytes(),
                    subject.as_slice(),
                    ecdh.nonce.as_ref(),
                    None,
                )
                .unwrap();
                let output = ECDHOutput {
                    payload: ByteBuf::from(payload),
                    public_key: server_public.to_bytes().into(),
                };
                return Ok(encode_one(Ok::<_, String>(output)).unwrap());
            }

            match self.responses.lock().unwrap().pop_front() {
                Some(Ok(bytes)) => Ok(bytes),
                Some(Err(err)) => Err(io::Error::other(err).into()),
                None => Err(io::Error::other(format!("missing mock response for {method}")).into()),
            }
        }
    }

    impl CoseSDK for MockCose {
        fn canister(&self) -> &Principal {
            &self.canister
        }
    }

    impl CanisterCaller for MockCose {
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
            self.calls.lock().unwrap().push(CallRecord {
                kind: CallKind::Query,
                canister: *canister,
                method: method.to_string(),
                args: input.clone(),
            });
            let bytes = self.next_response(method, &input)?;
            Ok(Decode!(bytes.as_slice(), Out)?)
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
            self.calls.lock().unwrap().push(CallRecord {
                kind: CallKind::Update,
                canister: *canister,
                method: method.to_string(),
                args: input.clone(),
            });
            let bytes = self.next_response(method, &input)?;
            Ok(Decode!(bytes.as_slice(), Out)?)
        }
    }

    fn principals() -> BTreeSet<Principal> {
        BTreeSet::from([Principal::management_canister()])
    }

    fn strings() -> BTreeSet<String> {
        BTreeSet::from(["state_get_info".to_string()])
    }

    fn public_key_output() -> PublicKeyOutput {
        PublicKeyOutput {
            public_key: ByteBuf::from(vec![1, 2, 3]),
            chain_code: ByteBuf::from(vec![4, 5, 6]),
        }
    }

    fn state_info() -> StateInfo {
        StateInfo {
            name: "ic_cose".to_string(),
            ecdsa_key_name: "ecdsa".to_string(),
            schnorr_key_name: "schnorr".to_string(),
            vetkd_key_name: "vetkd".to_string(),
            vetkd_context_version: 2,
            managers: principals(),
            auditors: principals(),
            allowed_apis: strings(),
            namespace_total: 1,
            subnet_size: 13,
            freezing_threshold: 2,
            ecdsa_public_key: Some(public_key_output()),
            schnorr_ed25519_public_key: Some(public_key_output()),
            schnorr_secp256k1_public_key: Some(public_key_output()),
            governance_canister: Some(Principal::management_canister()),
            low_wasm_memory: false,
        }
    }

    fn namespace_info() -> NamespaceInfo {
        NamespaceInfo {
            name: "namespace_1".to_string(),
            desc: "desc".to_string(),
            created_at: 1,
            updated_at: 2,
            max_payload_size: 1024,
            payload_bytes_total: 10,
            status: 0,
            visibility: 1,
            managers: principals(),
            auditors: principals(),
            users: principals(),
            manager_count: 1,
            auditor_count: 1,
            user_count: 1,
            fixed_delegator_count: 1,
            gas_balance: 100,
            fixed_id_names: BTreeMap::from([("fixed".to_string(), principals())]),
            session_expires_in_ms: 86_400_000,
        }
    }

    fn setting_path() -> SettingPath {
        SettingPath {
            ns: "namespace_1".to_string(),
            user_owned: true,
            subject: Some(Principal::management_canister()),
            key: ByteBuf::from(vec![1, 2, 3]),
            version: 1,
        }
    }

    // PocketIC `test_key_1` master public key. Deserialized directly because
    // `MasterPublicKey::for_pocketic_key` takes the `VetKDKeyId` of the
    // management-canister crate version ic-vetkeys depends on.
    const POCKETIC_TEST_KEY_1: &str = "9069b82c7aae418cef27678291e7f2cb1a008a500eceba7199bffca12421b07c158987c6a22618af3d1958738b2835691028801f7663d311799733286c557c8979184bb62cb559a4d582fca7d2e48b860f08ed6641aef66a059ec891889a6218";

    fn derived_public_key_bytes() -> Vec<u8> {
        let master = crate::vetkeys::MasterPublicKey::deserialize(
            &hex::decode(POCKETIC_TEST_KEY_1).unwrap(),
        )
        .unwrap();
        master
            .derive_canister_key(Principal::management_canister().as_slice())
            .serialize()
    }

    fn setting_info() -> SettingInfo {
        SettingInfo {
            key: ByteBuf::from(vec![1]),
            subject: Principal::management_canister(),
            desc: "setting".to_string(),
            created_at: 1,
            updated_at: 2,
            status: 0,
            version: 1,
            readers: principals(),
            tags: BTreeMap::from([("tag".to_string(), "value".to_string())]),
            dek: Some(ByteBuf::from(vec![7])),
            payload: Some(ByteBuf::from(vec![8])),
        }
    }

    fn archived_payload() -> SettingArchivedPayload {
        SettingArchivedPayload {
            version: 1,
            archived_at: 2,
            deprecated: false,
            payload: Some(ByteBuf::from(vec![1, 2])),
            dek: Some(ByteBuf::from(vec![3, 4])),
        }
    }

    fn create_namespace_input() -> CreateNamespaceInput {
        CreateNamespaceInput {
            name: "namespace_1".to_string(),
            visibility: 1,
            managers: principals(),
            ..Default::default()
        }
    }

    fn update_namespace_input() -> UpdateNamespaceInput {
        UpdateNamespaceInput {
            name: "namespace_1".to_string(),
            status: Some(0),
            visibility: Some(1),
            ..Default::default()
        }
    }

    fn delegators_input() -> NamespaceDelegatorsInput {
        NamespaceDelegatorsInput {
            ns: "namespace_1".to_string(),
            name: "fixed".to_string(),
            delegators: principals(),
        }
    }

    fn sign_input() -> SignInput {
        SignInput {
            ns: "namespace_1".to_string(),
            derivation_path: vec![ByteBuf::from(vec![1])],
            message: ByteBuf::from(vec![2; 32]),
        }
    }

    fn sign_delegation_input() -> SignDelegationInput {
        SignDelegationInput {
            ns: "namespace_1".to_string(),
            name: "fixed".to_string(),
            pubkey: ByteBuf::from(vec![1]),
            sig: ByteBuf::from(vec![2]),
        }
    }

    fn sign_in_response() -> SignInResponse {
        SignInResponse {
            expiration: 123,
            user_key: ByteBufB64::from(vec![1]),
            seed: ByteBufB64::from(vec![2]),
        }
    }

    fn signed_delegation() -> SignedDelegation {
        SignedDelegation {
            delegation: Delegation {
                pubkey: ByteBufB64::from(vec![1]),
                expiration: 123,
                targets: Some(vec![Principal::management_canister()]),
                permissions: None,
            },
            signature: ByteBufB64::from(vec![2]),
        }
    }

    #[derive(Debug)]
    struct StaticHttpService {
        responses: Mutex<VecDeque<(StatusCode, &'static str, Vec<u8>)>>,
    }

    impl StaticHttpService {
        fn new(status: StatusCode, content_type: &'static str, body: Vec<u8>) -> Arc<Self> {
            Arc::new(Self {
                responses: Mutex::new(VecDeque::from([(status, content_type, body)])),
            })
        }
    }

    #[async_trait::async_trait]
    impl HttpService for StaticHttpService {
        async fn call<'a>(
            &'a self,
            req: &'a (dyn Fn() -> Result<http::Request<Bytes>, AgentError> + Send + Sync),
            _max_retries: usize,
            _size_limit: Option<usize>,
        ) -> Result<Response<Bytes>, AgentError> {
            let _ = req()?;
            let (status, content_type, body) = self.responses.lock().unwrap().pop_front().unwrap();
            Ok(Response::builder()
                .status(status)
                .header("content-type", content_type)
                .body(Bytes::from(body))
                .unwrap())
        }
    }

    fn agent_with_response(
        status: StatusCode,
        content_type: &'static str,
        body: Vec<u8>,
    ) -> Arc<Agent> {
        Arc::new(
            Agent::builder()
                .with_url("http://127.0.0.1")
                .with_verify_query_signatures(false)
                .with_arc_http_middleware(StaticHttpService::new(status, content_type, body))
                .build()
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn default_agent_rejects_uncertified_query_responses() {
        let reply = QueryResponse::Replied {
            reply: ReplyResponse {
                arg: encode_one(123u32).unwrap(),
            },
            signatures: vec![],
        };
        let encoded = cbor2::to_vec(&reply).unwrap();
        let service = StaticHttpService::new(StatusCode::OK, "application/cbor", encoded.clone());
        // The fake endpoint cannot provide a certificate for its node keys.
        service.responses.lock().unwrap().push_back((
            StatusCode::OK,
            "application/cbor",
            vec![0xa0],
        ));
        let agent = crate::agent::agent_builder(
            "http://127.0.0.1",
            Arc::new(ic_agent::identity::AnonymousIdentity),
        )
        .with_arc_http_middleware(service)
        .build()
        .unwrap();
        let client = Client::new(Arc::new(agent), Principal::management_canister());
        assert!(client
            .canister_query::<_, u32>(client.canister(), "get", ())
            .await
            .is_err());
        // The same unsigned reply is well-formed and would be accepted if verification were disabled.
        let client = Client::new(
            agent_with_response(StatusCode::OK, "application/cbor", encoded),
            Principal::management_canister(),
        );
        assert_eq!(
            client
                .canister_query::<_, u32>(client.canister(), "get", ())
                .await
                .unwrap(),
            123
        );
    }

    #[tokio::test]
    async fn paginated_sdk_preserves_cursors_and_consensus_read_mode() {
        let sdk = MockCose::new();
        let subject = Principal::from_slice(&[7]);
        let values: Vec<_> = (0u32..1_001)
            .map(|i| (subject, ByteBuf::from(i.to_be_bytes().to_vec())))
            .collect();
        sdk.respond(values[..1_000].to_vec());
        let mut page = sdk
            .namespace_list_setting_keys_v2("namespace_1", true, Some(subject), None, Some(1_000))
            .await
            .unwrap();
        let cursor = page.last().cloned();
        sdk.respond(values[1_000..].to_vec());
        page.extend(
            sdk.namespace_list_setting_keys_v2(
                "namespace_1",
                true,
                Some(subject),
                cursor.clone(),
                Some(1_000),
            )
            .await
            .unwrap(),
        );
        assert_eq!(page, values);
        {
            let calls = sdk.calls();
            assert_eq!(calls[1].method, "namespace_list_setting_keys_v2");
            type KeyPageArgs = (
                String,
                bool,
                Option<Principal>,
                Option<(Principal, ByteBuf)>,
                Option<u32>,
            );
            let args: KeyPageArgs = decode_args(&calls[1].args).unwrap();
            assert_eq!(
                args,
                (
                    "namespace_1".into(),
                    true,
                    Some(subject),
                    cursor,
                    Some(1_000)
                )
            );
        }
        sdk.respond(namespace_info());
        sdk.namespace_get_info_v2("namespace_1", false)
            .await
            .unwrap();
        sdk.respond(vec![subject]);
        assert_eq!(
            sdk.namespace_list_members("namespace_1", "user", None, Some(10))
                .await
                .unwrap(),
            vec![subject]
        );
        sdk.respond(vec!["identity".to_string()]);
        assert_eq!(
            sdk.namespace_list_fixed_identity_names("namespace_1", None, Some(10))
                .await
                .unwrap(),
            vec!["identity"]
        );
        sdk.respond(setting_info());
        sdk.setting_get_consensus(&setting_path()).await.unwrap();
        let calls = sdk.calls();
        assert_eq!(calls.last().unwrap().kind, CallKind::Update);
        assert_eq!(calls.last().unwrap().method, "setting_get");
    }

    #[tokio::test]
    async fn client_agent_adapter_decodes_query_and_surfaces_update_errors() {
        let reply = QueryResponse::Replied {
            reply: ReplyResponse {
                arg: encode_one(123u32).unwrap(),
            },
            signatures: vec![],
        };
        let agent = agent_with_response(
            StatusCode::OK,
            "application/cbor",
            cbor2::to_vec(&reply).unwrap(),
        );
        let client = Client::new(agent, Principal::management_canister());

        assert_eq!(client.canister(), &Principal::management_canister());
        let value: u32 = client
            .canister_query(&Principal::management_canister(), "get", ())
            .await
            .unwrap();
        assert_eq!(value, 123);

        let agent = agent_with_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "text/plain",
            b"nope".to_vec(),
        );
        let client = Client::new(agent, Principal::management_canister());
        let err = client
            .canister_update::<_, u32>(&Principal::management_canister(), "set", ())
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());

        let agent = agent_with_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "text/plain",
            b"nope".to_vec(),
        );
        let client = Client::new(agent, Principal::management_canister());
        assert!(client
            .canister_query::<_, u32>(&Principal::management_canister(), "get", ())
            .await
            .is_err());

        let rejected = QueryResponse::Replied {
            reply: ReplyResponse {
                arg: b"not candid".to_vec(),
            },
            signatures: vec![],
        };
        let agent = agent_with_response(
            StatusCode::OK,
            "application/cbor",
            cbor2::to_vec(&rejected).unwrap(),
        );
        let client = Client::new(agent, Principal::management_canister());
        assert!(client
            .canister_query::<_, u32>(&Principal::management_canister(), "get", ())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn cose_sdk_methods_call_expected_canister_methods() {
        let sdk = MockCose::new();
        let path = setting_path();
        let managers = principals();
        let apis = strings();
        let namespace_input = create_namespace_input();
        let update_namespace = update_namespace_input();
        let delegators = delegators_input();
        let sign = sign_input();
        let sign_identity = SignIdentityInput {
            ns: "namespace_1".to_string(),
            audience: "audience".to_string(),
        };
        let sign_delegation = sign_delegation_input();
        let create_setting = CreateSettingInput {
            payload: Some(ByteBuf::from(vec![1])),
            ..Default::default()
        };
        let update_info = UpdateSettingInfoInput {
            desc: Some("desc".to_string()),
            ..Default::default()
        };
        let update_payload = UpdateSettingPayloadInput {
            payload: Some(ByteBuf::from(vec![2])),
            ..Default::default()
        };
        let create_output = CreateSettingOutput {
            created_at: 1,
            updated_at: 2,
            version: 3,
        };
        macro_rules! respond_unit {
            ($future:expr) => {{
                sdk.respond(());
                $future.await.unwrap();
            }};
        }

        sdk.respond(state_info());
        assert_eq!(sdk.get_state().await.unwrap().name, "ic_cose");

        respond_unit!(sdk.admin_add_managers(&managers));
        respond_unit!(sdk.admin_remove_managers(&managers));
        respond_unit!(sdk.admin_add_auditors(&managers));
        respond_unit!(sdk.admin_remove_auditors(&managers));
        respond_unit!(sdk.admin_add_allowed_apis(&apis));
        respond_unit!(sdk.admin_remove_allowed_apis(&apis));

        sdk.respond(namespace_info());
        assert_eq!(
            sdk.admin_create_namespace(&namespace_input)
                .await
                .unwrap()
                .name,
            "namespace_1"
        );
        sdk.respond(vec![namespace_info()]);
        assert_eq!(
            sdk.admin_list_namespace(Some("namespace_0"), Some(10))
                .await
                .unwrap()
                .len(),
            1
        );

        sdk.respond(public_key_output());
        assert_eq!(
            sdk.ecdsa_public_key(Some(&PublicKeyInput {
                ns: "namespace_1".to_string(),
                derivation_path: vec![ByteBuf::from(vec![1])],
            }))
            .await
            .unwrap()
            .public_key,
            ByteBuf::from(vec![1, 2, 3])
        );
        sdk.respond(ByteBuf::from(vec![1]));
        assert_eq!(sdk.ecdsa_sign(&sign).await.unwrap(), ByteBuf::from(vec![1]));
        sdk.respond(public_key_output());
        sdk.schnorr_public_key(&SchnorrAlgorithm::Ed25519, None)
            .await
            .unwrap();
        sdk.respond(ByteBuf::from(vec![2]));
        sdk.schnorr_sign(&SchnorrAlgorithm::Ed25519, &sign)
            .await
            .unwrap();
        sdk.respond(ByteBuf::from(vec![3]));
        sdk.schnorr_sign_identity(&SchnorrAlgorithm::Ed25519, &sign_identity)
            .await
            .unwrap();

        let ecdh = ECDHInput {
            nonce: [1u8; 12].into(),
            public_key: [2u8; 32].into(),
        };
        assert!(!sdk
            .ecdh_cose_encrypted_key(&path, &ecdh)
            .await
            .unwrap()
            .payload
            .is_empty());
        assert_eq!(
            sdk.get_cose_encrypted_key(&path).await.unwrap(),
            ByteArray::from([9u8; 32])
        );

        sdk.respond(ByteBuf::from(vec![4]));
        assert_eq!(
            sdk.vetkd_public_key(&path).await.unwrap(),
            ByteBuf::from(vec![4])
        );
        sdk.respond(ByteBuf::from(vec![5]));
        assert_eq!(
            sdk.vetkd_encrypted_key(&path, &ByteBuf::from(vec![9]))
                .await
                .unwrap(),
            ByteBuf::from(vec![5])
        );
        sdk.respond(ByteBuf::from(vec![1, 2, 3]));
        sdk.respond(ByteBuf::from(vec![4, 5, 6]));
        assert!(!sdk.vetkey(&path).await.unwrap_err().is_empty());
        sdk.respond(ByteBuf::from(derived_public_key_bytes()));
        sdk.respond(ByteBuf::from(vec![4, 5, 6]));
        assert!(!sdk.vetkey(&path).await.unwrap_err().is_empty());

        sdk.respond(Principal::management_canister());
        assert_eq!(
            sdk.namespace_get_fixed_identity("namespace_1", "fixed")
                .await
                .unwrap(),
            Principal::management_canister()
        );
        sdk.respond(principals());
        assert_eq!(
            sdk.namespace_get_delegators("namespace_1", "fixed")
                .await
                .unwrap(),
            principals()
        );
        sdk.respond(principals());
        assert_eq!(
            sdk.namespace_add_delegator(&delegators).await.unwrap(),
            principals()
        );
        sdk.respond(());
        sdk.namespace_remove_delegator(&delegators).await.unwrap();
        sdk.respond(sign_in_response());
        assert_eq!(
            sdk.namespace_sign_delegation(&sign_delegation)
                .await
                .unwrap()
                .expiration,
            123
        );
        sdk.respond(signed_delegation());
        assert_eq!(
            sdk.get_delegation(&ByteBuf::from(vec![1]), &ByteBuf::from(vec![2]), 3)
                .await
                .unwrap()
                .signature,
            ByteBufB64::from(vec![2])
        );
        sdk.respond(namespace_info());
        sdk.namespace_get_info("namespace_1").await.unwrap();
        // must decode what the canister actually returns: vec record { principal; blob }
        let setting_keys = vec![(Principal::management_canister(), ByteBuf::from(vec![1, 2]))];
        sdk.respond(setting_keys.clone());
        assert_eq!(
            sdk.namespace_list_setting_keys(
                "namespace_1",
                true,
                Some(Principal::management_canister()),
            )
            .await
            .unwrap(),
            setting_keys
        );
        respond_unit!(sdk.namespace_update_info(&update_namespace));
        respond_unit!(sdk.namespace_delete("namespace_1"));
        respond_unit!(sdk.namespace_add_managers("namespace_1", &managers));
        respond_unit!(sdk.namespace_remove_managers("namespace_1", &managers));
        respond_unit!(sdk.namespace_add_auditors("namespace_1", &managers));
        respond_unit!(sdk.namespace_remove_auditors("namespace_1", &managers));
        respond_unit!(sdk.namespace_add_users("namespace_1", &managers));
        respond_unit!(sdk.namespace_remove_users("namespace_1", &managers));
        sdk.respond(true);
        assert!(sdk
            .namespace_is_member("namespace_1", "manager", &Principal::management_canister())
            .await
            .unwrap());
        sdk.respond(100u128);
        assert_eq!(sdk.namespace_top_up("namespace_1", 100).await.unwrap(), 100);

        sdk.respond(setting_info());
        assert_eq!(sdk.setting_get_info(&path).await.unwrap().version, 1);
        sdk.respond(setting_info());
        assert_eq!(sdk.setting_get(&path).await.unwrap().version, 1);
        sdk.respond(archived_payload());
        assert_eq!(
            sdk.setting_get_archived_payload(&path)
                .await
                .unwrap()
                .version,
            1
        );
        sdk.respond(create_output.clone());
        assert_eq!(
            sdk.setting_create(&path, &create_setting)
                .await
                .unwrap()
                .version,
            3
        );
        sdk.respond(create_output.clone());
        assert_eq!(
            sdk.setting_update_info(&path, &update_info)
                .await
                .unwrap()
                .version,
            3
        );
        sdk.respond(create_output);
        assert_eq!(
            sdk.setting_update_payload(&path, &update_payload)
                .await
                .unwrap()
                .version,
            3
        );
        respond_unit!(sdk.setting_add_readers(&path, &managers));
        respond_unit!(sdk.setting_remove_readers(&path, &managers));
        respond_unit!(sdk.setting_delete(&path));

        let calls = sdk.calls();
        assert!(calls
            .iter()
            .any(|call| call.kind == CallKind::Query && call.method == "state_get_info"));
        assert!(calls
            .iter()
            .any(|call| call.kind == CallKind::Update && call.method == "setting_delete"));
        assert!(calls.iter().all(|call| call.canister == sdk.canister));
        let ecdsa_call = calls
            .iter()
            .find(|call| call.method == "ecdsa_public_key")
            .unwrap();
        let (input,): (Option<PublicKeyInput>,) = decode_args(&ecdsa_call.args).unwrap();
        assert_eq!(input.unwrap().ns, "namespace_1");
    }

    #[tokio::test]
    async fn cose_sdk_maps_caller_errors_and_checks_required_subject() {
        let sdk = MockCose::new();
        sdk.respond_err("boom");
        assert!(sdk.get_state().await.unwrap_err().contains("boom"));

        let path = SettingPath {
            subject: None,
            ..setting_path()
        };
        assert_eq!(
            sdk.get_cose_encrypted_key(&path).await.unwrap_err(),
            "subject is required for get_cose_encrypted_key"
        );

        let sdk = MockCose::new();
        sdk.set_ecdh_mode(EcdhMode::InvalidCoseKey);
        assert!(sdk
            .get_cose_encrypted_key(&setting_path())
            .await
            .unwrap_err()
            .starts_with("invalid COSE key:"));

        let sdk = MockCose::new();
        sdk.set_ecdh_mode(EcdhMode::ShortSecret);
        assert_eq!(
            sdk.get_cose_encrypted_key(&setting_path())
                .await
                .unwrap_err(),
            "invalid COSE secret, expected 32 bytes, got 31"
        );
    }
}
