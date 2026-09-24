use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};
use std::collections::{BTreeMap, BTreeSet};

use crate::validate_str;

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize)]
pub struct StateInfo {
    pub name: String,
    pub managers: BTreeSet<Principal>,
    pub committers: BTreeSet<Principal>,
    pub provisioners: BTreeSet<Principal>,
    pub latest_version: BTreeMap<String, ByteArray<32>>,
    pub latest_version_total: u64,
    pub latest_version_truncated: bool,
    pub wasm_total: u64,
    pub deployed_total: u64,
    pub deployment_logs: u64,
    pub governance_canister: Option<Principal>,
    pub topup_threshold: u128,
    pub topup_amount: u128,
    pub low_wasm_memory: bool,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct WasmInfo {
    pub name: String,
    pub created_at: u64, // in milliseconds
    pub created_by: Principal,
    pub description: String,
    pub wasm: ByteBuf,
    pub hash: ByteArray<32>, // sha256 hash of the stored artifact bytes
    /// SHA-256 of the raw Wasm module after decoding `encoding`.
    pub module_hash: ByteArray<32>,
    pub wasm_size: u64,
    /// Encoding of `wasm`. For `Gzip`, `hash` is the artifact hash and must not
    /// be assumed equal to the module hash reported once installed.
    pub encoding: WasmEncoding,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct WasmMetadata {
    pub name: String,
    pub created_at: u64,
    pub created_by: Principal,
    pub description: String,
    pub hash: ByteArray<32>,
    pub module_hash: ByteArray<32>,
    pub wasm_size: u64,
    pub encoding: WasmEncoding,
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize)]
pub struct AddWasmInput {
    pub name: String,
    pub description: String,
    pub wasm: ByteBuf,
    /// Defaults to [`WasmEncoding::Raw`] when omitted.
    pub encoding: Option<WasmEncoding>,
}

/// Assembles a wasm artifact from chunks staged with `admin_add_wasm_chunk`.
///
/// Lets a module larger than the 2 MiB ingress limit be published, which a
/// single `admin_add_wasm` call cannot do.
#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize)]
pub struct CommitWasmChunksInput {
    pub name: String,
    pub description: String,
    /// Staged chunk hashes, in the order they concatenate.
    pub chunk_hashes: Vec<ByteArray<32>>,
    /// Expected `SHA-256` of the assembled artifact.
    pub artifact_hash: ByteArray<32>,
    pub encoding: Option<WasmEncoding>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct DeployWasmInput {
    pub name: String,
    pub canister: Principal,
    pub args: Option<ByteBuf>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct DeploymentInfo {
    pub log_id: u64,
    pub name: String,
    pub deploy_at: u64, // in milliseconds
    pub canister: Principal,
    pub prev_hash: ByteArray<32>,
    pub wasm_hash: ByteArray<32>,
    pub module_hash: Option<ByteArray<32>>,
    pub args: Option<ByteBuf>,
    pub args_hash: Option<ByteArray<32>>,
    pub args_size: u64,
    pub error: Option<String>,
}

// ----- Provisioning: governance-approved templates and idempotent requests -----

/// Protocol hard cap on the canonical init/upgrade arguments of one request.
pub const MAX_PROVISION_ARGS_BYTES: u32 = 256 * 1024;
/// Protocol hard cap on how many pre-created canisters one template may pool.
pub const MAX_PROVISION_POOL_SIZE: u16 = 32;
/// Number of controllers a provisioning template must fix: the wasm canister
/// itself plus the platform governance canister.
pub const PROVISION_CONTROLLERS: usize = 2;
/// Longest lifetime a request epoch may claim, in milliseconds.
pub const MAX_REQUEST_TTL_MS: u64 = 3_600_000; // 1 hour

/// Domain separators for the hashes this module defines.
pub const PROVISION_TEMPLATE_DOMAIN: &str = "ic-cose:provision-template:v1";
pub const PROVISION_SETTINGS_DOMAIN: &str = "ic-cose:provision-settings:v1";
pub const PROVISION_SUBNET_POLICY_DOMAIN: &str = "ic-cose:provision-subnet-policy:v1";

/// How the stored wasm artifact bytes are encoded.
///
/// The distinction matters because `artifact_hash` covers the bytes this
/// canister stores and transfers, while `module_hash` covers what the management
/// canister reports as installed. For [`WasmEncoding::Gzip`] the two must never
/// be assumed equal.
#[derive(CandidType, Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum WasmEncoding {
    #[default]
    Raw,
    Gzip,
}

/// Canister settings applied to every canister provisioned from a template.
///
/// Held immutably inside the template so a provisioner can never submit its own
/// controllers, allocations or limits.
#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProvisionSettings {
    /// Exactly [`PROVISION_CONTROLLERS`] principals: this canister and the
    /// platform governance canister. The issuer never becomes a controller.
    pub controllers: Vec<Principal>,
    pub compute_allocation: Option<u64>,
    pub memory_allocation: Option<u64>,
    pub freezing_threshold: Option<u64>,
    pub reserved_cycles_limit: Option<u128>,
    pub wasm_memory_limit: Option<u64>,
}

impl ProvisionSettings {
    pub fn validate(&self) -> Result<(), String> {
        if self.controllers.len() != PROVISION_CONTROLLERS {
            return Err(format!(
                "controllers must contain exactly {} principals, got {}",
                PROVISION_CONTROLLERS,
                self.controllers.len()
            ));
        }
        let unique: BTreeSet<&Principal> = self.controllers.iter().collect();
        if unique.len() != self.controllers.len() {
            return Err("controllers must not repeat a principal".to_string());
        }
        if unique.contains(&Principal::anonymous()) {
            return Err("anonymous user is not allowed".to_string());
        }
        if !self.controllers.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err("controllers must be sorted in canonical principal order".to_string());
        }
        if self.compute_allocation.is_some_and(|value| value > 100) {
            return Err("compute_allocation must be in 0..=100".to_string());
        }
        const MAX_MEMORY_BYTES: u64 = 1u64 << 48;
        if self
            .memory_allocation
            .is_some_and(|value| value > MAX_MEMORY_BYTES)
        {
            return Err("memory_allocation exceeds 2^48 bytes".to_string());
        }
        if self
            .wasm_memory_limit
            .is_some_and(|value| value > MAX_MEMORY_BYTES)
        {
            return Err("wasm_memory_limit exceeds 2^48 bytes".to_string());
        }
        Ok(())
    }

    pub fn hash(&self) -> Result<ByteArray<32>, String> {
        crate::canonical_hash(PROVISION_SETTINGS_DOMAIN, self).map(ByteArray::from)
    }
}

/// A governance-approved, immutable provisioning template.
///
/// A provisioner may only name an approved template by `id` and `hash`; every
/// other provisioning parameter is loaded from here, so approving a template is
/// the governance act that fixes which module, settings, controllers, subnet and
/// creation budget allocated to a provisioned canister.
#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProvisionTemplate {
    pub id: String,
    pub wasm_name: String,
    /// Hash of the stored artifact bytes, as recorded by `add_wasm`.
    pub artifact_hash: ByteArray<32>,
    /// Module hash the management canister must report after installation.
    pub expected_module_hash: ByteArray<32>,
    pub encoding: WasmEncoding,
    pub settings: ProvisionSettings,
    /// Subnet to create pool canisters on; `None` uses the local subnet.
    pub subnet: Option<Principal>,
    /// Total cycles attached to canister creation, including the subnet's
    /// creation fee. The new canister receives the remainder.
    pub initial_cycles: u128,
    pub max_init_args_bytes: u32,
    /// How many `Available` canisters this template keeps pre-created.
    pub pool_size: u16,
}

impl ProvisionTemplate {
    pub fn validate(&self) -> Result<(), String> {
        validate_str(&self.id)?;
        validate_str(&self.wasm_name)?;
        self.settings.validate()?;
        if self.max_init_args_bytes == 0 || self.max_init_args_bytes > MAX_PROVISION_ARGS_BYTES {
            return Err(format!(
                "max_init_args_bytes should be in 1..={}",
                MAX_PROVISION_ARGS_BYTES
            ));
        }
        if self.pool_size == 0 || self.pool_size > MAX_PROVISION_POOL_SIZE {
            return Err(format!(
                "pool_size should be in 1..={}",
                MAX_PROVISION_POOL_SIZE
            ));
        }
        if self.initial_cycles == 0 {
            return Err("initial_cycles should be greater than 0".to_string());
        }
        if self.subnet == Some(Principal::anonymous()) {
            return Err("subnet must not be anonymous".to_string());
        }
        Ok(())
    }

    /// Binding hash over every field a provisioner is not allowed to choose.
    pub fn hash(&self) -> Result<ByteArray<32>, String> {
        crate::canonical_hash(PROVISION_TEMPLATE_DOMAIN, self).map(ByteArray::from)
    }

    pub fn subnet_policy_hash(&self) -> Result<ByteArray<32>, String> {
        crate::canonical_hash(PROVISION_SUBNET_POLICY_DOMAIN, &self.subnet).map(ByteArray::from)
    }
}

/// Whether a template's pool may currently create another canister.
#[derive(CandidType, Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum PoolStatus {
    /// No outstanding create; refill is allowed.
    #[default]
    Idle,
    /// A create call is in flight. At most one per template.
    CreatePending,
    /// A create returned an unknown outcome: a canister may exist without this
    /// canister knowing its principal. Refill stays circuit-broken until
    /// governance reconciles.
    CreateUnknown,
}

/// State of one pre-created canister inside a template's pool.
#[derive(CandidType, Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum PoolCanisterState {
    /// Free to be claimed by a reservation.
    #[default]
    Available,
    /// Claimed by a request id, not installed yet.
    Reserved,
    /// Carries an installed module. No longer recorded: an installed canister
    /// leaves the pool, and the variant remains only so old data decodes.
    Installed,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PoolCanisterInfo {
    pub canister: Principal,
    pub state: PoolCanisterState,
    pub created_at: u64,
    pub request_id: Option<ByteArray<32>>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProvisionTemplateInfo {
    pub template: ProvisionTemplate,
    pub hash: ByteArray<32>,
    pub settings_hash: ByteArray<32>,
    pub subnet_policy_hash: ByteArray<32>,
    pub created_at: u64,
    pub created_by: Principal,
    pub pool_status: PoolStatus,
    pub available: u32,
    pub reserved: u32,
    pub installed: u32,
    /// Release tombstones currently retained for this template.
    pub tombstones: u32,
}

/// Claims one pre-created canister for `request_id`.
#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReserveRequest {
    pub request_id: ByteArray<32>,
    pub provision_template_id: String,
    pub provision_template_hash: ByteArray<32>,
    /// Request epoch in milliseconds. Rejected once elapsed, so a request that
    /// outlives its release tombstone can no longer be replayed.
    pub expires_at: u64,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReservationReceipt {
    pub request_id: ByteArray<32>,
    pub owner: Principal,
    pub expires_at: u64,
    pub canister: Principal,
    pub provision_template_id: String,
    pub provision_template_hash: ByteArray<32>,
    pub settings_hash: ByteArray<32>,
    pub controllers: Vec<Principal>,
    pub subnet_policy_hash: ByteArray<32>,
    /// Creation budget committed by the template, inclusive of creation fee.
    pub initial_cycles: u128,
    pub reserved_at: u64,
}

/// Installs the template's module on the canister reserved for `request_id`.
#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct InstallRequest {
    pub request_id: ByteArray<32>,
    /// Must equal the canister named by the reservation receipt.
    pub canister: Principal,
    pub provision_template_id: String,
    pub provision_template_hash: ByteArray<32>,
    /// Module hash the caller committed to. Must equal the template's
    /// `expected_module_hash`: an activation is paid for one exact hash, so
    /// installing anything else would deliver something nobody bought.
    pub expected_module_hash: ByteArray<32>,
    pub init_args: ByteBuf,
    /// `SHA-256(init_args)`.
    pub init_args_hash: ByteArray<32>,
    /// Opaque binding computed by the caller over its own provisioning spec.
    /// Recorded verbatim in the receipt so the caller can prove which spec was
    /// installed; this canister never interprets it.
    pub provision_spec_hash: ByteArray<32>,
    pub expires_at: u64,
}

/// Upgrades an already deployed canister under an exact previous module hash.
#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeploymentRequest {
    pub request_id: ByteArray<32>,
    pub canister: Principal,
    pub wasm_name: String,
    pub artifact_hash: ByteArray<32>,
    pub expected_module_hash: ByteArray<32>,
    /// Compare-and-swap guard: the module hash the canister must currently run.
    pub expected_prev_module_hash: ByteArray<32>,
    pub args: ByteBuf,
    /// `SHA-256(args)`.
    pub args_hash: ByteArray<32>,
    pub expires_at: u64,
}

#[derive(CandidType, Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum ProvisionStage {
    #[default]
    Reserved,
    InstallPending,
    Installed,
    Failed,
    Released,
}

/// Queryable outcome of one `request_id`, durable across response loss.
#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProvisionReceipt {
    pub request_id: ByteArray<32>,
    pub owner: Principal,
    pub expires_at: u64,
    pub stage: ProvisionStage,
    pub canister: Principal,
    pub wasm_name: String,
    /// `None` for upgrades, which are not bound to a provisioning template.
    pub provision_template_id: Option<String>,
    pub provision_template_hash: Option<ByteArray<32>>,
    pub artifact_hash: ByteArray<32>,
    /// Module hash reported by the management canister after installation.
    pub module_hash: Option<ByteArray<32>>,
    /// Module hash the canister ran before an upgrade.
    pub prev_module_hash: Option<ByteArray<32>>,
    pub args_hash: Option<ByteArray<32>>,
    pub provision_spec_hash: Option<ByteArray<32>>,
    pub error: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct BatchCallResult {
    pub canister: Principal,
    pub reply: Option<ByteBuf>,
    pub error: Option<String>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TopupResult {
    pub canister: Principal,
    pub balance_before: Option<u128>,
    pub deposited: u128,
    pub error: Option<String>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReleaseReceipt {
    pub request_id: ByteArray<32>,
    pub canister: Principal,
    pub released_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::{decode_one, encode_one};

    fn assert_candid_roundtrip<T>(value: T)
    where
        T: CandidType
            + Clone
            + std::fmt::Debug
            + PartialEq
            + Serialize
            + for<'de> candid::Deserialize<'de>,
    {
        let encoded = encode_one(value.clone()).unwrap();
        let decoded: T = decode_one(&encoded).unwrap();
        assert_eq!(decoded, value);
        assert!(!crate::to_cbor_bytes(&value).is_empty());
    }

    fn test_settings() -> ProvisionSettings {
        ProvisionSettings {
            controllers: vec![
                Principal::from_slice(&[1, 1]),
                Principal::from_slice(&[2, 2]),
            ],
            ..Default::default()
        }
    }

    fn test_template() -> ProvisionTemplate {
        ProvisionTemplate {
            id: "project_v1".to_string(),
            wasm_name: "project".to_string(),
            artifact_hash: [1u8; 32].into(),
            expected_module_hash: [2u8; 32].into(),
            encoding: WasmEncoding::Raw,
            settings: test_settings(),
            subnet: None,
            initial_cycles: 2_000_000_000_000,
            max_init_args_bytes: MAX_PROVISION_ARGS_BYTES,
            pool_size: 8,
        }
    }

    #[test]
    fn provision_settings_fix_exactly_two_distinct_controllers() {
        assert!(test_settings().validate().is_ok());

        let mut one = test_settings();
        one.controllers.pop();
        assert!(one.validate().unwrap_err().contains("exactly 2"));

        let mut dup = test_settings();
        dup.controllers[1] = dup.controllers[0];
        assert!(dup.validate().unwrap_err().contains("must not repeat"));

        let mut anon = test_settings();
        anon.controllers[1] = Principal::anonymous();
        assert_eq!(
            anon.validate().unwrap_err(),
            "anonymous user is not allowed"
        );
    }

    #[test]
    fn provision_template_validates_and_hashes_its_bindings() {
        let tpl = test_template();
        assert!(tpl.validate().is_ok());
        assert_candid_roundtrip(tpl.clone());

        // the hash must move with every field a provisioner may not choose
        let base = tpl.hash().unwrap();
        let mut other = tpl.clone();
        other.expected_module_hash = [3u8; 32].into();
        assert_ne!(base, other.hash().unwrap());
        let mut other = tpl.clone();
        other.settings.controllers[0] = Principal::from_slice(&[3, 3]);
        assert_ne!(base, other.hash().unwrap());
        assert_ne!(tpl.settings.hash().unwrap(), other.settings.hash().unwrap());
        let mut other = tpl.clone();
        other.initial_cycles += 1;
        assert_ne!(base, other.hash().unwrap());
        let mut other = tpl.clone();
        other.subnet = Some(Principal::management_canister());
        assert_ne!(base, other.hash().unwrap());
        assert_ne!(
            tpl.subnet_policy_hash().unwrap(),
            other.subnet_policy_hash().unwrap()
        );

        let mut bad = tpl.clone();
        bad.id = "Project".to_string();
        assert!(bad.validate().is_err());
        let mut bad = tpl.clone();
        bad.max_init_args_bytes = MAX_PROVISION_ARGS_BYTES + 1;
        assert!(bad.validate().unwrap_err().contains("max_init_args_bytes"));
        let mut bad = tpl.clone();
        bad.pool_size = MAX_PROVISION_POOL_SIZE + 1;
        assert!(bad.validate().unwrap_err().contains("pool_size"));
        let mut bad = tpl.clone();
        bad.initial_cycles = 0;
        assert!(bad.validate().unwrap_err().contains("initial_cycles"));
        let mut bad = tpl;
        bad.subnet = Some(Principal::anonymous());
        assert!(bad.validate().unwrap_err().contains("subnet"));
    }

    #[test]
    fn provisioning_request_types_roundtrip_candid() {
        assert_candid_roundtrip(ReserveRequest {
            request_id: [1u8; 32].into(),
            provision_template_id: "project_v1".to_string(),
            provision_template_hash: [2u8; 32].into(),
            expires_at: 1,
        });
        assert_candid_roundtrip(InstallRequest {
            request_id: [1u8; 32].into(),
            canister: Principal::management_canister(),
            provision_template_id: "project_v1".to_string(),
            provision_template_hash: [2u8; 32].into(),
            expected_module_hash: [3u8; 32].into(),
            init_args: ByteBuf::from(vec![1]),
            init_args_hash: [4u8; 32].into(),
            provision_spec_hash: [5u8; 32].into(),
            expires_at: 1,
        });
        assert_candid_roundtrip(DeploymentRequest {
            request_id: [1u8; 32].into(),
            canister: Principal::management_canister(),
            wasm_name: "project".to_string(),
            artifact_hash: [2u8; 32].into(),
            expected_module_hash: [3u8; 32].into(),
            expected_prev_module_hash: [4u8; 32].into(),
            args: ByteBuf::from(vec![1]),
            args_hash: [5u8; 32].into(),
            expires_at: 1,
        });
        assert_candid_roundtrip(ProvisionReceipt {
            request_id: [1u8; 32].into(),
            owner: Principal::management_canister(),
            expires_at: 10,
            stage: ProvisionStage::Installed,
            canister: Principal::management_canister(),
            wasm_name: "project".to_string(),
            provision_template_id: Some("project_v1".to_string()),
            provision_template_hash: Some([2u8; 32].into()),
            artifact_hash: [3u8; 32].into(),
            module_hash: Some([4u8; 32].into()),
            prev_module_hash: None,
            args_hash: Some([5u8; 32].into()),
            provision_spec_hash: Some([6u8; 32].into()),
            error: None,
            created_at: 1,
            updated_at: 2,
        });
        assert_candid_roundtrip(ReservationReceipt {
            request_id: [1u8; 32].into(),
            owner: Principal::management_canister(),
            expires_at: 10,
            canister: Principal::management_canister(),
            provision_template_id: "project_v1".to_string(),
            provision_template_hash: [2u8; 32].into(),
            settings_hash: [3u8; 32].into(),
            controllers: vec![Principal::management_canister()],
            subnet_policy_hash: [4u8; 32].into(),
            initial_cycles: 1,
            reserved_at: 2,
        });
        assert_candid_roundtrip(ReleaseReceipt {
            request_id: [1u8; 32].into(),
            canister: Principal::management_canister(),
            released_at: 1,
        });
        assert_candid_roundtrip(PoolCanisterInfo {
            canister: Principal::management_canister(),
            state: PoolCanisterState::Available,
            created_at: 1,
            request_id: None,
        });
        assert_candid_roundtrip(ProvisionTemplateInfo {
            template: test_template(),
            hash: [1u8; 32].into(),
            settings_hash: [2u8; 32].into(),
            subnet_policy_hash: [3u8; 32].into(),
            created_at: 1,
            created_by: Principal::management_canister(),
            pool_status: PoolStatus::Idle,
            available: 1,
            reserved: 0,
            installed: 0,
            tombstones: 0,
        });
    }

    #[test]
    fn wasm_types_are_constructible() {
        let state = StateInfo {
            name: "wasm".to_string(),
            managers: BTreeSet::from([Principal::management_canister()]),
            committers: BTreeSet::new(),
            provisioners: BTreeSet::new(),
            latest_version: BTreeMap::from([("module".to_string(), [1u8; 32].into())]),
            latest_version_total: 1,
            latest_version_truncated: false,
            wasm_total: 1,
            deployed_total: 2,
            deployment_logs: 3,
            governance_canister: None,
            topup_threshold: 1,
            topup_amount: 2,
            low_wasm_memory: false,
        };
        assert_eq!(state.latest_version["module"].as_ref(), &[1u8; 32]);
        assert!(!format!("{:?}", state.clone()).is_empty());
        assert!(!encode_one(state).unwrap().is_empty());
        assert!(!crate::to_cbor_bytes(&StateInfo::default()).is_empty());

        let wasm = WasmInfo {
            name: "module".to_string(),
            created_at: 1,
            created_by: Principal::management_canister(),
            description: "desc".to_string(),
            wasm: ByteBuf::from(vec![0, 1]),
            hash: [2u8; 32].into(),
            module_hash: [3u8; 32].into(),
            wasm_size: 2,
            encoding: WasmEncoding::Gzip,
        };
        assert_eq!(wasm.hash.as_ref(), &[2u8; 32]);
        assert!(!format!("{:?}", wasm.clone()).is_empty());
        assert!(!encode_one(wasm.clone()).unwrap().is_empty());
        assert!(!crate::to_cbor_bytes(&wasm).is_empty());

        let add = AddWasmInput {
            name: wasm.name.clone(),
            description: wasm.description.clone(),
            wasm: wasm.wasm.clone(),
            encoding: Some(WasmEncoding::Gzip),
        };
        assert_eq!(add.wasm, ByteBuf::from(vec![0, 1]));
        assert!(!format!("{:?}", add.clone()).is_empty());
        assert!(!encode_one(add.clone()).unwrap().is_empty());
        assert!(!crate::to_cbor_bytes(&add).is_empty());

        let deploy = DeployWasmInput {
            name: "module".to_string(),
            canister: Principal::management_canister(),
            args: Some(ByteBuf::from(vec![3])),
        };
        assert_eq!(deploy.args, Some(ByteBuf::from(vec![3])));
        assert!(!format!("{:?}", deploy.clone()).is_empty());
        assert!(!encode_one(deploy.clone()).unwrap().is_empty());
        assert!(!crate::to_cbor_bytes(&deploy).is_empty());

        let deployment = DeploymentInfo {
            log_id: 1,
            name: "module".to_string(),
            deploy_at: 4,
            canister: Principal::management_canister(),
            prev_hash: [5u8; 32].into(),
            wasm_hash: [6u8; 32].into(),
            module_hash: Some([7u8; 32].into()),
            args: None,
            args_hash: Some([8u8; 32].into()),
            args_size: 0,
            error: Some("failed".to_string()),
        };
        assert_eq!(deployment.error.as_deref(), Some("failed"));
        assert!(!format!("{:?}", deployment.clone()).is_empty());
        assert!(!encode_one(deployment.clone()).unwrap().is_empty());
        assert!(!crate::to_cbor_bytes(&deployment).is_empty());
    }
}
