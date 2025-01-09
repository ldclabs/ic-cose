use candid::{
    utils::{encode_args, ArgumentEncoder},
    CandidType, Decode, Principal,
};
use ic_agent::{Agent, Identity};
use ic_cose_types::format_error;
use std::sync::Arc;

/// Creates and configures an IC agent with the given host URL and identity.
/// 
/// # Arguments
/// * `host` - The IC host URL (e.g., "https://ic0.app" or "http://localhost:8000")
/// * `identity` - Arc-wrapped identity for authentication
/// 
/// # Returns
/// Result containing the configured Agent or an error string
/// 
/// # Notes
/// - Automatically fetches root key for local development (http:// URLs)
/// - Enables query signature verification by default
pub async fn build_agent(host: &str, identity: Arc<dyn Identity>) -> Result<Agent, String> {
    let agent = Agent::builder()
        .with_url(host)
        .with_arc_identity(identity)
        .with_verify_query_signatures(true)
        .build()
        .map_err(format_error)?;
    if host.starts_with("http://") {
        agent.fetch_root_key().await.map_err(format_error)?;
    }

    Ok(agent)
}

/// Makes an update call to a canister and waits for the result.
///
/// # Arguments
/// * `agent` - IC agent instance
/// * `canister_id` - Target canister principal
/// * `method_name` - Canister method to call
/// * `args` - Input arguments (must implement ArgumentEncoder)
///
/// # Returns
/// Result with decoded output or error string
///
/// # Notes
/// - Update calls modify canister state
/// - Automatically waits for execution completion
pub async fn update_call<In, Out>(
    agent: &Agent,
    canister_id: &Principal,
    method_name: &str,
    args: In,
) -> Result<Out, String>
where
    In: ArgumentEncoder + Send,
    Out: CandidType + for<'a> candid::Deserialize<'a>,
{
    let input = encode_args(args).map_err(format_error)?;
    let res = agent
        .update(canister_id, method_name)
        .with_arg(input)
        .call_and_wait()
        .await
        .map_err(format_error)?;
    let output = Decode!(res.as_slice(), Out).map_err(format_error)?;
    Ok(output)
}

/// Makes a query call to a canister and returns the result.
///
/// # Arguments
/// * `agent` - IC agent instance
/// * `canister_id` - Target canister principal
/// * `method_name` - Canister method to call
/// * `args` - Input arguments (must implement ArgumentEncoder)
///
/// # Returns
/// Result with decoded output or error string
///
/// # Notes
/// - Query calls are read-only and don't modify canister state
/// - Executes immediately without waiting for consensus
pub async fn query_call<In, Out>(
    agent: &Agent,
    canister_id: &Principal,
    method_name: &str,
    args: In,
) -> Result<Out, String>
where
    In: ArgumentEncoder + Send,
    Out: CandidType + for<'a> candid::Deserialize<'a>,
{
    let input = encode_args(args).map_err(format_error)?;
    let res = agent
        .query(canister_id, method_name)
        .with_arg(input)
        .call()
        .await
        .map_err(format_error)?;
    let output = Decode!(res.as_slice(), Out).map_err(format_error)?;
    Ok(output)
}
