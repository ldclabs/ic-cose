use ic_agent::{Agent, Identity};
use ic_cose_types::format_error;
use std::sync::Arc;

pub async fn build_agent(host: &str, identity: Arc<dyn Identity>) -> Result<Agent, String> {
    let agent = Agent::builder()
        .with_url(host)
        .with_arc_identity(identity)
        .with_verify_query_signatures(true)
        // .with_background_dynamic_routing()
        .build()
        .map_err(format_error)?;
    if host.starts_with("http://") {
        agent.fetch_root_key().await.map_err(format_error)?;
    }

    Ok(agent)
}
