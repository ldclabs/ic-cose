use ic_agent::{Agent, Identity};
use ic_cose_types::format_error;
use std::sync::Arc;

pub(crate) fn agent_builder(
    host: &str,
    identity: Arc<dyn Identity>,
) -> ic_agent::agent::AgentBuilder {
    Agent::builder().with_url(host).with_arc_identity(identity)
}

/// Builds an agent with query signature verification and the pinned IC root key.
/// Use [`build_local_agent`] explicitly for a local replica. Query signatures
/// authenticate a replica's reply; use update calls when consensus is required.
pub async fn build_agent(host: &str, identity: Arc<dyn Identity>) -> Result<Agent, String> {
    let agent = agent_builder(host, identity);

    let agent = if host.starts_with("https://") {
        agent
            .with_background_dynamic_routing()
            .build()
            .map_err(format_error)?
    } else {
        agent.build().map_err(format_error)?
    };

    Ok(agent)
}

/// Builds an agent for a trusted local replica, fetching its development root key.
/// Do not use this helper for mainnet or an untrusted endpoint.
pub async fn build_local_agent(host: &str, identity: Arc<dyn Identity>) -> Result<Agent, String> {
    let agent = agent_builder(host, identity)
        .build()
        .map_err(format_error)?;
    agent.fetch_root_key().await.map_err(format_error)?;
    Ok(agent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_agent::identity::AnonymousIdentity;

    #[tokio::test]
    async fn build_agent_accepts_https_without_fetching_root_key() {
        let agent = build_agent("https://ic0.app", Arc::new(AnonymousIdentity))
            .await
            .unwrap();
        assert!(format!("{agent:?}").contains("Agent"));
    }

    #[tokio::test]
    async fn build_agent_preserves_root_key_even_for_http() {
        let agent = build_agent("http://127.0.0.1:9", Arc::new(AnonymousIdentity))
            .await
            .unwrap();
        let default_agent = Agent::builder()
            .with_url("http://127.0.0.1:9")
            .build()
            .unwrap();
        assert_eq!(agent.read_root_key(), default_agent.read_root_key());
    }

    #[tokio::test]
    async fn build_local_agent_reports_root_key_fetch_errors() {
        let err = build_local_agent("http://127.0.0.1:9", Arc::new(AnonymousIdentity))
            .await
            .unwrap_err();
        assert!(!err.is_empty());
    }
}
