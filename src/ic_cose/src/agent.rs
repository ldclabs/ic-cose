use ic_agent::{Agent, Identity};
use ic_cose_types::format_error;
use std::sync::Arc;

pub async fn build_agent(host: &str, identity: Arc<dyn Identity>) -> Result<Agent, String> {
    let agent = Agent::builder()
        .with_url(host)
        .with_arc_identity(identity)
        .with_verify_query_signatures(false);

    let agent = if host.starts_with("https://") {
        agent
            .with_background_dynamic_routing()
            .build()
            .map_err(format_error)?
    } else {
        agent.build().map_err(format_error)?
    };

    if host.starts_with("http://") {
        agent.fetch_root_key().await.map_err(format_error)?;
    }

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
    async fn build_agent_reports_http_root_key_fetch_errors() {
        let err = build_agent("http://127.0.0.1:9", Arc::new(AnonymousIdentity))
            .await
            .unwrap_err();
        assert!(!err.is_empty());
    }
}
