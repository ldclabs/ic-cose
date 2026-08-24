use ic_agent::{Agent, Identity};
use ic_cose_types::format_error;
use std::sync::Arc;

/// Builds an [`Agent`] for the given host.
///
/// # Security
///
/// Query signature verification is **disabled**, so query responses are not
/// authenticated: whoever serves the request can return arbitrary data for any
/// query call. That matters for the query endpoints whose answers are trusted
/// downstream — `ecdsa_public_key` and `schnorr_public_key` are used to verify
/// signatures, and `namespace_get_fixed_identity` returns a principal used for
/// authorization. Update calls (`ecdh_cose_encrypted_key`, `vetkd_*`, every
/// write) go through consensus and are unaffected.
///
/// If your deployment needs verified queries, construct the [`Agent`] yourself
/// without `with_verify_query_signatures(false)` and pass it to
/// [`crate::client::Client::new`].
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
