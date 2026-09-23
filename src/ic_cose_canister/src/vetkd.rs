use sha3::Digest;

pub fn derivation_path_to_context(
    version: u8,
    derivation_path: &[&[u8]],
) -> Result<Vec<u8>, String> {
    let mut hasher = sha3::Sha3_256::new();
    match version {
        1 => {
            for path in derivation_path {
                hasher.update(path);
            }
        }
        2 => {
            hasher.update(b"ic-cose:vetkd-context:v2");
            for path in derivation_path {
                hasher.update((path.len() as u64).to_be_bytes());
                hasher.update(path);
            }
        }
        _ => return Err("unsupported vetKD context version".to_string()),
    }
    let rt: [u8; 32] = hasher.finalize().into();
    Ok(rt.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_context_preserves_component_boundaries() {
        assert_eq!(
            derivation_path_to_context(1, &[b"ab", b"c"]).unwrap(),
            derivation_path_to_context(1, &[b"a", b"bc"]).unwrap()
        );
        assert_ne!(
            derivation_path_to_context(2, &[b"ab", b"c"]).unwrap(),
            derivation_path_to_context(2, &[b"a", b"bc"]).unwrap()
        );
        assert!(derivation_path_to_context(3, &[]).is_err());
    }
}
