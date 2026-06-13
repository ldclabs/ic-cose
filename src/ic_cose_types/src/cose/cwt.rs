use coset::{iana, CborSerializable};
use num_traits::ToPrimitive;

pub use coset::cwt::*;

const CLOCK_SKEW: i64 = 5 * 60; // 5 minutes
pub static SCOPE_NAME: ClaimName = ClaimName::Assigned(iana::CwtClaimName::Scope);

/// Parses and validates a CWT (CBOR Web Token) from raw bytes.
///
/// # Arguments
/// * `data` - Raw CBOR-encoded CWT data
/// * `now_sec` - Current timestamp in seconds for validation
///
/// # Returns
/// * `Ok(ClaimsSet)` if token is valid
/// * `Err(String)` if token is invalid or expired
///
/// # Validation
/// * Checks expiration time (exp) with 5-minute clock skew
/// * Checks not-before time (nbf) with 5-minute clock skew
pub fn cwt_from(data: &[u8], now_sec: i64) -> Result<ClaimsSet, String> {
    let claims = ClaimsSet::from_slice(data).map_err(|err| format!("invalid claims: {}", err))?;
    if let Some(ref exp) = claims.expiration_time {
        if timestamp_secs(exp)? < now_sec - CLOCK_SKEW {
            return Err("token expired".to_string());
        }
    }
    if let Some(ref nbf) = claims.not_before {
        if timestamp_secs(nbf)? > now_sec + CLOCK_SKEW {
            return Err("token not yet valid".to_string());
        }
    }

    Ok(claims)
}

/// Converts a CWT timestamp to whole seconds, rejecting values (NaN, infinity,
/// out of i64 range) that cannot be compared against the current time.
fn timestamp_secs(ts: &Timestamp) -> Result<i64, String> {
    match ts {
        Timestamp::WholeSeconds(v) => Ok(*v),
        Timestamp::FractionalSeconds(v) => v
            .to_i64()
            .ok_or_else(|| "invalid timestamp value".to_string()),
    }
}

/// Extracts scope claim from CWT claims set.
///
/// # Arguments
/// * `claims` - CWT claims set to search
///
/// # Returns
/// * `Ok(String)` with scope value if found and valid
/// * `Err(String)` if scope is missing or invalid
pub fn get_scope(claims: &ClaimsSet) -> Result<String, String> {
    let scope = claims
        .rest
        .iter()
        .find(|(key, _)| key == &SCOPE_NAME)
        .ok_or("missing scope")?;
    let scope = scope.1.as_text().ok_or("invalid scope text")?;
    Ok(scope.to_string())
}

#[cfg(test)]
mod test {
    use super::*;
    use coset::cbor::value::Value;
    use hex::decode;

    #[test]
    fn cwt_works() {
        let data = decode("a801781b35336379672d79796161612d61616161702d61687075612d63616902783f693267616d2d75756533792d75787779642d6d7a7968622d6e697268642d687a336c342d32687733662d34667a76772d6c707676632d64716472672d3771650366746573746572041a66d11526051a66d10716061a66d10716075029420f3d16231d2de11fb7c33bbe971e096d4e616d6573706163652e2a3a5f").unwrap();
        let claims = cwt_from(&data, 1724974880).unwrap();
        assert_eq!(
            claims.issuer,
            Some("53cyg-yyaaa-aaaap-ahpua-cai".to_string())
        );
        assert_eq!(
            claims.subject,
            Some("i2gam-uue3y-uxwyd-mzyhb-nirhd-hz3l4-2hw3f-4fzvw-lpvvc-dqdrg-7qe".to_string())
        );
        assert_eq!(claims.audience, Some("tester".to_string()));
        assert_eq!(get_scope(&claims).unwrap(), "Namespace.*:_");
    }

    #[test]
    fn cwt_rejects_invalid_time_windows_and_scope() {
        let expired = ClaimsSet {
            expiration_time: Some(Timestamp::WholeSeconds(1_000)),
            ..Default::default()
        }
        .to_vec()
        .unwrap();
        assert_eq!(cwt_from(&expired, 2_000).unwrap_err(), "token expired");

        let not_yet_valid = ClaimsSet {
            not_before: Some(Timestamp::FractionalSeconds(2_000.0)),
            ..Default::default()
        }
        .to_vec()
        .unwrap();
        assert_eq!(
            cwt_from(&not_yet_valid, 1_000).unwrap_err(),
            "token not yet valid"
        );

        let valid_fractional_exp = ClaimsSet {
            expiration_time: Some(Timestamp::FractionalSeconds(2_000.0)),
            not_before: Some(Timestamp::WholeSeconds(1_000)),
            ..Default::default()
        }
        .to_vec()
        .unwrap();
        assert!(cwt_from(&valid_fractional_exp, 1_500).is_ok());

        let no_time_claims = ClaimsSet::default().to_vec().unwrap();
        assert!(cwt_from(&no_time_claims, 1_500).is_ok());

        let nan_nbf = ClaimsSet {
            not_before: Some(Timestamp::FractionalSeconds(f64::NAN)),
            ..Default::default()
        }
        .to_vec()
        .unwrap();
        assert_eq!(
            cwt_from(&nan_nbf, 1_000).unwrap_err(),
            "invalid timestamp value"
        );

        let inf_exp = ClaimsSet {
            expiration_time: Some(Timestamp::FractionalSeconds(f64::INFINITY)),
            ..Default::default()
        }
        .to_vec()
        .unwrap();
        assert_eq!(
            cwt_from(&inf_exp, 1_000).unwrap_err(),
            "invalid timestamp value"
        );

        let scoped = ClaimsSet {
            rest: vec![(SCOPE_NAME.clone(), Value::Integer(1.into()))],
            ..Default::default()
        };
        assert_eq!(
            get_scope(&ClaimsSet::default()).unwrap_err(),
            "missing scope"
        );
        assert_eq!(get_scope(&scoped).unwrap_err(), "invalid scope text");
        assert!(cwt_from(b"not cbor", 1_000)
            .unwrap_err()
            .starts_with("invalid claims:"));
    }
}
