use coset::{
    cwt::{ClaimName, ClaimsSet, Timestamp},
    iana, CborSerializable,
};
use num_traits::ToPrimitive;

const CLOCK_SKEW: i64 = 5 * 60; // 5 minutes
pub static SCOPE_NAME: ClaimName = ClaimName::Assigned(iana::CwtClaimName::Scope);

pub fn cwt_from_cwt(data: &[u8], now_sec: i64) -> Result<ClaimsSet, String> {
    let claims = ClaimsSet::from_slice(data).map_err(|err| format!("invalid claims: {}", err))?;
    if let Some(ref exp) = claims.expiration_time {
        let exp = match exp {
            Timestamp::WholeSeconds(v) => *v,
            Timestamp::FractionalSeconds(v) => (*v).to_i64().unwrap_or_default(),
        };
        if exp < now_sec - CLOCK_SKEW {
            return Err("token expired".to_string());
        }
    }
    if let Some(ref nbf) = claims.not_before {
        let nbf = match nbf {
            Timestamp::WholeSeconds(v) => *v,
            Timestamp::FractionalSeconds(v) => (*v).to_i64().unwrap_or_default(),
        };
        if nbf > now_sec + CLOCK_SKEW {
            return Err("token not yet valid".to_string());
        }
    }

    Ok(claims)
}

pub fn get_scope(claims: &ClaimsSet) -> Result<String, String> {
    let scope = claims
        .rest
        .iter()
        .find(|(key, _)| key == &SCOPE_NAME)
        .ok_or("missing scope")?;
    let scope = scope.1.as_text().ok_or("invalid scope text")?;
    Ok(scope.to_string())
}
