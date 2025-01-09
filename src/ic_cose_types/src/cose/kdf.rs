use coset::{iana, CborSerializable, CoseKdfContextBuilder, HeaderBuilder, SuppPubInfoBuilder};
use hkdf::Hkdf;
use sha2::Sha256;

/// Derives a key using HKDF-SHA-256 (RFC 5869)
///
/// # Arguments
/// * `secret` - Input keying material (IKM)
/// * `salt` - Optional salt value (can improve security)
/// * `info` - Context and application specific information
///
/// # Returns
/// Derived key of length `N` bytes
///
/// # Panics
/// If HKDF expansion fails (e.g., output length too large)
pub fn hkdf256<const N: usize>(secret: &[u8], salt: Option<&[u8]>, info: &[u8]) -> [u8; N] {
    let mut output = [0u8; N];
    let hkdf = Hkdf::<Sha256>::new(salt, secret);
    hkdf.expand(info, &mut output).expect("HKDF failed");
    output
}

/// Derives a 256-bit key for AES-GCM using HKDF-SHA-256 with COSE context
/// 
/// https://datatracker.ietf.org/doc/html/rfc9053#name-context-information-structu
///
/// # Arguments
/// * `secret` - Input key material (IKM)
/// * `salt` - Optional salt value (can improve security)
///
/// # Returns
/// 32-byte derived key suitable for AES-256-GCM
///
/// # Panics
/// If context serialization or HKDF expansion fails
pub fn derive_a256gcm_key(secret: &[u8], salt: Option<&[u8]>) -> [u8; 32] {
    let ctx = CoseKdfContextBuilder::new()
        .algorithm(iana::Algorithm::A256GCM)
        .supp_pub_info(
            SuppPubInfoBuilder::new()
                .key_data_length(256)
                .protected(
                    HeaderBuilder::new()
                        .algorithm(iana::Algorithm::Direct_HKDF_SHA_256)
                        .build(),
                )
                .build(),
        )
        .build();
    let info = ctx.to_vec().expect("failed to serialize context");
    hkdf256(secret, salt, &info)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn hkdf256_work() {
        // https://github.com/cose-wg/Examples/blob/master/ecdh-direct-examples/p256-hkdf-256-01.json
        let ctx = CoseKdfContextBuilder::new()
            .algorithm(iana::Algorithm::A128GCM)
            .supp_pub_info(
                SuppPubInfoBuilder::new()
                    .key_data_length(128)
                    .protected(
                        HeaderBuilder::new()
                            .algorithm(iana::Algorithm::ECDH_ES_HKDF_256)
                            .build(),
                    )
                    .build(),
            )
            .build();
        let info = ctx.to_vec().expect("failed to serialize context");
        let secret =
            const_hex::decode("4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6")
                .unwrap();
        let res = hkdf256::<16>(&secret, None, &info);
        println!("{:?}", res);
        assert_eq!(
            res,
            const_hex::decode_to_array("56074D506729CA40C4B4FE50C6439893").unwrap()
        );
    }
}
