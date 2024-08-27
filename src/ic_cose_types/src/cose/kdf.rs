use coset::{iana, CborSerializable, CoseKdfContextBuilder, HeaderBuilder, SuppPubInfoBuilder};
use hkdf::Hkdf;
use sha2::Sha256;

// HKDF-SHA-256
pub fn hkdf256<const N: usize>(secret: &[u8], salt: Option<&[u8]>, info: &[u8]) -> [u8; N] {
    let mut output = [0u8; N];
    let hkdf = Hkdf::<Sha256>::new(salt, secret);
    hkdf.expand(info, &mut output).expect("HKDF failed");
    output
}

// HKDF-SHA-256 with Context Information Structure
// https://datatracker.ietf.org/doc/html/rfc9053#name-context-information-structu
pub fn hkdf256_context(secret: &[u8], salt: Option<&[u8]>, ecdh: bool) -> [u8; 32] {
    let ctx = CoseKdfContextBuilder::new()
        .algorithm(iana::Algorithm::A256GCM)
        .supp_pub_info(
            SuppPubInfoBuilder::new()
                .key_data_length(256)
                .protected(
                    HeaderBuilder::new()
                        .algorithm(if ecdh {
                            iana::Algorithm::ECDH_ES_HKDF_256
                        } else {
                            iana::Algorithm::Direct_HKDF_SHA_256
                        })
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
