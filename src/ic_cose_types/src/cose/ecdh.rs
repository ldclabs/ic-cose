use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

pub fn ecdh_x25519(secret: [u8; 32], their_public: [u8; 32]) -> (SharedSecret, PublicKey) {
    let secret = StaticSecret::from(secret);
    let public = PublicKey::from(&secret);
    (
        secret.diffie_hellman(&PublicKey::from(their_public)),
        public,
    )
}

#[cfg(test)]
mod test {
    use candid::Principal;
    use const_hex::{decode, encode};

    use super::*;
    use crate::cose::{encrypt0::cose_decrypt0, get_cose_key_secret, CborSerializable, CoseKey};

    #[test]
    fn ecdh_works() {
        let subject =
            Principal::from_text("i2gam-uue3y-uxwyd-mzyhb-nirhd-hz3l4-2hw3f-4fzvw-lpvvc-dqdrg-7qe")
                .unwrap();
        let aad = subject.as_slice();

        // ecdh_cose_encrypted_key request 1:
        let secret: [u8; 32] =
            decode("65775d6e01b640d83a042466b06c0e77796f5367e243cc51e3b741f4bd3aa227")
                .unwrap()
                .try_into()
                .unwrap();
        let xpub = PublicKey::from(&StaticSecret::from(secret));
        println!("xpub: {:?}", encode(xpub.as_bytes()));
        // 6233976850d2fc6ab653306b332dde4389a4e87b79d521a331683cf90102c478

        // dfx canister call ic_cose_canister ecdh_cose_encrypted_key '(record {
        //     ns = "_";
        //     key = blob "\01\02\03\04";
        //     subject = null;
        //     version = 0;
        //     user_owned = true;
        //   }, record { public_key = blob "\62\33\97\68\50\d2\fc\6a\b6\53\30\6b\33\2d\de\43\89\a4\e8\7b\79\d5\21\a3\31\68\3c\f9\01\02\c4\78"; nonce = blob "\72\ca\b0\8a\fb\f3\32\eb\2b\b1\da\8d"})' --ic
        let their_public: [u8; 32] =
            decode("d391bdd98bb760fa0f0ca4c04711fb6fff3160e243483f9613b9c572c0398074")
                .unwrap()
                .try_into()
                .unwrap();
        let (shared_secret, _) = ecdh_x25519(secret, their_public);
        let payload = decode("d08343a10103a1054c72cab08afbf332eb2bb1da8d583e4aa106b6803554e97b5027b2d7c53c61ce130620088d79d0839a6a8b61424ecd2c69f2ad26a91ee31bcb1b65d32130cc3e585f741a7c0e91c1f1f03172a8").unwrap();
        let cose_key = cose_decrypt0(&payload, shared_secret.as_bytes(), aad).unwrap();
        println!("cose_key: {:?}", encode(&cose_key));
        let cose_key = CoseKey::from_slice(&cose_key).unwrap();
        let kek = get_cose_key_secret(cose_key).unwrap();
        println!("kek: {:?}", encode(&kek));

        // ecdh_cose_encrypted_key request 2:
        let secret: [u8; 32] =
            decode("65775d6e01b640d83a042466b06c0e77796f5367e243cc51e3b741f4bd3aa228")
                .unwrap()
                .try_into()
                .unwrap();
        let xpub = PublicKey::from(&StaticSecret::from(secret));
        println!("xpub: {:?}", encode(xpub.as_bytes()));
        // d50defd7d7cc946b828aaa4db70fe6f99f259f8a58802290b9b21f32f417fb4d

        // dfx canister call ic_cose_canister ecdh_cose_encrypted_key '(record {
        //     ns = "_";
        //     key = blob "\01\02\03\04";
        //     subject = null;
        //     version = 0;
        //     user_owned = true;
        //   }, record { public_key = blob "\d5\0d\ef\d7\d7\cc\94\6b\82\8a\aa\4d\b7\0f\e6\f9\9f\25\9f\8a\58\80\22\90\b9\b2\1f\32\f4\17\fb\4d"; nonce = blob "\72\ca\b0\8a\fb\f3\32\eb\2b\b1\da\88"})' --ic
        let their_public: [u8; 32] =
            decode("dfca9cf65bb0b0a3e4197098cfb5891efab9d8ed135b49dea80f1aeeab557263")
                .unwrap()
                .try_into()
                .unwrap();
        let (shared_secret, _) = ecdh_x25519(secret, their_public);
        let payload = decode("d08343a10103a1054c72cab08afbf332eb2bb1da88583e74b2537cd28f81be717e209acb81323b070cfbc4d44df08a525bdc17698e70b84e665d7fa98d1aa168570d3fd2d7dd3eadcc390107102969e2e613eb6a87").unwrap();
        let cose_key = cose_decrypt0(&payload, shared_secret.as_bytes(), aad).unwrap();
        println!("cose_key: {:?}", encode(&cose_key));
        let cose_key = CoseKey::from_slice(&cose_key).unwrap();
        let kek2 = get_cose_key_secret(cose_key).unwrap();
        println!("kek2: {:?}", encode(&kek2));
        assert_eq!(kek, kek2);
    }
}
