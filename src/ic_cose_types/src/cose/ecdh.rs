pub use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

/// Performs X25519 Elliptic Curve Diffie-Hellman key exchange.
///
/// # Arguments
/// * `secret` - 32-byte private key
/// * `their_public` - 32-byte public key of the other party
///
/// # Returns
/// A tuple containing:
/// * Shared secret for symmetric encryption
/// * Public key corresponding to the input secret
///
/// # Security
/// This function does not reject low-order public keys, so the resulting
/// shared secret may be the all-zero value known to third parties.
/// Prefer [`try_ecdh_x25519`] when `their_public` comes from an untrusted peer.
pub fn ecdh_x25519(secret: [u8; 32], their_public: [u8; 32]) -> (SharedSecret, PublicKey) {
    let secret = StaticSecret::from(secret);
    let public = PublicKey::from(&secret);
    (
        secret.diffie_hellman(&PublicKey::from(their_public)),
        public,
    )
}

/// Performs X25519 ECDH key exchange, rejecting non-contributory exchanges.
///
/// Unlike [`ecdh_x25519`], this fails if `their_public` is a low-order point,
/// which would yield an all-zero shared secret predictable by third parties.
///
/// # Arguments
/// * `secret` - 32-byte private key
/// * `their_public` - 32-byte public key of the other party
///
/// # Returns
/// A tuple containing:
/// * Shared secret for symmetric encryption
/// * Public key corresponding to the input secret
pub fn try_ecdh_x25519(
    secret: [u8; 32],
    their_public: [u8; 32],
) -> Result<(SharedSecret, PublicKey), String> {
    let secret = StaticSecret::from(secret);
    let public = PublicKey::from(&secret);
    let shared_secret = secret.diffie_hellman(&PublicKey::from(their_public));
    if !shared_secret.was_contributory() {
        return Err("non-contributory X25519 key exchange: low-order public key".to_string());
    }
    Ok((shared_secret, public))
}

#[cfg(test)]
mod test {
    use candid::Principal;
    use hex::{decode, encode};

    use super::*;
    use crate::cose::{encrypt0::cose_decrypt0, get_cose_key_secret, CoseKey};

    #[test]
    fn try_ecdh_x25519_rejects_low_order_public_keys() {
        let secret = [7u8; 32];
        let their_secret = StaticSecret::from([8u8; 32]);
        let their_public = PublicKey::from(&their_secret);

        let (shared_secret, public) = try_ecdh_x25519(secret, their_public.to_bytes()).unwrap();
        let (expected, expected_public) = ecdh_x25519(secret, their_public.to_bytes());
        assert_eq!(shared_secret.as_bytes(), expected.as_bytes());
        assert_eq!(public, expected_public);

        // the identity point is a low-order point: the exchange is non-contributory
        let low_order = [0u8; 32];
        assert_eq!(
            try_ecdh_x25519(secret, low_order).err(),
            Some("non-contributory X25519 key exchange: low-order public key".to_string())
        );
    }

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
