use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

pub fn ecdh_x25519(secret: [u8; 32], their_public: [u8; 32]) -> (SharedSecret, PublicKey) {
    let secret = StaticSecret::from(secret);
    let public = PublicKey::from(&secret);
    (
        secret.diffie_hellman(&PublicKey::from(their_public)),
        public,
    )
}
