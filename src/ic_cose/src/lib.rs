use rand::Rng;

pub mod agent;
pub mod client;
pub mod vetkeys;

pub fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut rng = rand::rng();
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rand_bytes_returns_requested_length() {
        let bytes: [u8; 32] = rand_bytes();
        assert_eq!(bytes.len(), 32);
    }
}
