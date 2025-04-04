use rand::RngCore;

pub mod agent;
pub mod client;

pub fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut rng = rand::rng();
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {}
}
