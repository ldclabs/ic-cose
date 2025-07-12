use candid::Principal;
use ic_agent::{identity::BasicIdentity, Identity};
use ic_cose::agent::build_agent;
use ic_cose::client::{Client, CoseSDK};
use ic_cose::rand_bytes;
use ic_cose::vetkeys::{IbeCiphertext, IbeIdentity, IbeSeed};
use ic_cose_types::types::SettingPath;
use std::sync::Arc;

const IS_LOCAL: bool = false;

// cargo run --example vetkeys
#[tokio::main]
async fn main() {
    let canister = Principal::from_text("53cyg-yyaaa-aaaap-ahpua-cai").unwrap();
    let sk =
        hex::decode("5b3770cbfd16d3ac610cc3cda0bc292a448f2c78d6634de6ee280df0a65e4c04").unwrap();
    let sk: [u8; 32] = sk.try_into().unwrap();
    let id = BasicIdentity::from_raw_key(&sk);
    println!("Principal: {}", id.sender().unwrap());
    // "pxfqr-x3orr-z5yip-7yzdd-hyxgd-dktgh-3awsk-ohzma-lfjzi-753j7-tae"

    let host = if IS_LOCAL {
        "http://127.0.0.1:4943"
    } else {
        "https://icp-api.io"
    };
    let agent = build_agent(host, Arc::new(id)).await.unwrap();
    let cli = Client::new(Arc::new(agent), canister);

    let key = vec![0u8, 1, 2, 3].into();
    let path = SettingPath {
        ns: "_".to_string(),
        user_owned: true,
        subject: None,
        key,
        version: 1,
    };

    let (vk, dpk) = cli.vetkey(&path).await.unwrap();
    println!("VetKey: {:?}", hex::encode(vk.signature_bytes()));
    // VetKey: "8a4554dec6eeb1ab95574005c477ed5a8dadb0acb5d4c7c911771a16d974bcd61db63bd2a89eeb174fc96b58ca9d5eca"
    println!("Derived Public Key: {:?}", hex::encode(dpk.serialize()));
    // Derived Public Key: "81b09cdf3a525448978fd72532e19b9fbc8ec7d025af4b5fa2c1f85ef007fdb8946be1ccc288c623acf1bf1fa43cac5f1098012a4f91663eaa73894487c94b4b335af8a224e9e30ca136bad8bfdc2b7fc16f0424f66e88553713852ea04b27a8"

    let ibe_seed: [u8; 32] = rand_bytes();
    let ibe_seed = IbeSeed::from_bytes(&ibe_seed).unwrap();
    let ibe_id = IbeIdentity::from_bytes(&path.key);
    let msg = b"Hello, LDC Labs!";
    let ciphertext = IbeCiphertext::encrypt(&dpk, &ibe_id, msg, &ibe_seed);
    let data = ciphertext.serialize();
    println!("Ciphertext: {:?}", hex::encode(&data));

    let ciphertext = IbeCiphertext::deserialize(&data).unwrap();
    let decrypted = ciphertext.decrypt(&vk).unwrap();
    assert_eq!(&decrypted, msg);
}
