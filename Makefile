BUILD_ENV := rust

.PHONY: build-wasm build-did

lint:
	@cargo fmt
	@cargo clippy --all-targets --all-features

fix:
	@cargo clippy --fix --workspace --tests

test:
	@cargo test --workspace --all-features -- --nocapture

# cargo install ic-wasm
build-wasm:
	@cargo build --release --target wasm32-unknown-unknown -p ic_cose_canister -p ic_wasm_canister

build-wasm64:
	@cargo +nightly build -Z build-std=std,panic_abort --target wasm64-unknown-unknown --release -p ic_cose_canister -p ic_wasm_canister

# cargo install candid-extractor
build-did:
	candid-extractor target/wasm32-unknown-unknown/release/ic_cose_canister.wasm > src/ic_cose_canister/ic_cose_canister.did
	candid-extractor target/wasm32-unknown-unknown/release/ic_wasm_canister.wasm > src/ic_wasm_canister/ic_wasm_canister.did
	dfx generate
