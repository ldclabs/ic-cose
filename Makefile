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
	@cargo build --release --target wasm32-unknown-unknown --package ic_cose_canister --package ic_object_store_canister

# cargo install candid-extractor
build-did:
	candid-extractor target/wasm32-unknown-unknown/release/ic_cose_canister.wasm > src/ic_cose_canister/ic_cose_canister.did
	candid-extractor target/wasm32-unknown-unknown/release/ic_object_store_canister.wasm > src/ic_object_store_canister/ic_object_store_canister.did
	dfx generate
