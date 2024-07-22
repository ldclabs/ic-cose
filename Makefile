BUILD_ENV := rust

.PHONY: build-wasm build-did

lint:
	@cargo fmt
	@cargo clippy --all-targets --all-features

fix:
	@cargo clippy --fix --workspace --tests

test:
	@cargo test --workspace -- --nocapture

# cargo install ic-wasm
build-wasm:
	@cargo build --release --target wasm32-unknown-unknown --package ic_cose_canister

# cargo install candid-extractor
build-did:
	candid-extractor target/wasm32-unknown-unknown/release/ic_cose_canister.wasm > src/ic_cose_canister/ic_cose_canister.did