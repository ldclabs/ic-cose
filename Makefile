BUILD_ENV := rust

# getrandom has no backend for wasm32/64-unknown-unknown by default. The
# canisters rely on ic-dummy-getrandom-for-wasm, which only takes effect with
# this cfg; without it the build fails in getrandom. Keep in sync with
# .github/workflows/release.yml.
WASM_RUSTFLAGS := --cfg=getrandom_backend="custom"

.PHONY: lint fix test build-wasm build-wasm64 build-did bindings

lint:
	@cargo fmt --all -- --check
	@cargo clippy --workspace --all-targets --all-features -- -D warnings

fix:
	@cargo clippy --fix --workspace --tests

test:
	@cargo test --workspace --all-features -- --nocapture

# cargo install ic-wasm
build-wasm:
	@RUSTFLAGS='$(WASM_RUSTFLAGS)' cargo build --locked --release --target wasm32-unknown-unknown -p ic_cose_canister -p ic_wasm_canister

build-wasm64:
	@RUSTFLAGS='$(WASM_RUSTFLAGS)' cargo +nightly build --locked -Z build-std=std,panic_abort --target wasm64-unknown-unknown --release -p ic_cose_canister -p ic_wasm_canister

# cargo install candid-extractor
# Depends on build-wasm: the .did is extracted from the built modules, so
# generating it from stale artifacts would silently commit a stale interface.
build-did: build-wasm
	candid-extractor target/wasm32-unknown-unknown/release/ic_cose_canister.wasm > src/ic_cose_canister/ic_cose_canister.did
	candid-extractor target/wasm32-unknown-unknown/release/ic_wasm_canister.wasm > src/ic_wasm_canister/ic_wasm_canister.did
	python3 scripts/generate-bindings.py

bindings:
	python3 scripts/generate-bindings.py
