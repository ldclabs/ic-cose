//! Stable-structures 0.7 selects its system-memory backend only on wasm32.
//! Keep its optimized default there and on native tests; wasm64 must not fall
//! back to VectorMemory, which would discard every stable map on upgrade.

#[cfg(not(target_arch = "wasm64"))]
pub use ic_stable_structures::DefaultMemoryImpl;

#[cfg(target_arch = "wasm64")]
#[derive(Clone, Copy, Default)]
pub struct DefaultMemoryImpl;

#[cfg(target_arch = "wasm64")]
impl ic_stable_structures::Memory for DefaultMemoryImpl {
    fn size(&self) -> u64 {
        ic_cdk::stable::stable_size()
    }

    fn grow(&self, pages: u64) -> i64 {
        ic_cdk::stable::stable_grow(pages)
            .map(|previous| previous as i64)
            .unwrap_or(-1)
    }

    fn read(&self, offset: u64, dst: &mut [u8]) {
        ic_cdk::stable::stable_read(offset, dst);
    }

    fn write(&self, offset: u64, src: &[u8]) {
        ic_cdk::stable::stable_write(offset, src);
    }
}
