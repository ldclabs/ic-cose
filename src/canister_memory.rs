//! Stable-structures 0.7 selects its system-memory backend only on wasm32.
//! Keep its optimized default there and on native tests; wasm64 must not fall
//! back to VectorMemory, which would discard every stable map on upgrade.

use ic_stable_structures::{Memory, StableBTreeMap, Storable};

#[cfg(not(target_arch = "wasm64"))]
pub use ic_stable_structures::DefaultMemoryImpl;

#[cfg(target_arch = "wasm64")]
#[derive(Clone, Copy, Default)]
pub struct DefaultMemoryImpl;

#[cfg(target_arch = "wasm64")]
impl Memory for DefaultMemoryImpl {
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

/// Record count of a retired stable map, read without allocating its memory:
/// a virtual memory that was never used must stay unallocated.
///
/// Retired maps stored unbounded values, so their V2 layout loads without
/// checking the value type; only the header length is read.
pub fn retired_map_len<K, M>(memory: M) -> u64
where
    K: Storable + Ord + Clone,
    M: Memory,
{
    if memory.size() == 0 {
        return 0;
    }
    StableBTreeMap::<K, Vec<u8>, M>::load(memory).len()
}
