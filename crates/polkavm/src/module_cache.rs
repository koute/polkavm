use crate::api::{Module, ModulePrivate};
use crate::mutex::Mutex;
use crate::{ModuleConfig, ProgramBlob};
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use polkavm_common::hasher::Hash;

#[derive(Copy, Clone, Debug)]
pub struct ModuleKey {
    unique_id: u64,
    config_hash: Hash,
    module_hash: Option<Hash>,
}

impl core::hash::Hash for ModuleKey {
    fn hash<H>(&self, hasher: &mut H)
    where
        H: core::hash::Hasher,
    {
        self.config_hash.hash(hasher);
        if let Some(hash) = self.module_hash {
            hash.hash(hasher);
        } else {
            hasher.write_u64(self.unique_id);
        }
    }
}

impl Ord for ModuleKey {
    fn cmp(&self, rhs: &ModuleKey) -> core::cmp::Ordering {
        self.config_hash.cmp(&rhs.config_hash).then_with(|| {
            if let (Some(lhs_hash), Some(rhs_hash)) = (self.module_hash, rhs.module_hash) {
                lhs_hash.cmp(&rhs_hash)
            } else {
                self.unique_id.cmp(&rhs.unique_id)
            }
        })
    }
}

impl PartialOrd for ModuleKey {
    fn partial_cmp(&self, rhs: &ModuleKey) -> Option<core::cmp::Ordering> {
        Some(self.cmp(rhs))
    }
}

impl PartialEq for ModuleKey {
    fn eq(&self, rhs: &ModuleKey) -> bool {
        self.cmp(rhs) == core::cmp::Ordering::Equal
    }
}

impl Eq for ModuleKey {}

struct ModuleCacheInner {
    active: BTreeMap<ModuleKey, Weak<ModulePrivate>>,
    inactive: schnellru::LruMap<ModuleKey, Arc<ModulePrivate>>,
}

pub struct ModuleCache {
    enabled: bool,
    inner: Mutex<ModuleCacheInner>,
}

impl ModuleCache {
    pub fn new(enabled: bool, lru_cache_size: u32) -> Self {
        ModuleCache {
            enabled,
            inner: Mutex::new(ModuleCacheInner {
                active: BTreeMap::new(),
                inactive: schnellru::LruMap::new(schnellru::ByLength::new(if enabled { lru_cache_size } else { 0 })),
            }),
        }
    }

    pub fn get(&self, config: &ModuleConfig, blob: &ProgramBlob) -> (Option<ModuleKey>, Option<Module>) {
        if !self.enabled {
            return (None, None);
        }

        let key = ModuleKey {
            unique_id: blob.unique_id(),
            config_hash: config.hash(),
            module_hash: if config.cache_by_hash() {
                Some(blob.unique_hash(true))
            } else {
                None
            },
        };

        let mut inner = self.inner.lock();
        let inner = &mut *inner;
        if let Some(module) = inner.active.get(&key) {
            if let Some(module) = Weak::upgrade(module) {
                log::debug!("Found cached module (active): {key:?}");
                return (Some(key), Some(Module(Some(module))));
            }
        }

        if let Some(module) = inner.inactive.remove(&key) {
            log::debug!("Found cached module (inactive): {key:?}");
            inner.active.insert(key, Arc::downgrade(&module));
            return (Some(key), Some(Module(Some(module))));
        }

        (Some(key), None)
    }

    pub fn insert(&self, key: ModuleKey, module: Arc<ModulePrivate>) -> Module {
        use alloc::collections::btree_map::Entry;

        if !self.enabled {
            return Module(Some(module));
        }

        log::debug!("Adding module to active cache: {key:?}");
        let mut inner = self.inner.lock();

        if let Some(module) = inner.inactive.remove(&key) {
            inner.active.insert(key, Arc::downgrade(&module));
            return Module(Some(module));
        }

        match inner.active.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(Arc::downgrade(&module));
                Module(Some(module))
            }
            Entry::Occupied(mut entry) => {
                // Should only happen if multiple threads were racing to compile the same module.
                if let Some(module) = Weak::upgrade(entry.get()) {
                    Module(Some(module))
                } else {
                    entry.insert(Arc::downgrade(&module));
                    Module(Some(module))
                }
            }
        }
    }

    pub fn on_drop(&self, module: Arc<ModulePrivate>) {
        let Some(key) = module.module_key else {
            return;
        };

        let mut inner = self.inner.lock();
        if Arc::strong_count(&module) != 1 {
            return;
        }

        log::debug!("Removing module from the active cache: {key:?}");
        inner.active.remove(&key);
        inner.inactive.get_or_insert(key, || {
            log::debug!("Adding module to inactive cache: {key:?}");
            module
        });
    }
}
