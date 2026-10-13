//! The module's handle on the host's storage, reached over the storage bus.
//!
//! The module owns no storage backend, file or path. Box records and the jail
//! index go through [`tinybox_drivers`] on the document port the host serves;
//! the host binds the scope from the authenticated caller, so nothing here
//! names one. A host that does not serve storage (an older host, or a bare test
//! broker) leaves the module on in-memory box records, exactly as before.

use std::sync::Arc;

use tinybox_core::{MemoryStore, Store};
use tinybus::Connection;
use tinystoragedrivers_core::{DocumentStore, ScopedStorage, StorageBackend};

/// Lazily connected storage for one module instance.
#[derive(Default)]
pub(super) struct ModuleStorage {
    connection: Option<Connection>,
    scoped: tokio::sync::Mutex<Option<ScopedStorage>>,
}

impl ModuleStorage {
    /// Storage reached through `connection`.
    pub(super) fn connected(connection: Connection) -> Self {
        Self {
            connection: Some(connection),
            scoped: tokio::sync::Mutex::default(),
        }
    }

    /// The scoped handle, connected on first use and shared afterwards.
    ///
    /// A failed connect is not cached, so a host that starts serving storage
    /// later is picked up by the next call.
    async fn scoped(&self) -> Option<ScopedStorage> {
        let connection = self.connection.clone()?;
        let mut slot = self.scoped.lock().await;
        if let Some(scoped) = slot.as_ref() {
            return Some(scoped.clone());
        }
        let bus = match tinystoragedrivers_busproxy::connect_storage(connection).await {
            Ok(bus) => bus,
            Err(error) => {
                log::debug!("[tinybox_module] storage bus unavailable: {error}");
                return None;
            }
        };
        match bus.for_scope(&tinystoragedrivers_busproxy::module_scope_label()) {
            Ok(scoped) => {
                log::debug!("[tinybox_module] storage bus connected");
                *slot = Some(scoped.clone());
                Some(scoped)
            }
            Err(error) => {
                log::warn!("[tinybox_module] storage bus scope refused: {error}");
                None
            }
        }
    }

    /// The host's document port, when it serves one.
    pub(super) async fn documents(&self) -> Option<Arc<dyn DocumentStore>> {
        self.scoped()
            .await
            .map(|scoped| Arc::clone(scoped.documents()))
    }

    /// Where a new resource keeps its box record: the host's document port
    /// when it serves one, memory otherwise.
    pub(super) async fn box_store(&self) -> Arc<dyn Store> {
        let Some(documents) = self.documents().await else {
            return Arc::new(MemoryStore::new());
        };
        // The store declares its collection with a blocking bridge, which must
        // not run on an async worker.
        let opened =
            tokio::task::spawn_blocking(move || tinybox_drivers::DocumentBoxStore::new(documents))
                .await;
        match opened {
            Ok(Ok(store)) => Arc::new(store),
            Ok(Err(error)) => {
                log::warn!("[tinybox_module] box store on host storage refused: {error}");
                Arc::new(MemoryStore::new())
            }
            Err(error) => {
                log::warn!("[tinybox_module] box store task failed: {error}");
                Arc::new(MemoryStore::new())
            }
        }
    }

    /// A jail registry rooted at `base` whose index lives on the host's
    /// document port, or `None` when the host serves no storage.
    #[cfg(test)]
    pub(super) async fn jail_registry(
        &self,
        base: std::path::PathBuf,
        name: String,
    ) -> Option<std::io::Result<tinybox_jail::JailRegistry>> {
        let documents = self.documents().await?;
        let opened = tokio::task::spawn_blocking(move || {
            let index = tinybox_drivers::DocumentIndexStore::new(documents, name)?;
            tinybox_jail::JailRegistry::open_with_store(
                base,
                Arc::new(tinybox_core::clock::SystemClock::new()),
                Arc::new(index),
            )
        })
        .await;
        Some(opened.unwrap_or_else(|error| Err(std::io::Error::other(error))))
    }
}

impl std::fmt::Debug for ModuleStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModuleStorage")
            .field("connected", &self.connection.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
