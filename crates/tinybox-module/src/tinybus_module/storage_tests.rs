use super::*;
use tinybox_core::{BoxId, BoxInfo, BoxSpec, BoxState, HostRef, Placement, SandboxRef};
use tinybox_core::{WorkspaceSource, store::insert_new};
use tinybus::broker::Broker;
use tinybus::transport::memory::MemoryBus;
use tinystoragedrivers_busproxy::{PerCallerEndpoint, ServedStorage, serve};
use tinystoragedrivers_client::StorageServer;
use tinystoragedrivers_core::{
    DocumentStoreExt, MemoryStorage, Query, Scope, ScopedStorage, StorageBackend,
};

/// A broker with a module-side connection and, optionally, a storage host.
struct Rig {
    module: Connection,
    backend: MemoryStorage,
    _served: Option<ServedStorage>,
}

async fn rig(serve_storage: bool) -> Rig {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());
    let backend = MemoryStorage::new();
    let host = Connection::connect(bus.connect().await.unwrap())
        .await
        .unwrap();
    let served = if serve_storage {
        let bound = backend.clone();
        let endpoint = PerCallerEndpoint::new(move |_sender| {
            let scoped: ScopedStorage = bound.for_scope(&Scope::local()).ok()?;
            Some(StorageServer::new(scoped))
        });
        Some(serve(&host, Arc::new(endpoint)).await.unwrap())
    } else {
        None
    };
    let module = Connection::connect(bus.connect().await.unwrap())
        .await
        .unwrap();
    // Keep the host connection alive for the life of the broker.
    std::mem::forget(host);
    Rig {
        module,
        backend,
        _served: served,
    }
}

fn info(id: &str) -> BoxInfo {
    let spec = BoxSpec::new(
        Placement::new(
            HostRef::new("local").unwrap(),
            SandboxRef::new("passthrough").unwrap(),
        ),
        WorkspaceSource::LocalDir("/srv/work".into()),
    );
    BoxInfo::new(BoxId::new(id).unwrap(), BoxState::Ready, spec)
}

async fn host_docs(rig: &Rig, collection: &'static str) -> Vec<serde_json::Value> {
    let docs = Arc::clone(rig.backend.for_scope(&Scope::local()).unwrap().documents());
    docs.query_all(collection, &Query::all())
        .await
        .map(|all| all.into_iter().map(|entry| entry.value).collect())
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn box_records_land_on_the_host_document_port() {
    let rig = rig(true).await;
    let storage = ModuleStorage::connected(rig.module.clone());
    let store = storage.box_store().await;
    let record = info("module-box-1");
    let writer = Arc::clone(&store);
    let written = record.clone();
    tokio::task::spawn_blocking(move || insert_new(writer.as_ref(), &written))
        .await
        .unwrap()
        .unwrap();

    let stored = host_docs(&rig, tinybox_drivers::BOX_COLLECTION).await;
    assert_eq!(stored.len(), 1, "the record is a document on the host");
    let read = Arc::clone(&store);
    let listed = tokio::task::spawn_blocking(move || read.list())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(listed, vec![record]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_storage_host_box_records_stay_in_memory() {
    let rig = rig(false).await;
    let storage = ModuleStorage::connected(rig.module.clone());
    assert!(storage.documents().await.is_none());
    let store = storage.box_store().await;
    let record = info("memory-box");
    let writer = Arc::clone(&store);
    let written = record.clone();
    tokio::task::spawn_blocking(move || writer.insert(&written))
        .await
        .unwrap()
        .unwrap();
    assert!(host_docs(&rig, tinybox_drivers::BOX_COLLECTION).await.is_empty());
}

#[tokio::test]
async fn an_unconnected_module_has_no_documents() {
    let storage = ModuleStorage::default();
    assert!(storage.documents().await.is_none());
    assert!(
        storage
            .jail_registry(std::env::temp_dir(), "none".into())
            .await
            .is_none()
    );
    assert!(format!("{storage:?}").contains("connected: false"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_jail_index_is_a_document_on_the_host_not_a_file() {
    let rig = rig(true).await;
    let storage = ModuleStorage::connected(rig.module.clone());
    let base = tempfile::tempdir().unwrap();
    let registry = storage
        .jail_registry(base.path().to_path_buf(), "jails".into())
        .await
        .expect("host serves storage")
        .unwrap();
    let created = tokio::task::spawn_blocking(move || registry.create("scratch"))
        .await
        .unwrap()
        .unwrap();

    assert!(
        !base.path().join("index.json").exists(),
        "no index file is written"
    );
    let stored = host_docs(&rig, tinybox_drivers::JAIL_INDEX_COLLECTION).await;
    assert_eq!(stored.len(), 1);
    assert!(stored[0].to_string().contains(&created.id));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_connect_is_retried_when_the_host_starts_serving() {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await.unwrap())
        .await
        .unwrap();
    let module = Connection::connect(bus.connect().await.unwrap())
        .await
        .unwrap();
    let storage = ModuleStorage::connected(module);
    assert!(storage.documents().await.is_none());

    let backend = MemoryStorage::new();
    let endpoint = PerCallerEndpoint::new(move |_sender| {
        Some(StorageServer::new(backend.for_scope(&Scope::local()).ok()?))
    });
    let _served = serve(&host, Arc::new(endpoint)).await.unwrap();
    assert!(storage.documents().await.is_some());
}
