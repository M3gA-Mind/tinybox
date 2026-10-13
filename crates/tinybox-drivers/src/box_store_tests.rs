use super::*;
use serde_json::json;
use tinybox_core::store::insert_new;
use tinybox_core::{BoxSpec, HostRef, Placement, SandboxRef, WorkspaceSource};
use tinystoragedrivers_core::{MemoryStorage, Scope, StorageBackend};

fn documents() -> Arc<dyn DocumentStore> {
    MemoryStorage::new()
        .for_scope(&Scope::local())
        .expect("scope")
        .documents()
        .clone()
}

fn spec() -> Result<BoxSpec> {
    Ok(BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new("passthrough")?),
        WorkspaceSource::LocalDir("/srv/work".into()),
    )
    .with_env("KEY", "value"))
}

fn info(id: &str) -> Result<BoxInfo> {
    Ok(BoxInfo::new(BoxId::new(id)?, BoxState::Ready, spec()?))
}

#[test]
fn an_inserted_box_round_trips() -> Result<()> {
    let store = DocumentBoxStore::new(documents())?;
    let original = info("build-1")?;
    store.insert(&original)?;
    assert_eq!(store.get(&original.id)?, original);
    assert_eq!(store.list()?, vec![original]);
    Ok(())
}

#[test]
fn a_second_insert_of_one_id_is_a_duplicate() -> Result<()> {
    let store = DocumentBoxStore::new(documents())?;
    store.insert(&info("a")?)?;
    assert!(matches!(
        store.insert(&info("a")?),
        Err(Error::DuplicateBox { id }) if id == "a"
    ));
    Ok(())
}

#[test]
fn an_unknown_box_is_reported_by_every_operation() -> Result<()> {
    let store = DocumentBoxStore::new(documents())?;
    let id = BoxId::new("ghost")?;
    assert!(matches!(store.get(&id), Err(Error::UnknownBox { .. })));
    assert!(matches!(
        store.set_state(&id, BoxState::Stopped),
        Err(Error::UnknownBox { .. })
    ));
    assert!(matches!(store.remove(&id), Err(Error::UnknownBox { .. })));
    Ok(())
}

#[test]
fn set_state_and_remove_change_the_record() -> Result<()> {
    let store = DocumentBoxStore::new(documents())?;
    let record = info("a")?;
    store.insert(&record)?;
    store.set_state(&record.id, BoxState::Stopped)?;
    assert_eq!(store.get(&record.id)?.state, BoxState::Stopped);
    store.remove(&record.id)?;
    assert!(store.list()?.is_empty());
    Ok(())
}

#[test]
fn list_is_ordered_by_identifier() -> Result<()> {
    let store = DocumentBoxStore::new(documents())?;
    for id in ["c", "a", "b"] {
        store.insert(&info(id)?)?;
    }
    let ids: Vec<String> = store
        .list()?
        .into_iter()
        .map(|record| record.id.into_string())
        .collect();
    assert_eq!(ids, ["a", "b", "c"]);
    Ok(())
}

#[test]
fn allocation_takes_the_lowest_free_name() -> Result<()> {
    let store = DocumentBoxStore::new(documents())?;
    let first = insert_new(&store, BoxState::Ready, &spec()?, std::time::UNIX_EPOCH)?;
    let second = insert_new(&store, BoxState::Ready, &spec()?, std::time::UNIX_EPOCH)?;
    assert_eq!(first.id.as_str(), "box-0");
    assert_eq!(second.id.as_str(), "box-1");
    Ok(())
}

#[test]
fn concurrent_allocation_never_loses_or_repeats_a_box() -> Result<()> {
    let store = Arc::new(DocumentBoxStore::new(documents())?);
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                insert_new(
                    store.as_ref(),
                    BoxState::Ready,
                    &spec().expect("spec"),
                    std::time::UNIX_EPOCH,
                )
                .map(|created| created.id.into_string())
            })
        })
        .collect();
    let mut ids = std::collections::BTreeSet::new();
    for handle in handles {
        let id = handle.join().expect("thread")?;
        assert!(ids.insert(id), "an identifier was handed out twice");
    }
    assert_eq!(store.list()?.len(), 8);
    Ok(())
}

#[test]
fn concurrent_state_changes_on_different_boxes_all_land() -> Result<()> {
    let store = Arc::new(DocumentBoxStore::new(documents())?);
    for id in ["a", "b", "c", "d"] {
        store.insert(&info(id)?)?;
    }
    let handles: Vec<_> = ["a", "b", "c", "d"]
        .into_iter()
        .map(|id| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                store.set_state(&BoxId::new(id).expect("id"), BoxState::Stopped)
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("thread")?;
    }
    assert!(store.list()?.iter().all(|r| r.state == BoxState::Stopped));
    Ok(())
}

#[test]
fn a_document_that_does_not_decode_is_a_store_error() -> Result<()> {
    let docs = documents();
    let store = DocumentBoxStore::new(Arc::clone(&docs))?;
    let bridge = Blocking::new().expect("bridge");
    let writer = Arc::clone(&docs);
    bridge
        .run(async move {
            writer
                .put(
                    BOX_COLLECTION,
                    "bad",
                    json!({"nope": 1}),
                    Precondition::None,
                )
                .await
        })
        .expect("bridge")
        .expect("put");
    assert!(matches!(
        store.get(&BoxId::new("bad")?),
        Err(Error::Store {
            operation: "decode",
            ..
        })
    ));
    Ok(())
}

#[test]
fn it_works_from_inside_a_current_thread_runtime() -> Result<()> {
    let runtime = std::thread::spawn(|| -> Result<()> {
        let runtime = tokio_rt();
        runtime.block_on(async {
            let store = DocumentBoxStore::new(documents())?;
            store.insert(&info("a")?)?;
            assert_eq!(store.list()?.len(), 1);
            Ok(())
        })
    });
    runtime.join().expect("thread")
}

fn tokio_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}
