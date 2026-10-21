//! Behavior tests for document-backed TinyBox templates.

use super::*;
use tinystoragedrivers_api::{DocumentStoreExt, Storage, StorageBackend};
use tinystoragedrivers_testkit::memory_storage;
use tinystoragedrivers_types::Scope;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn storage(scope: &str) -> std::result::Result<Storage, Box<dyn std::error::Error>> {
    Ok(memory_storage(&Scope::new(scope)?))
}

#[tokio::test(flavor = "multi_thread")]
async fn templates_persist_as_documents_and_round_trip() -> TestResult {
    let storage = storage("template-round-trip")?;
    let store = DocumentTemplateStore::open(storage.clone()).await?;
    let name = TemplateName::new("rust-ci")?;
    let snapshot = SnapshotId::new("snap-2a4f")?;

    store.save(&name, &snapshot)?;

    assert_eq!(store.get(&name)?, snapshot);
    assert_eq!(store.list()?, vec![(name, snapshot)]);
    let body = storage
        .documents()
        .get_as::<TemplateRecord>(TEMPLATE_COLLECTION, "rust-ci")
        .await?
        .ok_or("template document missing")?;
    assert_eq!(body.doc.snapshot.as_str(), "snap-2a4f");
    assert_eq!(body.meta.schema, BODY_VERSION);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn resaving_replaces_a_template_and_remove_is_idempotently_reported() -> TestResult {
    let store = DocumentTemplateStore::open(storage("template-replace")?).await?;
    let name = TemplateName::new("rust-ci")?;
    store.save(&name, &SnapshotId::new("old")?)?;
    store.save(&name, &SnapshotId::new("new")?)?;
    assert_eq!(store.get(&name)?.as_str(), "new");
    store.remove(&name)?;
    assert!(matches!(
        store.get(&name),
        Err(Error::UnknownTemplate { name }) if name == "rust-ci"
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn template_names_are_isolated_by_the_supplied_scope() -> TestResult {
    let backend = tinystoragedrivers_testkit::MemoryBackend::new();
    let left_storage = backend.for_scope(&Scope::new("template-left")?)?;
    let right_storage = backend.for_scope(&Scope::new("template-right")?)?;
    let left = DocumentTemplateStore::open(left_storage).await?;
    let right = DocumentTemplateStore::open(right_storage).await?;
    let name = TemplateName::new("release")?;
    left.save(&name, &SnapshotId::new("left")?)?;
    assert!(matches!(
        right.get(&name),
        Err(Error::UnknownTemplate { .. })
    ));
    Ok(())
}
