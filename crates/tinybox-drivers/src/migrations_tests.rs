use super::*;
use crate::faulty::{Faults, Faulty};
use serde_json::json;
use std::sync::Arc;

use tinystoragedrivers_document::memory::MemoryConnection;
use tinystoragedrivers_testkit::memory_storage;
use tinystoragedrivers_types::Scope;

use tinybox_bus::storage::BOX_COLLECTION;

fn storage(scope: &str) -> Storage {
    let scope = Scope::new(scope).expect("scope");
    let other_ports = memory_storage(&scope);
    let documents_and_streams = MemoryConnection::with_clock(Arc::new(|| 0)).for_scope(scope);
    Storage::new(
        documents_and_streams.documents(),
        documents_and_streams.streams(),
        Arc::clone(other_ports.kv()),
        Arc::clone(other_ports.blobs()),
        Arc::clone(other_ports.queues()),
        Arc::clone(other_ports.secrets()),
    )
}

fn old_box(id: &str) -> Value {
    json!({
        "id": id,
        "state": "Paused",
        "spec": {
            "runner": {"host": "local", "sandbox": "passthrough"},
            "workspace": {"host": "local", "sandbox": "passthrough"},
            "source": {"GitRepo": {"url": "https://x.test/r", "rev": "main"}},
            "resources": {"cpu_millis": 1, "memory_bytes": 2, "pids_max": 3, "disk_bytes": 4},
            "lifecycle": {"Persistent": {}},
            "network": "Open",
            "env": {}
        },
        "created_at": {"secs_since_epoch": 2, "nanos_since_epoch": 3_000_000}
    })
}

async fn seed_legacy(storage: &Storage, id: &str, body: Value, expires_ms: Option<i64>) {
    let documents = storage.documents();
    documents
        .ensure_collection(&CollectionSpec::new(V1_BOX_COLLECTION))
        .await
        .expect("legacy collection");
    let options = expires_ms.map_or_else(WriteOptions::new, |expiry| {
        WriteOptions::new().expires_ms(expiry)
    });
    documents
        .put_with(V1_BOX_COLLECTION, id, body, Precondition::Absent, options)
        .await
        .expect("legacy row");
}

fn with_document_fault(storage: &Storage, faults: Faults) -> Storage {
    Storage::new(
        Faulty::new(Arc::clone(storage.documents()), faults),
        Arc::clone(storage.streams()),
        Arc::clone(storage.kv()),
        Arc::clone(storage.blobs()),
        Arc::clone(storage.queues()),
        Arc::clone(storage.secrets()),
    )
}

#[tokio::test]
async fn migration_preserves_expiry_and_verifies_before_removing_source() {
    let storage = storage("tinybox-migrate-expiry");
    seed_legacy(&storage, "b1", old_box("b1"), Some(789)).await;

    prepare(&storage).await.expect("migration");

    let target = storage
        .documents()
        .get(BOX_COLLECTION, "b1")
        .await
        .expect("read target")
        .expect("target exists");
    assert_eq!(target.meta.schema, BODY_VERSION);
    assert_eq!(target.meta.expires_ms, Some(789));
    assert_eq!(target.doc["created_ms"], 2003);
    assert!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await
            .expect("read source")
            .is_none()
    );
}

#[tokio::test]
async fn an_existing_destination_with_a_different_expiry_preserves_legacy_source() {
    let storage = storage("tinybox-migrate-expiry-conflict");
    let old = old_box("b1");
    seed_legacy(&storage, "b1", old.clone(), Some(789)).await;
    let target = box_v1::to_body(old).expect("expected target body");
    storage
        .documents()
        .ensure_collection(&CollectionSpec::new(BOX_COLLECTION))
        .await
        .expect("target collection");
    storage
        .documents()
        .put_with(
            BOX_COLLECTION,
            "b1",
            target,
            Precondition::Absent,
            WriteOptions::new().schema(BODY_VERSION).expires_ms(456),
        )
        .await
        .expect("conflicting destination");

    let error = prepare(&storage).await.expect_err("expiry mismatch");

    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await
            .expect("read source")
            .is_some()
    );
}

#[tokio::test]
async fn a_future_receipt_fails_closed_before_migrating_any_source() {
    let storage = storage("tinybox-migrate-future-receipt");
    seed_legacy(&storage, "b1", old_box("b1"), None).await;
    storage
        .documents()
        .ensure_collection(&CollectionSpec::new(MIGRATIONS_COLLECTION))
        .await
        .expect("receipt collection");
    storage
        .documents()
        .put_with(
            MIGRATIONS_COLLECTION,
            BOXES_STEP,
            json!({"step": BOXES_STEP, "version": 9, "complete": true}),
            Precondition::Absent,
            WriteOptions::new().schema(BODY_VERSION),
        )
        .await
        .expect("future receipt");

    let error = prepare(&storage).await.expect_err("future receipt refused");

    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await
            .expect("read source")
            .is_some()
    );
    assert!(
        storage
            .documents()
            .get(BOX_COLLECTION, "b1")
            .await
            .expect("read target")
            .is_none()
    );
}

#[tokio::test]
async fn malformed_or_unrepresentable_legacy_rows_are_not_deleted() {
    let storage = storage("tinybox-migrate-unknown-field");
    let mut old = old_box("b1");
    old["future_field"] = json!("preserve me");
    seed_legacy(&storage, "b1", old.clone(), None).await;

    assert!(prepare(&storage).await.is_err());
    assert_eq!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await
            .expect("source read")
            .expect("source preserved")
            .doc,
        old
    );
    assert!(
        storage
            .documents()
            .get(BOX_COLLECTION, "b1")
            .await
            .expect("target read")
            .is_none()
    );
}

#[tokio::test]
async fn a_delete_failure_preserves_source_and_retry_finishes_safely() {
    let storage = storage("tinybox-migrate-delete-failure");
    seed_legacy(&storage, "b1", old_box("b1"), None).await;
    let faulty = with_document_fault(
        &storage,
        Faults {
            delete: true,
            ..Faults::default()
        },
    );

    assert!(prepare(&faulty).await.is_err());
    assert!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await
            .expect("source read")
            .is_some()
    );
    assert!(
        storage
            .documents()
            .get(BOX_COLLECTION, "b1")
            .await
            .expect("target read")
            .is_some()
    );

    prepare(&storage).await.expect("retry completes safely");
    assert!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await
            .expect("source read")
            .is_none()
    );
}

#[tokio::test]
async fn a_source_version_changed_during_copy_is_preserved() {
    let storage = storage("tinybox-migrate-source-race");
    let original = old_box("b1");
    seed_legacy(&storage, "b1", original, None).await;
    let mut changed = old_box("b1");
    changed["created_at"]["secs_since_epoch"] = json!(7);
    let faulty = Faulty::changing_source_after_target_write(
        Arc::clone(storage.documents()),
        "b1".to_owned(),
        changed.clone(),
    );
    let raced = Storage::new(
        faulty,
        Arc::clone(storage.streams()),
        Arc::clone(storage.kv()),
        Arc::clone(storage.blobs()),
        Arc::clone(storage.queues()),
        Arc::clone(storage.secrets()),
    );

    let error = prepare(&raced).await.expect_err("source version race");

    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert_eq!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await
            .expect("source read")
            .expect("new source retained")
            .doc,
        changed
    );
    assert!(
        storage
            .documents()
            .get(MIGRATIONS_COLLECTION, BOXES_STEP)
            .await
            .expect("receipt read")
            .is_none()
    );
}

#[tokio::test]
async fn a_destination_readback_failure_preserves_legacy_source() {
    let storage = storage("tinybox-migrate-readback-failure");
    seed_legacy(&storage, "b1", old_box("b1"), None).await;
    let faulty = Faulty::failing_target_readback(Arc::clone(storage.documents()));
    let storage_with_fault = Storage::new(
        faulty,
        Arc::clone(storage.streams()),
        Arc::clone(storage.kv()),
        Arc::clone(storage.blobs()),
        Arc::clone(storage.queues()),
        Arc::clone(storage.secrets()),
    );

    assert!(prepare(&storage_with_fault).await.is_err());
    assert!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await
            .expect("source read")
            .is_some()
    );
    assert!(
        storage
            .documents()
            .get(BOX_COLLECTION, "b1")
            .await
            .expect("target read")
            .is_some()
    );
    assert!(
        storage
            .documents()
            .get(MIGRATIONS_COLLECTION, BOXES_STEP)
            .await
            .expect("receipt read")
            .is_none()
    );
}

#[tokio::test]
async fn a_legacy_key_and_embedded_identifier_must_match() {
    let storage = storage("tinybox-migrate-id-mismatch");
    seed_legacy(&storage, "key-id", old_box("body-id"), None).await;

    let error = prepare(&storage).await.expect_err("key mismatch");

    assert_eq!(error.kind(), ErrorKind::Serialization);
    assert!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "key-id")
            .await
            .expect("source read")
            .is_some()
    );
}
