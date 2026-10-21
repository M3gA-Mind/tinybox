use super::*;
use std::sync::Mutex;
use tempfile::TempDir;
use tinybox_core::{
    BoxId, BoxInfo, BoxSpec, BoxState, HostRef, Placement, SandboxRef, WorkspaceSource,
};
use tinystoragedrivers_api::Storage;
use tinystoragedrivers_types::{Precondition, Scope, WriteOptions};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn args(values: &[&str]) -> Vec<std::ffi::OsString> {
    values.iter().map(std::ffi::OsString::from).collect()
}

fn is_exit_code(actual: ExitCode, expected: ExitCode) -> bool {
    format!("{actual:?}") == format!("{expected:?}")
}

fn sample_box(
    id: &str,
    workspace: &str,
) -> std::result::Result<BoxInfo, Box<dyn std::error::Error>> {
    Ok(BoxInfo::new(
        BoxId::new(id)?,
        BoxState::Ready,
        BoxSpec::new(
            Placement::new(HostRef::new("local")?, SandboxRef::new("passthrough")?),
            WorkspaceSource::LocalDir(workspace.into()),
        ),
    ))
}

async fn file_test_storage(
    directory: &Path,
    identity: &str,
) -> std::result::Result<Storage, Box<dyn std::error::Error>> {
    let backend = tinystoragedrivers::open(&StorageConfig::File {
        dir: directory.to_owned(),
    })
    .await?;
    let scope_name = format!("tinybox.cli.{identity}");
    let scope = Scope::new(&scope_name)?;
    Ok(backend.for_scope(&scope)?)
}

#[derive(Debug)]
enum InsertResult {
    Succeed,
    SucceedAs(BoxInfo),
    Duplicate(BoxInfo),
    Fail,
}

#[derive(Debug)]
struct ImportStoreStub {
    current: Mutex<Option<BoxInfo>>,
    after_insert: Mutex<Option<BoxInfo>>,
    insert_result: InsertResult,
    fail_initial_read: bool,
}

impl ImportStoreStub {
    fn empty(insert_result: InsertResult) -> Self {
        Self {
            current: Mutex::new(None),
            after_insert: Mutex::new(None),
            insert_result,
            fail_initial_read: false,
        }
    }
}

impl Store for ImportStoreStub {
    fn insert(&self, info: &BoxInfo) -> tinybox_core::Result<()> {
        match &self.insert_result {
            InsertResult::Succeed => {
                *self
                    .after_insert
                    .lock()
                    .map_err(|_| tinybox_core::Error::Store {
                        operation: "test",
                        message: "stub lock poisoned".to_owned(),
                    })? = Some(info.clone());
                Ok(())
            }
            InsertResult::SucceedAs(stored) => {
                *self
                    .after_insert
                    .lock()
                    .map_err(|_| tinybox_core::Error::Store {
                        operation: "test",
                        message: "stub lock poisoned".to_owned(),
                    })? = Some(stored.clone());
                Ok(())
            }
            InsertResult::Duplicate(existing) => {
                *self
                    .after_insert
                    .lock()
                    .map_err(|_| tinybox_core::Error::Store {
                        operation: "test",
                        message: "stub lock poisoned".to_owned(),
                    })? = Some(existing.clone());
                Err(tinybox_core::Error::DuplicateBox {
                    id: info.id.to_string(),
                })
            }
            InsertResult::Fail => Err(tinybox_core::Error::Store {
                operation: "insert",
                message: "injected failure".to_owned(),
            }),
        }
    }

    fn get(&self, id: &BoxId) -> tinybox_core::Result<BoxInfo> {
        if self.fail_initial_read
            && self
                .after_insert
                .lock()
                .map_err(|_| tinybox_core::Error::Store {
                    operation: "test",
                    message: "stub lock poisoned".to_owned(),
                })?
                .is_none()
        {
            return Err(tinybox_core::Error::Store {
                operation: "read",
                message: "injected failure".to_owned(),
            });
        }
        if let Some(current) = self
            .current
            .lock()
            .map_err(|_| tinybox_core::Error::Store {
                operation: "test",
                message: "stub lock poisoned".to_owned(),
            })?
            .clone()
        {
            if &current.id == id {
                return Ok(current);
            }
        }
        if let Some(current) = self
            .after_insert
            .lock()
            .map_err(|_| tinybox_core::Error::Store {
                operation: "test",
                message: "stub lock poisoned".to_owned(),
            })?
            .clone()
        {
            if &current.id == id {
                return Ok(current);
            }
        }
        Err(tinybox_core::Error::UnknownBox { id: id.to_string() })
    }

    fn list(&self) -> tinybox_core::Result<Vec<BoxInfo>> {
        Ok(self
            .current
            .lock()
            .map_err(|_| tinybox_core::Error::Store {
                operation: "test",
                message: "stub lock poisoned".to_owned(),
            })?
            .clone()
            .into_iter()
            .collect())
    }

    fn set_state(&self, _id: &BoxId, _state: BoxState) -> tinybox_core::Result<()> {
        Ok(())
    }

    fn remove(&self, _id: &BoxId) -> tinybox_core::Result<()> {
        Ok(())
    }
}

fn write_legacy_box(path: &Path, key: &str, record: &BoxInfo) -> TestResult {
    let bytes = serde_json::to_vec(
        &[(key.to_owned(), record.clone())]
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
    )?;
    std::fs::write(path, bytes)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn executable_run_dispatches_with_explicit_store_and_reports_parse_errors() -> TestResult {
    let root = TempDir::new()?;
    let path = root.path().join("boxes.json");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let success = run(
        args(&[
            "tinybox",
            "--store",
            path.to_str().ok_or("unicode path")?,
            "ls",
        ]),
        &mut stdout,
        &mut stderr,
    )
    .await;
    assert!(is_exit_code(success, ExitCode::SUCCESS));
    assert!(stderr.is_empty());
    assert!(root.path().join(".tinybox-storage").is_dir());

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let help = run(args(&["tinybox", "--help"]), &mut stdout, &mut stderr).await;
    assert!(is_exit_code(help, ExitCode::SUCCESS));
    assert!(stdout.windows(6).any(|window| window == b"Usage:"));
    assert!(stderr.is_empty());

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let dispatch_error = run(
        args(&[
            "tinybox",
            "--store",
            path.to_str().ok_or("unicode path")?,
            "template",
            "rm",
            "missing",
        ]),
        &mut stdout,
        &mut stderr,
    )
    .await;
    assert!(is_exit_code(
        dispatch_error,
        ExitCode::from(EXIT_TINYBOX_ERROR)
    ));
    assert!(!stderr.is_empty());

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let invalid = run(
        args(&["tinybox", "--not-an-option"]),
        &mut stdout,
        &mut stderr,
    )
    .await;
    assert!(is_exit_code(invalid, ExitCode::from(2)));
    assert!(stderr.windows(6).any(|window| window == b"error:"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn executable_run_rejects_a_store_path_without_a_filename() -> TestResult {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let result = run(
        args(&["tinybox", "--store", "/", "ls"]),
        &mut stdout,
        &mut stderr,
    )
    .await;

    assert!(is_exit_code(result, ExitCode::from(EXIT_TINYBOX_ERROR)));
    assert!(stderr.windows(6).any(|window| window == b"error:"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn opening_a_backend_below_a_regular_file_reports_the_open_context() -> TestResult {
    let root = TempDir::new()?;
    let blocker = root.path().join("not-a-directory");
    std::fs::write(&blocker, b"keep")?;
    let error = open_stores(
        &blocker.join("backend"),
        "isolated",
        &root.path().join("missing-boxes.json"),
        &root.path().join("missing-templates.json"),
    )
    .await
    .err()
    .ok_or_else(|| std::io::Error::other("backend open must fail"))?;

    assert!(matches!(
        error,
        Error::Store {
            operation: "open",
            ..
        }
    ));
    assert_eq!(std::fs::read(blocker)?, b"keep");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn storage_composition_imports_once_and_preserves_later_box_changes() -> TestResult {
    let root = TempDir::new()?;
    let storage_dir = root.path().join("storage");
    let boxes_path = root.path().join("boxes.json");
    let templates_path = root.path().join("templates.json");
    std::fs::write(
        &boxes_path,
        include_bytes!("../tests/fixtures/legacy-v0.1.40/boxes.json"),
    )?;
    std::fs::write(
        &templates_path,
        include_bytes!("../tests/fixtures/legacy-v0.1.40/templates.json"),
    )?;

    let (store, templates) = open_stores(
        &storage_dir,
        "independent-store",
        &boxes_path,
        &templates_path,
    )
    .await?;
    let id = BoxId::new("box-released")?;
    let original = store.get(&id)?;
    assert_eq!(original.id, id);
    store.remove(&id)?;
    templates.save(
        &TemplateName::new("released-template")?,
        &SnapshotId::new("later-snapshot")?,
    )?;

    let (reopened, reopened_templates) = open_stores(
        &storage_dir,
        "independent-store",
        &boxes_path,
        &templates_path,
    )
    .await?;
    assert!(matches!(reopened.get(&id), Err(Error::UnknownBox { .. })));
    assert_eq!(
        reopened_templates.get(&TemplateName::new("released-template")?)?,
        SnapshotId::new("later-snapshot")?
    );
    assert!(
        boxes_path.exists(),
        "the importer never consumes its source"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn box_import_accepts_an_identical_destination_without_rewriting_it() -> TestResult {
    let root = TempDir::new()?;
    let storage = file_test_storage(&root.path().join("storage"), "same-box").await?;
    let boxes = DocumentBoxStore::open(storage.clone()).await?;
    let record = sample_box("existing", "/workspace")?;
    boxes.insert(&record)?;
    let legacy_path = root.path().join("boxes.json");
    let records = [("existing".to_owned(), record.clone())]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    std::fs::write(&legacy_path, serde_json::to_vec(&records)?)?;

    import_legacy_boxes(&legacy_path, &boxes, &Arc::clone(storage.documents())).await?;

    assert_eq!(boxes.get(&record.id)?, record);
    assert!(
        storage
            .documents()
            .get(CLI_IMPORTS_COLLECTION, "boxes")
            .await?
            .is_some()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_current_box_is_not_mistaken_for_a_missing_destination() -> TestResult {
    let root = TempDir::new()?;
    let storage = file_test_storage(&root.path().join("storage"), "bad-current-box").await?;
    let boxes = DocumentBoxStore::open(storage.clone()).await?;
    let record = sample_box("existing", "/legacy")?;
    storage
        .documents()
        .put_with(
            tinybox_bus::storage::BOX_COLLECTION,
            "existing",
            serde_json::json!({"state": "not-a-box"}),
            Precondition::Absent,
            WriteOptions::new().schema(BODY_VERSION),
        )
        .await?;
    let legacy_path = root.path().join("boxes.json");
    std::fs::write(
        &legacy_path,
        serde_json::to_vec(
            &[("existing".to_owned(), record)]
                .into_iter()
                .collect::<BTreeMap<_, _>>(),
        )?,
    )?;

    let error = import_legacy_boxes(&legacy_path, &boxes, &Arc::clone(storage.documents()))
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("malformed current record must fail closed"))?;

    assert!(matches!(error, Error::Store { .. }));
    assert!(
        storage
            .documents()
            .get(CLI_IMPORTS_COLLECTION, "boxes")
            .await?
            .is_none()
    );
    assert_eq!(
        std::fs::read(legacy_path)?,
        serde_json::to_vec(
            &[("existing".to_owned(), sample_box("existing", "/legacy")?)]
                .into_iter()
                .collect::<BTreeMap<_, _>>()
        )?
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_legacy_json_fails_open_without_replacing_the_source() -> TestResult {
    let root = TempDir::new()?;
    let storage_dir = root.path().join("storage");
    let boxes_path = root.path().join("boxes.json");
    let templates_path = root.path().join("templates.json");
    let bytes = b"{not-json";
    std::fs::write(&boxes_path, bytes)?;

    let error = open_stores(
        &storage_dir,
        "malformed-store",
        &boxes_path,
        &templates_path,
    )
    .await
    .err()
    .ok_or_else(|| std::io::Error::other("malformed source must fail closed"))?;

    assert!(matches!(
        error,
        Error::Store {
            operation: "migrate",
            ..
        }
    ));
    assert_eq!(std::fs::read(&boxes_path)?, bytes);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changed_legacy_source_is_rejected_after_import_completion() -> TestResult {
    let root = TempDir::new()?;
    let storage_dir = root.path().join("storage");
    let boxes_path = root.path().join("boxes.json");
    let templates_path = root.path().join("templates.json");
    std::fs::write(
        &boxes_path,
        include_bytes!("../tests/fixtures/legacy-v0.1.40/boxes.json"),
    )?;
    open_stores(&storage_dir, "changed-source", &boxes_path, &templates_path).await?;
    std::fs::write(&boxes_path, b"{}")?;

    let error = open_stores(&storage_dir, "changed-source", &boxes_path, &templates_path)
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("changed legacy source must be rejected"))?;

    assert!(matches!(
        error,
        Error::Store {
            operation: "migrate",
            ..
        }
    ));
    assert_eq!(std::fs::read(&boxes_path)?, b"{}");
    Ok(())
}

#[test]
fn path_identity_requires_an_existing_parent_and_unicode_names() -> TestResult {
    let root = TempDir::new()?;
    let missing = root.path().join("missing").join("boxes.json");
    assert!(normalized_path(&missing).is_err());

    let plain = root.path().join("boxes.json");
    let (directory, identity) = store_location(&plain)?;
    assert!(directory.ends_with(&identity));
    assert!(directory.starts_with(root.path()));
    Ok(())
}

#[test]
fn normalized_paths_reject_root_and_non_unicode_names() -> TestResult {
    assert!(normalized_path(Path::new("/")).is_err());

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let root = TempDir::new()?;
        let non_unicode = root
            .path()
            .join(std::ffi::OsStr::from_bytes(b"box-\xff.json"));
        assert!(normalized_path(&non_unicode).is_err());
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let invalid = Path::new(std::ffi::OsStr::from_bytes(b"bad\0path"));
        assert!(matches!(
            legacy_source(invalid, "fixture"),
            Err(Error::Io {
                operation: "inspect",
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn legacy_source_verification_detects_disappearance_and_changed_bytes() -> TestResult {
    let root = TempDir::new()?;
    let path = root.path().join("boxes.json");
    std::fs::write(&path, b"{}")?;
    let (_, identity) =
        legacy_source(&path, "box store")?.ok_or_else(|| std::io::Error::other("source exists"))?;
    let original = blake3::hash(b"{}").to_hex().to_string();
    verify_legacy_unchanged(&path, &identity, &original, "box store")?;

    std::fs::write(&path, b"{\"changed\":true}")?;
    assert!(matches!(
        verify_legacy_unchanged(&path, &identity, &original, "box store"),
        Err(Error::Store {
            operation: "migrate",
            ..
        })
    ));
    std::fs::remove_file(&path)?;
    assert!(matches!(
        verify_legacy_unchanged(&path, &identity, &original, "box store"),
        Err(Error::Store {
            operation: "migrate",
            ..
        })
    ));
    Ok(())
}

#[test]
fn state_path_uses_explicit_store_then_state_home_fallbacks_in_order() -> TestResult {
    let explicit = Cli::try_parse_from(args(&["tinybox", "--store", "/chosen/boxes.json", "ls"]))?;
    assert_eq!(
        state_path_from_environment(
            &explicit,
            Some("state".into()),
            Some("xdg".into()),
            Some("home".into()),
        )?,
        PathBuf::from("/chosen/boxes.json")
    );

    let default = Cli::try_parse_from(args(&["tinybox", "ls"]))?;
    assert_eq!(
        state_path_from_environment(
            &default,
            Some("state".into()),
            Some("xdg".into()),
            Some("home".into()),
        )?,
        PathBuf::from("state/boxes.json")
    );
    assert_eq!(
        state_path_from_environment(&default, None, Some("xdg".into()), Some("home".into()))?,
        PathBuf::from("xdg/tinybox/boxes.json")
    );
    assert_eq!(
        state_path_from_environment(&default, None, None, Some("home".into()))?,
        PathBuf::from("home/.local/state/tinybox/boxes.json")
    );
    assert!(state_path_from_environment(&default, None, None, None).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn legacy_source_requires_a_regular_nonsymlink_file() -> TestResult {
    use std::os::unix::fs::symlink;

    let root = TempDir::new()?;
    let missing = root.path().join("missing.json");
    assert!(legacy_source(&missing, "fixture")?.is_none());
    assert!(legacy_source(root.path(), "fixture").is_err());

    let source = root.path().join("source.json");
    std::fs::write(&source, b"{}")?;
    let link = root.path().join("link.json");
    symlink(&source, &link)?;
    assert!(legacy_source(&link, "fixture").is_err());
    Ok(())
}

#[test]
fn a_file_cannot_be_used_as_the_state_directory() -> TestResult {
    let root = TempDir::new()?;
    let file = root.path().join("not-a-directory");
    std::fs::write(&file, b"sentinel")?;
    assert!(store_location(&file.join("boxes.json")).is_err());
    assert_eq!(std::fs::read(&file)?, b"sentinel");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_box_import_checks_keys_and_store_race_outcomes() -> TestResult {
    let root = TempDir::new()?;
    let source = root.path().join("boxes.json");
    let record = sample_box("expected", "/legacy")?;
    let bad_key_storage = file_test_storage(&root.path().join("bad-key"), "bad-key").await?;
    let bad_key_documents = Arc::clone(bad_key_storage.documents());

    write_legacy_box(&source, "different-key", &record)?;
    let error = import_legacy_boxes(
        &source,
        &ImportStoreStub::empty(InsertResult::Succeed),
        &bad_key_documents,
    )
    .await
    .err()
    .ok_or_else(|| std::io::Error::other("mismatched key must fail"))?;
    assert!(matches!(
        error,
        Error::Store {
            operation: "migrate",
            ..
        }
    ));

    write_legacy_box(&source, "expected", &record)?;
    let race_storage =
        file_test_storage(&root.path().join("matching-race"), "matching-race").await?;
    let race_documents = Arc::clone(race_storage.documents());
    let _race_stores = open_stores(
        &root.path().join("matching-race"),
        "matching-race",
        &root.path().join("missing-boxes.json"),
        &root.path().join("missing-templates.json"),
    )
    .await?;
    let matching_race = ImportStoreStub::empty(InsertResult::Duplicate(record.clone()));
    import_legacy_boxes(&source, &matching_race, &race_documents).await?;

    let differing = sample_box("expected", "/concurrent-writer")?;
    for (index, store) in [
        ImportStoreStub::empty(InsertResult::Duplicate(differing.clone())),
        ImportStoreStub::empty(InsertResult::SucceedAs(differing)),
        ImportStoreStub::empty(InsertResult::Fail),
    ]
    .into_iter()
    .enumerate()
    {
        let storage = file_test_storage(
            &root.path().join(format!("failure-{index}")),
            &format!("failure-{index}"),
        )
        .await?;
        let documents = Arc::clone(storage.documents());
        let error = import_legacy_boxes(&source, &store, &documents)
            .await
            .err()
            .ok_or_else(|| std::io::Error::other("conflicting store outcome must fail"))?;
        assert!(matches!(error, Error::Store { .. }));
    }

    let read_storage = file_test_storage(&root.path().join("read-error"), "read-error").await?;
    let read_documents = Arc::clone(read_storage.documents());
    let mut failing_read = ImportStoreStub::empty(InsertResult::Succeed);
    failing_read.fail_initial_read = true;
    let error = import_legacy_boxes(&source, &failing_read, &read_documents)
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("store read error must propagate"))?;
    assert!(matches!(
        error,
        Error::Store {
            operation: "read",
            ..
        }
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_receipts_validate_schema_and_reconcile_conditional_write_races() -> TestResult {
    let root = TempDir::new()?;
    let storage = file_test_storage(&root.path().join("storage"), "receipt").await?;
    let documents = Arc::clone(storage.documents());
    let _stores = open_stores(
        &root.path().join("storage"),
        "receipt",
        &root.path().join("missing-boxes.json"),
        &root.path().join("missing-templates.json"),
    )
    .await?;

    complete_import(&documents, "boxes", "source", "digest").await?;
    complete_import(&documents, "boxes", "source", "digest").await?;
    let conflict = complete_import(&documents, "boxes", "other-source", "digest")
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("different receipt must conflict"))?;
    assert!(matches!(
        conflict,
        Error::Store {
            operation: "migrate",
            ..
        }
    ));

    let malformed_storage = file_test_storage(&root.path().join("malformed"), "malformed").await?;
    let malformed_documents = Arc::clone(malformed_storage.documents());
    let _malformed_stores = open_stores(
        &root.path().join("malformed"),
        "malformed",
        &root.path().join("missing-boxes.json"),
        &root.path().join("missing-templates.json"),
    )
    .await?;
    malformed_documents
        .put_with(
            CLI_IMPORTS_COLLECTION,
            "boxes",
            serde_json::json!({"unexpected": true}),
            Precondition::Absent,
            WriteOptions::new().schema(BODY_VERSION),
        )
        .await?;
    let error = import_already_complete(&malformed_documents, "boxes", "source", "digest")
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("malformed receipt must fail closed"))?;
    assert!(matches!(error, Error::Store { .. }));

    let schema_storage = file_test_storage(&root.path().join("schema"), "schema").await?;
    let schema_documents = Arc::clone(schema_storage.documents());
    let _schema_stores = open_stores(
        &root.path().join("schema"),
        "schema",
        &root.path().join("missing-boxes.json"),
        &root.path().join("missing-templates.json"),
    )
    .await?;
    schema_documents
        .put_with(
            CLI_IMPORTS_COLLECTION,
            "boxes",
            serde_json::json!({"source": "source", "digest": "digest", "version": 1}),
            Precondition::Absent,
            WriteOptions::new().schema(BODY_VERSION + 1),
        )
        .await?;
    assert!(
        import_already_complete(&schema_documents, "boxes", "source", "digest")
            .await
            .is_err()
    );

    let invalid_version_storage =
        file_test_storage(&root.path().join("version"), "version").await?;
    let invalid_version_documents = Arc::clone(invalid_version_storage.documents());
    let _version_stores = open_stores(
        &root.path().join("version"),
        "version",
        &root.path().join("missing-boxes.json"),
        &root.path().join("missing-templates.json"),
    )
    .await?;
    invalid_version_documents
        .put_with(
            CLI_IMPORTS_COLLECTION,
            "boxes",
            serde_json::json!({"source": "source", "digest": "digest", "version": 2}),
            Precondition::Absent,
            WriteOptions::new().schema(BODY_VERSION),
        )
        .await?;
    assert!(
        import_already_complete(&invalid_version_documents, "boxes", "source", "digest")
            .await
            .is_err()
    );
    Ok(())
}

#[test]
fn import_path_and_error_helpers_preserve_operation_context() -> TestResult {
    let root = TempDir::new()?;
    let missing_parent = root.path().join("missing").join("boxes.json");
    assert!(normalized_path(&missing_parent).is_err());
    assert!(store_location(Path::new("/")).is_err());

    let mapped = storage_error(
        "read import receipt",
        &StorageError::backend("injected backend failure"),
    );
    assert!(matches!(
        mapped,
        Error::Store {
            operation: "read import receipt",
            ..
        }
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_conflicting_current_box_blocks_legacy_import() -> TestResult {
    let root = TempDir::new()?;
    let storage_dir = root.path().join("storage");
    let boxes_path = root.path().join("boxes.json");
    let templates_path = root.path().join("templates.json");
    let (store, _) = open_stores(
        &storage_dir,
        "conflicting-import",
        &boxes_path,
        &templates_path,
    )
    .await?;
    let current = sample_box("same-id", "/new-state")?;
    store.insert(&current)?;
    let legacy = sample_box("same-id", "/old-state")?;
    std::fs::write(
        &boxes_path,
        serde_json::to_vec(
            &[("same-id".to_owned(), legacy)]
                .into_iter()
                .collect::<BTreeMap<_, _>>(),
        )?,
    )?;

    let error = open_stores(
        &storage_dir,
        "conflicting-import",
        &boxes_path,
        &templates_path,
    )
    .await
    .err()
    .ok_or_else(|| std::io::Error::other("conflicting destination must fail closed"))?;
    assert!(matches!(
        error,
        Error::Store {
            operation: "migrate",
            ..
        }
    ));
    assert_eq!(store.get(&BoxId::new("same-id")?)?, current);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invalid_template_name_is_not_recorded_as_imported() -> TestResult {
    let root = TempDir::new()?;
    let storage_dir = root.path().join("storage");
    let boxes_path = root.path().join("boxes.json");
    let templates_path = root.path().join("templates.json");
    let bytes = br#"{"":"snapshot"}"#;
    std::fs::write(&templates_path, bytes)?;

    let error = open_stores(
        &storage_dir,
        "invalid-template-name",
        &boxes_path,
        &templates_path,
    )
    .await
    .err()
    .ok_or_else(|| std::io::Error::other("empty template key must fail validation"))?;
    assert!(matches!(
        error,
        Error::InvalidIdentifier {
            kind: "template name",
            ..
        }
    ));
    assert_eq!(std::fs::read(&templates_path)?, bytes);
    Ok(())
}

#[test]
fn legacy_box_parser_rejects_unknown_fields_at_object_and_array_depths() -> TestResult {
    let mut value = serde_json::to_value(sample_box("unknown-field", "/legacy")?)?;
    value["unexpected"] = serde_json::json!(true);
    let unknown = [("unknown-field".to_owned(), value)]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    assert!(matches!(
        parse_legacy_boxes(&serde_json::to_vec(&unknown)?),
        Err(Error::Store {
            operation: "migrate",
            ..
        })
    ));

    let mut record = sample_box("array-field", "/legacy")?;
    record.spec.network = tinybox_core::NetworkPolicy::Allowlist(
        tinybox_core::EgressAllowlist::new(["example.test"], [443]),
    );
    let mut value = serde_json::to_value(record)?;
    value["spec"]["network"]["Allowlist"]["hosts"] =
        serde_json::json!(["example.test", "second.example.test"]);
    let array = [("array-field".to_owned(), value)]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    assert!(parse_legacy_boxes(&serde_json::to_vec(&array)?).is_ok());
    Ok(())
}
