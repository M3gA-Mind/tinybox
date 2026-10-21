use super::*;
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
