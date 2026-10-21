use super::*;
use tempfile::TempDir;
use tinybox_core::BoxId;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn args(values: &[&str]) -> Vec<std::ffi::OsString> {
    values.iter().map(std::ffi::OsString::from).collect()
}

fn is_exit_code(actual: ExitCode, expected: ExitCode) -> bool {
    format!("{actual:?}") == format!("{expected:?}")
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
