//! Module Docker operation tests use a local fake CLI, never a daemon.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tinybox_bus::{DockerRunRequest, MAX_DOCKER_RUN_TIMEOUT_MS};
use tinybox_docker::DockerCli;

use super::*;

fn canonical(path: &Path) -> std::io::Result<String> {
    path.canonicalize().map(|path| path.display().to_string())
}

fn has_pair(argv: &[String], flag: &str, value: &str) -> bool {
    argv.windows(2)
        .any(|pair| pair[0] == flag && pair[1] == value)
}

#[tokio::test]
async fn run_docker_preserves_one_shot_settings_output_and_timeout()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    let readonly = temp.path().join("readonly");
    std::fs::create_dir_all(&workspace)?;
    std::fs::create_dir_all(&readonly)?;
    let argv_file = temp.path().join("argv.bin");
    let script_path = temp.path().join("docker");
    std::fs::write(
        &script_path,
        format!(
            "#!/bin/sh\n: > '{}'\nfor a in \"$@\"; do printf '%s\\0' \"$a\" >> '{}'; done\nprintf out\nprintf err >&2\nexit 3\n",
            argv_file.display(),
            argv_file.display(),
        ),
    )?;
    let mut permissions = std::fs::metadata(&script_path)?.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script_path, permissions)?;

    let request = DockerRunRequest {
        workspace: workspace.display().to_string(),
        image: Some("debian:12".into()),
        command: "make test".into(),
        network: Some("bridge".into()),
        memory_limit_mb: Some(2048),
        cpus: Some(2.5),
        read_only_rootfs: Some(false),
        read_only_mounts: vec![readonly.display().to_string()],
        extra_cap_drops: vec!["NET_RAW".into(), "MKNOD".into()],
        env: [
            ("MODE".into(), "test".into()),
            ("SPACE".into(), "a b".into()),
        ]
        .into(),
        label: Some("openhuman.sandbox=true".into()),
        timeout_ms: 120_000,
    };
    let output = run_with_cli(&DockerCli::with_program(&script_path), request).await?;
    assert_eq!(output.exit_code, 3);
    assert_eq!(output.stdout, "out");
    assert_eq!(output.stderr, "err");
    assert!(!output.timed_out);

    let argv: Vec<String> = std::fs::read(&argv_file)?
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    assert!(has_pair(&argv, "--network", "bridge"));
    assert!(has_pair(&argv, "--cap-drop", "NET_RAW"));
    assert!(has_pair(&argv, "--cap-drop", "MKNOD"));
    assert!(has_pair(&argv, "-m", "2048m"));
    assert!(has_pair(&argv, "--cpus", "2.5"));
    assert!(!argv.iter().any(|argument| argument == "--read-only"));
    assert!(has_pair(
        &argv,
        "-v",
        &format!("{}:{}:ro", canonical(&readonly)?, canonical(&readonly)?)
    ));
    assert!(has_pair(&argv, "-e", "MODE=test"));
    assert!(has_pair(&argv, "-e", "SPACE=a b"));
    assert!(has_pair(&argv, "--label", "openhuman.sandbox=true"));
    assert!(has_pair(&argv, "-w", "/workspace"));
    Ok(())
}

#[test]
fn validation_rejects_unbounded_runtime() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let request = DockerRunRequest {
        workspace: "/tmp".into(),
        image: None,
        command: "true".into(),
        network: None,
        memory_limit_mb: None,
        cpus: None,
        read_only_rootfs: None,
        read_only_mounts: Vec::new(),
        extra_cap_drops: Vec::new(),
        env: std::collections::BTreeMap::new(),
        label: None,
        timeout_ms: MAX_DOCKER_RUN_TIMEOUT_MS + 1,
    };
    let error = validate(&request)
        .err()
        .ok_or("runtime should be bounded")?;
    assert_eq!(error.wire_name(), tinybox_bus::INVALID_DOCKER_RUN);
    Ok(())
}
