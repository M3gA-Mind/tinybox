//! Validation and environment behavior before process admission.
use super::*;
fn request(state: &Path) -> ShellExecRequest {
    ShellExecRequest {
        process: tinybox_bus::ResourceId("p".into()),
        resource: tinybox_bus::ResourceId("r".into()),
        shell: tinybox_bus::SelectShellRequest {
            command: "echo accepted".into(),
            preserve_pipeline_status: false,
        },
        cwd: None,
        extra_env: std::collections::BTreeMap::new(),
        state_dir: state.to_string_lossy().into_owned(),
        timeout_ms: 1000,
        stdin: None,
        jail: None,
    }
}
#[test]
fn invalid_shell_state_budget_and_environment_are_refused_before_execution()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let state = tempfile::tempdir()?;
    let resolved = tinybox_core::ExecRequest::new(["unused"]);
    let original = request(state.path());
    for timeout in [0, 86_400_001] {
        let mut invalid = original.clone();
        invalid.timeout_ms = timeout;
        assert!(ShellContext::prepare(invalid, state.path(), &resolved).is_err());
    }
    for directory in ["relative", "absent", "nul\0"] {
        let mut invalid = original.clone();
        invalid.state_dir = directory.into();
        assert!(ShellContext::prepare(invalid, state.path(), &resolved).is_err());
    }
    let file = state.path().join("file");
    std::fs::write(&file, "data")?;
    let mut invalid = original.clone();
    invalid.state_dir = file.to_string_lossy().into_owned();
    assert!(ShellContext::prepare(invalid, state.path(), &resolved).is_err());
    let mut invalid = original.clone();
    invalid.shell.command = "nul\0".into();
    assert!(ShellContext::prepare(invalid, state.path(), &resolved).is_err());
    for (name, value) in [("", "value"), ("NAME=bad", "value"), ("NAME", "nul\0")] {
        let mut invalid = original.clone();
        invalid.extra_env.insert(name.into(), value.into());
        assert!(ShellContext::prepare(invalid, state.path(), &resolved).is_err());
    }
    Ok(())
}
#[test]
fn approved_environment_overrides_preserve_custom_temporary_directory_and_remove_startup_hooks()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let state = tempfile::tempdir()?;
    let resolved = tinybox_core::ExecRequest::new(["unused"]);
    let mut request = request(state.path());
    request
        .extra_env
        .insert("TMPDIR".into(), "approved-temporary-location".into());
    request
        .extra_env
        .insert("SHELLOPTS".into(), "errexit".into());
    let shell = ShellContext::prepare(request, state.path(), &resolved)?;
    assert_eq!(
        shell.environment.get("TMPDIR").map(String::as_str),
        Some("approved-temporary-location")
    );
    #[cfg(unix)]
    assert_eq!(shell.environment.get("SHELLOPTS"), None);
    assert!(!shell.pending());
    Ok(())
}
