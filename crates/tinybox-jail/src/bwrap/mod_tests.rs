//! Tests for the bubblewrap backend that need no working `bwrap`.

use super::*;

fn unavailable() -> BubblewrapBackend {
    BubblewrapBackend { program: None }
}

fn available() -> BubblewrapBackend {
    BubblewrapBackend {
        program: Some(PathBuf::from("/nonexistent/bwrap")),
    }
}

#[test]
fn unavailable_backend_claims_nothing_and_refuses_to_spawn() {
    let backend = unavailable();
    assert_eq!(backend.name(), "bubblewrap");
    assert!(!backend.is_available());
    assert_eq!(backend.isolation(), IsolationLevel::None);
    assert!(!backend.is_suitable_for_untrusted_code());
    let kind = backend
        .spawn(&Jail::new(".", "t"), Command::new("true"))
        .err()
        .map(|e| e.kind());
    assert_eq!(kind, Some(io::ErrorKind::Unsupported));
}

#[test]
fn available_backend_reports_kernel_isolation_and_is_untrusted_safe() {
    let backend = available();
    assert_eq!(backend.isolation(), IsolationLevel::Kernel);
    assert!(backend.is_suitable_for_untrusted_code());
    assert!(backend.carves_denials());
    let jail = Jail::new(".", "t").deny_net();
    assert!(backend.require(&jail).is_ok());
}

#[test]
fn subprocess_denial_is_refused_because_it_is_not_enforced() {
    let backend = available();
    let jail = Jail::new(".", "t").deny_subprocess();
    assert!(backend.require(&jail).is_err());
    let kind = backend
        .spawn(&jail, Command::new("true"))
        .err()
        .map(|e| e.kind());
    assert_eq!(kind, Some(io::ErrorKind::Unsupported));
}

#[test]
fn wrapped_command_keeps_program_args_and_explicit_env() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let mut cmd = Command::new("node");
    cmd.arg("server.js").env("A", "1").env_remove("B");
    let wrapper = prepare_command(
        std::path::Path::new("/usr/bin/bwrap"),
        &Jail::new(root.path(), "t"),
        &cmd,
    )?;
    let argv: Vec<_> = wrapper
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let sep = argv.iter().position(|a| a == "--");
    assert_eq!(
        sep.map(|i| &argv[i + 1..]),
        Some(&["node".to_owned(), "server.js".to_owned()][..])
    );
    let envs: Vec<_> = wrapper.get_envs().collect();
    assert_eq!(envs.len(), 1);
    Ok(())
}

fn fake_bwrap() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-bwrap.sh")
}

#[test]
fn a_working_bwrap_makes_the_backend_available() {
    let backend = BubblewrapBackend::with_program(fake_bwrap());
    assert!(backend.is_available());
    assert_eq!(backend.program(), Some(fake_bwrap().as_path()));
    assert_eq!(
        backend
            .constraint_support()
            .enforcement(Constraint::Network),
        Enforcement::Enforced
    );
}

#[test]
fn a_bwrap_that_cannot_start_a_sandbox_is_unavailable() {
    for program in ["/nonexistent/bwrap", "/bin/false"] {
        let backend = BubblewrapBackend::with_program(program);
        assert!(!backend.is_available(), "{program}");
        assert_eq!(backend.program(), None);
        assert_eq!(backend.isolation(), IsolationLevel::None);
    }
}

#[test]
fn spawn_runs_the_wrapped_command_through_the_launcher() -> io::Result<()> {
    let backend = BubblewrapBackend::with_program(fake_bwrap());
    let root = tempfile::tempdir()?;
    let jail = Jail::new(root.path(), "t");
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg("exit 7");
    assert_eq!(backend.spawn(&jail, cmd)?.wait()?.code(), Some(7));
    Ok(())
}

#[test]
fn spawn_captured_pipes_the_wrapper_and_forwards_env() -> io::Result<()> {
    let backend = BubblewrapBackend::with_program(fake_bwrap());
    let root = tempfile::tempdir()?;
    let jail = Jail::new(root.path(), "t");
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg("printf %s \"$A\"").env("A", "hi");
    let out = backend.spawn_captured(&jail, cmd)?.wait_with_output()?;
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hi");
    Ok(())
}

#[test]
fn spawn_with_a_missing_root_is_not_found() {
    let backend = BubblewrapBackend::with_program(fake_bwrap());
    let kind = backend
        .spawn(&Jail::new("/nonexistent/root", "t"), Command::new("true"))
        .err()
        .map(|e| e.kind());
    assert_eq!(kind, Some(io::ErrorKind::NotFound));
}
