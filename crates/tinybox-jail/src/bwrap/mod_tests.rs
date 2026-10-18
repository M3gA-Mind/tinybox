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
