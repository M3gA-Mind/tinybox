//! Tests for the bubblewrap backend that need no working `bwrap`.

use super::*;
use std::os::unix::fs::PermissionsExt as _;

fn fake_bwrap() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-bwrap.sh")
}

fn available() -> BubblewrapBackend {
    BubblewrapBackend::unverified("/nonexistent/bwrap", true)
}

fn verified(program: &str) -> Verified {
    Verified {
        program: program.into(),
        disable_userns: true,
    }
}

fn argv_of(cmd: &Command) -> Vec<String> {
    cmd.get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn unavailable_backend_claims_nothing_and_refuses_to_spawn() {
    let backend = BubblewrapBackend { verified: None };
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
fn kernel_isolation_needs_disable_userns_support() {
    let hardened = BubblewrapBackend::unverified("/x", true);
    assert_eq!(hardened.isolation(), IsolationLevel::Kernel);
    assert!(hardened.is_suitable_for_untrusted_code());
    assert!(hardened.carves_denials());
    let old = BubblewrapBackend::unverified("/x", false);
    assert_eq!(old.isolation(), IsolationLevel::None);
    assert!(!old.is_suitable_for_untrusted_code());
    assert!(old.is_available(), "it still confines the filesystem");
}

#[test]
fn a_shared_network_namespace_is_not_suitable_for_untrusted_code() {
    let backend = available();
    let closed = Jail::new(".", "t").deny_net();
    let open = Jail::new(".", "t");
    assert!(backend.is_suitable_for_untrusted_jail(&closed));
    assert_eq!(backend.isolation_for(&closed), IsolationLevel::Kernel);
    assert!(!backend.is_suitable_for_untrusted_jail(&open));
    assert_eq!(backend.isolation_for(&open), IsolationLevel::Process);
    assert!(backend.require(&open).is_ok(), "preflight is unchanged");
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
fn caller_env_never_reaches_the_host_bwrap_process() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let mut cmd = Command::new("node");
    cmd.arg("server.js")
        .env("LD_PRELOAD", "/evil.so")
        .env("A", "1")
        .env_remove("B");
    let wrapper = prepare_command(
        &verified("/usr/bin/bwrap"),
        &Jail::new(root.path(), "t"),
        &cmd,
    )?;
    assert_eq!(wrapper.get_envs().count(), 0, "bwrap itself gets no env");
    let argv = argv_of(&wrapper);
    let clear = argv.iter().position(|a| a == "--clearenv");
    let sep = argv.iter().position(|a| a == "--");
    assert!(clear.is_some() && clear < sep);
    for (k, v) in [("LD_PRELOAD", "/evil.so"), ("A", "1")] {
        assert!(
            argv.windows(3)
                .any(|w| w[0] == "--setenv" && w[1] == k && w[2] == v),
            "{k} must be passed as --setenv"
        );
    }
    assert!(!argv.iter().any(|a| a == "B"));
    assert_eq!(
        sep.map(|i| &argv[i + 1..]),
        Some(&["node".to_owned(), "server.js".to_owned()][..])
    );
    Ok(())
}

#[test]
fn trust_requires_root_ownership_and_no_group_or_other_write() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let bin = dir.path().join("bwrap");
    std::fs::write(&bin, "#!/bin/sh\n")?;
    let is_root = std::fs::metadata(&bin)?.uid() == 0;
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
    assert_eq!(is_trusted_binary(&bin), is_root, "owner must be root");
    for mode in [0o775, 0o757, 0o777] {
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(mode))?;
        assert!(!is_trusted_binary(&bin), "{mode:o} is writable by others");
    }
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o644))?;
    assert!(!is_trusted_binary(&bin), "must be executable");
    assert!(!is_trusted_binary(&dir.path().join("missing")));
    Ok(())
}

#[test]
fn a_passthrough_shim_does_not_pass_the_isolation_probe() {
    // The fake runs its arguments unconfined: the host-only file stays visible
    // and the pid namespace is the parent's, so the probe must reject it.
    assert!(!BubblewrapBackend::with_program(fake_bwrap()).is_available());
    for program in ["/nonexistent/bwrap", "/bin/false", "/bin/true"] {
        assert!(!BubblewrapBackend::with_program(program).is_available());
    }
}

#[test]
fn spawn_runs_the_wrapped_command_through_the_launcher() -> io::Result<()> {
    let backend = BubblewrapBackend::unverified(fake_bwrap(), true);
    let root = tempfile::tempdir()?;
    let jail = Jail::new(root.path(), "t");
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg("exit 7");
    assert_eq!(backend.spawn(&jail, cmd)?.wait()?.code(), Some(7));
    Ok(())
}

#[test]
fn spawn_captured_pipes_the_wrapper_and_forwards_env_as_arguments() -> io::Result<()> {
    let backend = BubblewrapBackend::unverified(fake_bwrap(), true);
    let root = tempfile::tempdir()?;
    let jail = Jail::new(root.path(), "t");
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg("printf %s \"$A\"").env("A", "hi");
    let out = backend.spawn_captured(&jail, cmd)?.wait_with_output()?;
    // The fake drops --setenv with the other flags, so the variable is absent:
    // proof the host launcher is not what carries it.
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    Ok(())
}

#[test]
fn spawn_with_a_missing_root_is_not_found() {
    let backend = BubblewrapBackend::unverified(fake_bwrap(), true);
    let kind = backend
        .spawn(&Jail::new("/nonexistent/root", "t"), Command::new("true"))
        .err()
        .map(|e| e.kind());
    assert_eq!(kind, Some(io::ErrorKind::NotFound));
}

#[test]
fn a_leaked_descriptor_is_closed_through_the_shell_launcher() -> io::Result<()> {
    // Not reproducible without clearing CLOEXEC (see tests/bwrap_isolation.rs);
    // here, check the wrapper shape when the launcher has nothing to close.
    let root = tempfile::tempdir()?;
    let wrapper = prepare_command(
        &verified("/usr/bin/bwrap"),
        &Jail::new(root.path(), "t"),
        &Command::new("true"),
    )?;
    let leaked = fds::leaked_fds()?;
    if leaked.is_empty() {
        assert_eq!(wrapper.get_program(), "/usr/bin/bwrap");
    } else {
        // Whatever the environment leaked is closed by a shell first.
        assert!(
            wrapper.get_program().to_string_lossy().ends_with("sh"),
            "{:?}",
            wrapper.get_program()
        );
        assert!(argv_of(&wrapper).iter().any(|a| a.contains(">&-")));
    }
    Ok(())
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn a_launcher_that_passes_the_probe_is_available_with_kernel_isolation() {
    let backend = BubblewrapBackend::with_program(fixture("fake-bwrap-probe.sh"));
    assert!(backend.is_available());
    assert_eq!(backend.isolation(), IsolationLevel::Kernel);
    assert_eq!(
        backend.program(),
        Some(fixture("fake-bwrap-probe.sh").as_path())
    );
}

#[test]
fn a_bwrap_without_disable_userns_is_available_but_claims_no_isolation() {
    let backend = BubblewrapBackend::with_program(fixture("fake-bwrap-old.sh"));
    assert!(backend.is_available());
    assert_eq!(backend.isolation(), IsolationLevel::None);
    assert!(!backend.is_suitable_for_untrusted_code());
}

#[test]
fn the_default_constructor_probes_only_trusted_paths() {
    let backend = BubblewrapBackend::new();
    if let Some(program) = backend.program() {
        assert!(TRUSTED_PATHS.iter().any(|p| Path::new(p) == program));
        assert!(is_trusted_binary(program));
    }
    assert_eq!(
        BubblewrapBackend::default().is_available(),
        backend.is_available()
    );
}
