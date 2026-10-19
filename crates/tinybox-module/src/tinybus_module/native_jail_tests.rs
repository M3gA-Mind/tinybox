//! Native grant and enforcement preflight uses local files and mock facts.
use super::*;

struct Backend {
    available: bool,
    suitable: bool,
    name: &'static str,
    full: bool,
}
impl JailBackend for Backend {
    fn name(&self) -> &'static str {
        self.name
    }
    fn is_available(&self) -> bool {
        self.available
    }
    fn isolation(&self) -> tinybox_core::IsolationLevel {
        tinybox_core::IsolationLevel::None
    }
    fn is_suitable_for_untrusted_code(&self) -> bool {
        self.suitable
    }
    fn carves_denials(&self) -> bool {
        self.name == "seatbelt"
    }
    fn constraint_support(&self) -> tinybox_core::ConstraintSupport {
        use tinybox_core::{Constraint, ConstraintSupport, Enforcement};
        if self.full {
            ConstraintSupport::NONE
                .with(Constraint::Filesystem, Enforcement::Enforced)
                .with(Constraint::Network, Enforcement::Enforced)
                .with(Constraint::Subprocess, Enforcement::Enforced)
                .with(Constraint::Cpu, Enforcement::BestEffort)
                .with(Constraint::Memory, Enforcement::BestEffort)
                .with(Constraint::Pids, Enforcement::BestEffort)
                .with(Constraint::Disk, Enforcement::BestEffort)
        } else {
            ConstraintSupport::NONE.with(Constraint::Filesystem, Enforcement::BestEffort)
        }
    }
    fn spawn(&self, _: &Jail, _: std::process::Command) -> std::io::Result<std::process::Child> {
        Err(std::io::Error::other("preflight fixture never spawns"))
    }
}

struct BaselineBackend(Backend, std::path::PathBuf);
impl JailBackend for BaselineBackend {
    fn name(&self) -> &'static str {
        self.0.name
    }
    fn is_available(&self) -> bool {
        self.0.available
    }
    fn constraint_support(&self) -> tinybox_core::ConstraintSupport {
        self.0.constraint_support()
    }
    fn implicit_grants(&self) -> Vec<std::path::PathBuf> {
        vec![self.1.clone()]
    }
    fn spawn(
        &self,
        jail: &Jail,
        cmd: std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        self.0.spawn(jail, cmd)
    }
}

fn config() -> NativeJailConfig {
    NativeJailConfig {
        read_only: vec![],
        read_write: vec![],
        allow_net: false,
        allow_subprocess: false,
        enforcement: JailEnforcement::Enforced,
        require_process_isolation: false,
        deny_read: Vec::new(),
        resources: None,
    }
}

#[cfg(unix)]
#[test]
fn requested_native_resource_limits_are_refused_before_spawn()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.path().into());
    let backend = Backend {
        available: true,
        suitable: false,
        name: "fixture",
        full: true,
    };
    let mut config = config();
    config.enforcement = JailEnforcement::Declared;
    config.resources = Some(tinybox_bus::ResourceLimits {
        cpu_millis: 500,
        memory_bytes: 1024 * 1024,
        pids_max: 32,
        disk_bytes: 1024 * 1024,
    });
    // Declared enforcement accepts best-effort filesystem constraints, but a
    // resource budget remains a hard requirement and must refuse before spawn.
    assert!(prepare(root.path(), &config, &command, &backend).is_err());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn legacy_resource_limits_still_fail_closed_on_linux()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.path().into());
    let backend = tinybox_jail::LandlockBackend::new();
    if !backend.is_available() {
        return Ok(());
    }

    // Contract 1.22's all-dimensions request remains hard and unsupported by
    // the Landlock-only path. The new 2.1 subset request uses a separate API.
    let mut config = config();
    config.resources = Some(tinybox_bus::ResourceLimits {
        cpu_millis: 100,
        memory_bytes: 64 * 1024 * 1024,
        pids_max: 16,
        disk_bytes: 1024,
    });

    assert!(
        prepare(root.path(), &config, &command, &backend).is_err(),
        "legacy Linux native jail must refuse the unsupported all-resource request"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn resource_aware_namespace_jail_preserves_grants_and_blocks_manager_escape()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::process::{Command, Stdio};

    let root = tempfile::tempdir()?;
    let workspace = root.path().join("workspace");
    let hidden = workspace.join("hidden");
    std::fs::create_dir_all(&hidden)?;
    std::fs::write(hidden.join("secret"), "secret")?;
    let denied_inside = workspace.join("denied-inside");
    std::fs::create_dir_all(&denied_inside)?;
    std::fs::write(denied_inside.join("secret"), "secret")?;
    let outside = std::env::temp_dir().join(format!("tinybox-escape-proof-{}", std::process::id()));
    let _ = std::fs::remove_file(&outside);
    let bash_env = workspace.join("startup.sh");
    std::fs::write(
        &bash_env,
        format!(
            "printf startup > {}\n",
            shell_quote(&workspace.join("from-bash-env").display().to_string())
        ),
    )?;

    let probe = Command::new("systemd-run")
        .args([
            "--user",
            "--scope",
            "--quiet",
            "--property=CPUQuota=0.1%",
            "--property=MemoryMax=67108864",
            "--property=MemorySwapMax=0",
            "--property=TasksMax=16",
            "--",
            "/bin/true",
        ])
        .status()?;
    if !probe.success() {
        eprintln!("skipped: user systemd scope constraints are unavailable");
        return Ok(());
    }

    let mut jail = config();
    jail.allow_net = false;
    jail.allow_subprocess = true;
    jail.require_process_isolation = true;
    jail.deny_read = vec![denied_inside.display().to_string()];
    let request = tinybox_bus::NativeJailRequest {
        jail,
        resources: Some(tinybox_bus::NativeJailResourceRequest {
            cpu_millis: Some(1),
            memory_bytes: Some(64 * 1024 * 1024),
            pids_max: Some(16),
            disk_bytes: None,
        }),
    };
    let script = format!(
        "printf allowed > {}; test ! -e {} || exit 41; test ! -r {} || exit 42; if systemd-run --user --scope --quiet -- /usr/bin/touch {} 2>/dev/null; then exit 43; fi; exit 0",
        shell_quote(&workspace.join("control").display().to_string()),
        shell_quote(&denied_inside.join("secret").display().to_string()),
        shell_quote(&denied_inside.join("secret").display().to_string()),
        shell_quote(&outside.display().to_string()),
    );
    let mut command = tinybox_core::ExecRequest::new(["/bin/bash", "-c", &script]);
    command.cwd = Some(workspace.clone());
    command
        .env
        .insert("BASH_ENV".into(), bash_env.display().to_string());
    let backend = resource_backend();
    let jail = prepare_with_resources(
        root.path().join("workspace").as_path(),
        &request,
        &mut command,
        backend.as_ref(),
    )?;
    let mut child_command = Command::new(command.argv.first().ok_or("missing launcher")?);
    child_command
        .args(command.argv.iter().skip(1))
        .env_clear()
        .envs(&command.env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = tinybox_jail::spawn_captured_with(backend.as_ref(), &jail, child_command)?;
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "launcher failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(workspace.join("control"))?, b"allowed");
    assert_eq!(std::fs::read(workspace.join("from-bash-env"))?, b"startup");
    assert!(!outside.exists(), "jail wrote outside its granted roots");
    let _ = std::fs::remove_file(outside);
    Ok(())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
#[test]
fn native_grants_reject_relative_parent_null_and_missing_paths() {
    assert!(grants(&["/".repeat(tinybox_bus::MAX_FILE_PATH_BYTES + 1)]).is_err());
    for path in [
        "relative",
        "/usr/../etc",
        "/bad\0path",
        "/tinybox-missing-test-grant",
    ] {
        assert!(grants(&[path.into()]).is_err());
    }
}
#[test]
fn unavailable_and_noop_backends_never_accept_declared_enforcement()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let mut request = tinybox_core::ExecRequest::new(["irrelevant"]);
    request.cwd = Some(temp.path().into());
    for (available, name) in [(false, "fixture"), (true, tinybox_jail::NOOP_BACKEND_NAME)] {
        let backend = Backend {
            available,
            suitable: true,
            name,
            full: true,
        };
        let mut config = config();
        config.enforcement = JailEnforcement::Declared;
        assert!(prepare(temp.path(), &config, &request, &backend).is_err());
    }
    Ok(())
}
#[cfg(unix)]
#[test]
fn approved_grants_preserve_flags_and_preflight_refuses_weaker_facts()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let extra = tempfile::tempdir()?;
    let file = root.path().join("file");
    std::fs::write(&file, b"data")?;
    let backend = Backend {
        available: true,
        suitable: false,
        name: "fixture",
        full: true,
    };
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.path().into());
    let mut config = config();
    config.read_only.push(file.to_string_lossy().into_owned());
    config
        .read_write
        .push(extra.path().to_string_lossy().into_owned());
    let jail = prepare(root.path(), &config, &command, &backend)?;
    assert_eq!(jail.root, root.path().canonicalize()?);
    assert_eq!(jail.read_only, vec![file.canonicalize()?]);
    assert_eq!(jail.read_write, vec![extra.path().canonicalize()?]);
    assert!(!jail.allow_net && !jail.allow_subprocess);
    config.require_process_isolation = true;
    assert!(prepare(root.path(), &config, &command, &backend).is_err());
    config.require_process_isolation = false;
    let weak = Backend {
        available: true,
        suitable: false,
        name: "fixture",
        full: false,
    };
    assert!(prepare(root.path(), &config, &command, &weak).is_err());
    config.enforcement = JailEnforcement::Declared;
    assert!(prepare(root.path(), &config, &command, &weak).is_err());
    config.allow_net = true;
    config.allow_subprocess = true;
    assert!(prepare(root.path(), &config, &command, &weak).is_ok());
    config.read_only = vec!["/".into(); tinybox_bus::MAX_NATIVE_JAIL_GRANTS + 1];
    assert!(prepare(root.path(), &config, &command, &backend).is_err());
    config.read_only.clear();
    command.cwd = Some(extra.path().into());
    assert!(prepare(root.path(), &config, &command, &backend).is_err());
    command.cwd = None;
    assert!(prepare(root.path(), &config, &command, &backend).is_err());
    assert!(prepare(&file, &config, &command, &backend).is_err());
    assert!(prepare(&root.path().join("missing"), &config, &command, &backend).is_err());
    command.cwd = Some(root.path().join("missing"));
    assert!(prepare(root.path(), &config, &command, &backend).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn declared_enforcement_rejects_each_unsupported_requested_constraint()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use tinybox_core::{Constraint, ConstraintSupport, Enforcement};
    struct DeclaredBackend(ConstraintSupport);
    impl JailBackend for DeclaredBackend {
        fn name(&self) -> &'static str {
            "declared fixture"
        }
        fn is_available(&self) -> bool {
            true
        }
        fn isolation(&self) -> tinybox_core::IsolationLevel {
            tinybox_core::IsolationLevel::None
        }
        fn constraint_support(&self) -> ConstraintSupport {
            self.0
        }
        fn spawn(
            &self,
            _: &Jail,
            _: std::process::Command,
        ) -> std::io::Result<std::process::Child> {
            Err(std::io::Error::other("preflight fixture never spawns"))
        }
    }
    let root = tempfile::tempdir()?;
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.path().into());
    let mut config = config();
    config.enforcement = JailEnforcement::Declared;
    let constraints = [
        Constraint::Filesystem,
        Constraint::Network,
        Constraint::Subprocess,
    ];
    let supported = constraints
        .iter()
        .fold(ConstraintSupport::NONE, |support, &constraint| {
            support.with(constraint, Enforcement::BestEffort)
        });
    assert!(prepare(root.path(), &config, &command, &DeclaredBackend(supported)).is_ok());
    for constraint in constraints {
        let unsupported = supported.with(constraint, Enforcement::Unsupported);
        assert!(
            prepare(
                root.path(),
                &config,
                &command,
                &DeclaredBackend(unsupported)
            )
            .is_err(),
            "unsupported {constraint} must be rejected before execution"
        );
    }
    assert!(
        prepare(
            root.path(),
            &config,
            &command,
            &DeclaredBackend(ConstraintSupport::NONE)
        )
        .is_err()
    );
    Ok(())
}

// `prepare` refuses every native jail off Unix before reading any path.
#[cfg(unix)]
#[test]
fn denials_preserve_prospective_roots_and_refuse_unenforceable_overlaps()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    let root = home.path().join("project");
    let secrets = home.path().join(".ssh");
    let token = home.path().join(".netrc");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(&secrets)?;
    std::fs::write(&token, b"secret")?;
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.clone());
    let backend = |name| Backend {
        available: true,
        suitable: false,
        name,
        full: true,
    };
    let path = |p: &std::path::Path| p.to_string_lossy().into_owned();
    let mut config = config();
    config.deny_read = vec![
        path(&secrets),
        path(&token),
        path(&home.path().join(".aws")),
    ];
    let canonical_home = home.path().canonicalize()?;
    let mut expected = vec![
        secrets.clone(),
        token.clone(),
        home.path().join(".aws"),
        canonical_home.join(".ssh"),
        canonical_home.join(".netrc"),
        canonical_home.join(".aws"),
    ];
    expected.sort();
    expected.dedup();

    // Outside every grant: retain absent roots so a later-created credential
    // store remains denied by the backend.
    for name in ["fixture", "seatbelt"] {
        let jail = prepare(&root, &config, &command, &backend(name))?;
        assert_eq!(jail.deny_read, expected);
    }

    // Inside a read grant: only a backend that subtracts from grants keeps it.
    config.read_only = vec![path(home.path())];
    assert!(prepare(&root, &config, &command, &backend("fixture")).is_err());
    let jail = prepare(&root, &config, &command, &backend("seatbelt"))?;
    assert_eq!(jail.deny_read, expected);
    config.deny_read = vec![path(&home.path().join(".future-credential-store"))];
    assert!(prepare(&root, &config, &command, &backend("fixture")).is_err());
    assert!(prepare(&root, &config, &command, &backend("seatbelt")).is_ok());
    config.read_only.clear();
    config.deny_read = vec![path(&root.join(".future-credential-store"))];
    assert!(prepare(&root, &config, &command, &backend("fixture")).is_err());
    assert!(prepare(&root, &config, &command, &backend("seatbelt")).is_ok());

    // A denial over the root or a writable grant is refused everywhere.
    for denied in [path(home.path()), path(&root)] {
        config.deny_read = vec![denied];
        assert!(prepare(&root, &config, &command, &backend("seatbelt")).is_err());
    }
    config.deny_read = vec![path(&secrets)];
    config.read_write = vec![path(&secrets)];
    assert!(prepare(&root, &config, &command, &backend("seatbelt")).is_err());
    config.read_write.clear();

    // Seatbelt's final deny rule can carve a nested path out of a writable
    // grant, but it cannot preserve the grant if the denial contains it.
    config.read_write = vec![path(home.path())];
    config.deny_read = vec![path(&secrets)];
    assert!(prepare(&root, &config, &command, &backend("seatbelt")).is_ok());
    config.deny_read = vec![path(home.path())];
    assert!(prepare(&root, &config, &command, &backend("seatbelt")).is_err());
    config.read_write.clear();

    // Malformed denials are refused like malformed grants.
    for bad in ["relative", "/usr/../etc", "/bad\0path"] {
        config.deny_read = vec![bad.into()];
        assert!(prepare(&root, &config, &command, &backend("seatbelt")).is_err());
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn allow_list_backend_rejects_denials_over_implicit_baseline_grants()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("workspace");
    let baseline = temp.path().join("implicit-read-root");
    let alias = temp.path().join("implicit-read-alias");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(&baseline)?;
    std::os::unix::fs::symlink(&baseline, &alias)?;
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.clone());
    let mut config = config();
    config.deny_read = vec![
        baseline
            .join("future-credential")
            .to_string_lossy()
            .into_owned(),
    ];

    let backend = BaselineBackend(
        Backend {
            available: true,
            suitable: false,
            name: "allow-list",
            full: true,
        },
        alias,
    );

    assert!(prepare(&root, &config, &command, &backend).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn allow_list_preflight_keeps_future_implicit_grants_protected()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("workspace");
    let future_baseline = temp.path().join("baseline-created-before-spawn");
    std::fs::create_dir(&root)?;
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.clone());
    let mut config = config();
    config.deny_read = vec![
        future_baseline
            .join("future-credential")
            .to_string_lossy()
            .into_owned(),
    ];
    let backend = BaselineBackend(
        Backend {
            available: true,
            suitable: false,
            name: "allow-list",
            full: true,
        },
        future_baseline,
    );

    assert!(prepare(&root, &config, &command, &backend).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn prospective_denials_resolve_existing_aliases_and_refuse_dangling_symlinks()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir()?;
    let link = dir.path().join("credential-link");
    symlink(dir.path().join("future-target"), &link)?;
    assert!(denials(&[link.to_string_lossy().into_owned()]).is_err());

    let target = dir.path().join("real-home");
    std::fs::create_dir(&target)?;
    let alias = dir.path().join("home-alias");
    symlink(&target, &alias)?;
    let prospective = alias.join(".ssh");
    let roots = denials(&[prospective.to_string_lossy().into_owned()])?;
    let mut expected = vec![prospective.clone(), target.canonicalize()?.join(".ssh")];
    expected.sort();
    expected.dedup();
    assert!(roots.contains(&prospective));
    assert_eq!(roots, expected);

    let first_loop = dir.path().join("loop-a");
    let second_loop = dir.path().join("loop-b");
    symlink(&second_loop, &first_loop)?;
    symlink(&first_loop, &second_loop)?;
    assert!(denials(&[first_loop.to_string_lossy().into_owned()]).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn collector_builds_a_host_from_a_valid_native_jail()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.path().to_path_buf());

    let backend: Arc<dyn JailBackend> = Arc::new(Backend {
        available: true,
        suitable: true,
        name: "fixture",
        full: true,
    });
    let _collector = collector(root.path(), &config(), &command, backend)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn spawn_rejects_a_prospective_denial_symlinked_into_the_jail()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;
    let home = tempfile::tempdir()?;
    let root = home.path().join("project");
    std::fs::create_dir(&root)?;
    let credential = root.join("credential");
    std::fs::write(&credential, b"secret")?;
    let prospective = home.path().join(".credential-store");
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.clone());
    let backend = Backend {
        available: true,
        suitable: false,
        name: "fixture",
        full: true,
    };
    let mut native = config();
    native.allow_net = true;
    native.allow_subprocess = true;
    native.deny_read = vec![path_string(&prospective)];
    let jail = prepare(&root, &native, &command, &backend)?;

    symlink(&credential, &prospective)?;
    let error =
        tinybox_jail::spawn_captured_with(&backend, &jail, std::process::Command::new("true"))
            .err();
    assert_eq!(
        error.map(|error| error.kind()),
        Some(std::io::ErrorKind::InvalidInput)
    );
    Ok(())
}

fn path_string(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(target_os = "linux")]
#[test]
fn landlock_keeps_a_denied_path_unreadable_when_created_after_preflight()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let backend = tinybox_jail::LandlockBackend::new();
    if !backend.is_available() {
        eprintln!("skipped: Landlock is not supported by this kernel");
        return Ok(());
    }
    let home = tempfile::tempdir()?;
    let root = home.path().join("project");
    std::fs::create_dir(&root)?;
    let credential = home.path().join(".future-store").join("token");
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.clone());
    let mut native = config();
    native.allow_net = true;
    native.allow_subprocess = true;
    native.deny_read = vec![
        home.path()
            .join(".future-store")
            .to_string_lossy()
            .into_owned(),
    ];
    let mut uncarvable_root_child = native.clone();
    uncarvable_root_child.deny_read =
        vec![root.join(".future-store").to_string_lossy().into_owned()];
    assert!(prepare(&root, &uncarvable_root_child, &command, &backend).is_err());
    let jail = prepare(&root, &native, &command, &backend)?;
    assert!(jail.deny_read.contains(&home.path().join(".future-store")));

    std::fs::create_dir(home.path().join(".future-store"))?;
    std::fs::write(&credential, "secret")?;
    let allowed = root.join("allowed.txt");
    std::fs::write(&allowed, "allowed-read-control\n")?;
    let output = tinybox_jail::spawn_captured_with(&backend, &jail, {
        let mut shell = std::process::Command::new("/bin/sh");
        shell.arg("-c").arg(format!(
            "cat '{}' && cat '{}' >/dev/null",
            allowed.display(),
            credential.display()
        ));
        shell
    })?
    .wait_with_output()?;
    assert_eq!(output.stdout, b"allowed-read-control\n");
    assert!(!output.status.success());
    Ok(())
}
