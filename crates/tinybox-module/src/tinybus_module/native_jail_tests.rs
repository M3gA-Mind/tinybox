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
fn explicit_native_disk_limit_is_not_ignored_by_linux_jail()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.path().into());
    let backend = tinybox_jail::LandlockBackend::new();
    if !backend.is_available() {
        return Ok(());
    }

    // Contract 2.1 introduces this field. Older serde behavior silently drops
    // unknown fields, which would turn an explicit unsupported hard limit into
    // an unrestricted native launch.
    let mut value = serde_json::to_value(config())?;
    value["allow_net"] = serde_json::Value::Bool(true);
    value["allow_subprocess"] = serde_json::Value::Bool(true);
    value["resource_request"] = serde_json::json!({ "disk_bytes": 1024 });
    let config: NativeJailConfig = serde_json::from_value(value)?;

    assert!(
        prepare(root.path(), &config, &command, &backend).is_err(),
        "the Linux native jail must refuse an explicit disk limit it cannot enforce"
    );
    Ok(())
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
fn denials_are_canonicalized_and_refused_where_a_backend_cannot_keep_them()
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

    // Outside every grant: any backend keeps it; the absent path is dropped.
    for name in ["fixture", "seatbelt"] {
        let jail = prepare(&root, &config, &command, &backend(name))?;
        assert_eq!(
            jail.deny_read,
            vec![secrets.canonicalize()?, token.canonicalize()?]
        );
    }

    // Inside a read grant: only a backend that subtracts from grants keeps it.
    config.read_only = vec![path(home.path())];
    assert!(prepare(&root, &config, &command, &backend("fixture")).is_err());
    let jail = prepare(&root, &config, &command, &backend("seatbelt"))?;
    assert_eq!(jail.deny_read.len(), 2);
    config.read_only.clear();

    // A denial over the root or a writable grant is refused everywhere.
    for denied in [path(home.path()), path(&root)] {
        config.deny_read = vec![denied];
        assert!(prepare(&root, &config, &command, &backend("seatbelt")).is_err());
    }
    config.deny_read = vec![path(&secrets)];
    config.read_write = vec![path(&secrets)];
    assert!(prepare(&root, &config, &command, &backend("seatbelt")).is_err());
    config.read_write.clear();

    // Malformed denials are refused like malformed grants.
    for bad in ["relative", "/usr/../etc", "/bad\0path"] {
        config.deny_read = vec![bad.into()];
        assert!(prepare(&root, &config, &command, &backend("seatbelt")).is_err());
    }
    Ok(())
}
