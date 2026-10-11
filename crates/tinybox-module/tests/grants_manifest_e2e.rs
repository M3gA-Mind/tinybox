//! Unconditional compiled-artifact admission and local grant discovery proof.

use std::time::Duration;
use tinybus::{Connection, broker::Broker, module::ModuleHost, transport::memory::MemoryBus};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compiled_manifest_admits_and_executes_grant_and_shell_discovery()
-> Result<(), Box<dyn std::error::Error>> {
    let built_artifact = compiled_artifact()?;
    // Cargo output inherits the checkout ACL on Windows, which need not meet
    // production module admission. Stage the real artifact with private ACLs.
    let staged = tempfile::Builder::new()
        .prefix("admitted-module-")
        .tempdir_in(built_artifact.parent().ok_or("artifact has no directory")?)?;
    #[cfg(windows)]
    secure_staging_directory(staged.path())?;
    let artifact = staged.path().join(
        built_artifact
            .file_name()
            .ok_or("artifact has no filename")?,
    );
    std::fs::copy(&built_artifact, &artifact)?;
    assert!(
        artifact.is_file(),
        "compiled TinyBox artifact missing: {}",
        artifact.display()
    );
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let modules = ModuleHost::new(broker);
    let loaded = modules.load_file(&artifact)?;
    let declared: Vec<_> = loaded
        .manifest
        .provides
        .iter()
        .flat_map(|interface| interface.methods.iter())
        .map(tinybus::MemberName::as_str)
        .collect();
    assert_eq!(declared, tinybox_bus::METHODS);
    let client = Connection::connect(bus.connect().await?).await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if client
                .list_names()
                .await?
                .iter()
                .any(|name| name.as_str() == tinybox_bus::INTERFACE)
            {
                return Ok::<(), tinybus::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    let proxy = client.proxy(
        tinybox_bus::INTERFACE,
        tinybox_bus::OBJECT_PATH,
        tinybox_bus::INTERFACE,
    )?;
    let home = tempfile::tempdir()?;
    std::fs::create_dir(home.path().join("data"))?;
    let result: tinybox_bus::LocalGrants = proxy
        .call(
            "ResolveLocalGrants",
            (tinybox_bus::ResolveLocalGrantsRequest {
                home: Some(home.path().to_str().ok_or("home is not UTF-8")?.into()),
                config: tinybox_bus::LocalGrantConfig {
                    toolchain_homes: false,
                    extra_read_only: vec!["~/data".into()],
                    ..tinybox_bus::LocalGrantConfig::default()
                },
                protected: tinybox_bus::ProtectedPaths::default(),
            },),
        )
        .await?;
    assert_eq!(
        result.read_only,
        vec![
            home.path()
                .join("data")
                .canonicalize()?
                .to_str()
                .ok_or("grant is not UTF-8")?
        ]
    );
    assert_eq!(result.read_write, Vec::<String>::new());
    let selection: tinybox_bus::ShellInvocation = proxy
        .call(
            "SelectShell",
            (tinybox_bus::SelectShellRequest {
                command: "false | true".into(),
                preserve_pipeline_status: false,
            },),
        )
        .await?;
    if cfg!(windows) {
        assert_eq!(selection.flavor, tinybox_bus::ShellFlavor::Cmd);
        assert_eq!(selection.program, "cmd");
        assert_eq!(selection.arguments, ["/D", "/E:ON", "/V:OFF", "/S", "/C"]);
        assert_eq!(selection.raw_arguments.as_deref(), Some("\"false | true\""));
    } else {
        assert_eq!(selection.flavor, tinybox_bus::ShellFlavor::Posix);
        assert_eq!(selection.arguments[0], "-c");
        assert_eq!(selection.raw_arguments, None);
        assert_eq!(selection.remove_environment, ["BASH_ENV", "ENV"]);
    }
    proxy.call::<()>("Shutdown", ()).await?;
    broker_task.abort();
    Ok(())
}

fn compiled_artifact() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let executable = std::env::current_exe()?;
    let dependencies = executable
        .parent()
        .ok_or("integration test has no parent directory")?;
    let filename = format!(
        "{}tinybox{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    );
    // All-feature/static-link builds omit the dynamic ABI. Always build the
    // dynamic variant separately: another validation command may replace the
    // ordinary dependency artifact after Cargo releases its compilation lock.
    let target = dependencies
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or("integration test has no target directory")?
        .join("module-dynamic-proof");
    let status = std::process::Command::new(env!("CARGO"))
        .args([
            "build",
            "--locked",
            "--offline",
            "-p",
            "tinybox-module",
            "--no-default-features",
            "--lib",
        ])
        .arg("--manifest-path")
        .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&target)
        .status()?;
    assert!(
        status.success(),
        "default-feature dynamic artifact build failed: {status}"
    );
    Ok(target.join("debug").join(filename))
}

#[cfg(windows)]
fn secure_staging_directory(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let identity = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        ])
        .output()?;
    assert!(
        identity.status.success(),
        "current-user SID query failed: {identity:?}"
    );
    let sid = String::from_utf8(identity.stdout)?;
    let grant = format!("*{}:(OI)(CI)F", sid.trim());
    let acl = std::process::Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(grant)
        .output()?;
    assert!(
        acl.status.success(),
        "private module staging ACL failed: {acl:?}"
    );
    Ok(())
}
