//! Validate approved native grants before reserving or starting a child.
use std::{
    path::{Component, Path},
    sync::Arc,
};
use tinybox_bus::{JailEnforcement, NativeJailConfig};
use tinybox_jail::{Jail, JailBackend};
use tinybus::{Error, Result};

pub(super) fn prepare(
    root: &Path,
    config: &NativeJailConfig,
    command: &tinybox_core::ExecRequest,
    backend: &dyn JailBackend,
) -> Result<Jail> {
    if !cfg!(unix) || !backend.is_available() || backend.name() == tinybox_jail::NOOP_BACKEND_NAME {
        return Err(unavailable());
    }
    if config.require_process_isolation && !backend.is_suitable_for_untrusted_code() {
        return Err(unavailable());
    }
    if config.read_only.len() + config.read_write.len() + config.deny_read.len()
        > tinybox_bus::MAX_NATIVE_JAIL_GRANTS
    {
        return Err(invalid());
    }
    let root = root.canonicalize().map_err(|_| invalid())?;
    if !root.is_dir() {
        return Err(invalid());
    }
    let cwd = command.cwd.as_ref().ok_or_else(invalid)?;
    if !cwd
        .canonicalize()
        .map_err(|_| invalid())?
        .starts_with(&root)
    {
        return Err(invalid());
    }
    let mut jail = Jail::new(root, "tinybox.module");
    jail.allow_net = config.allow_net;
    jail.allow_subprocess = config.allow_subprocess;
    jail.read_only = grants(&config.read_only)?;
    jail.read_write = grants(&config.read_write)?;
    jail.deny_read = denials(&config.deny_read)?;
    jail.resources = config.resources.map(|limits| tinybox_core::Resources {
        cpu_millis: limits.cpu_millis,
        memory_bytes: limits.memory_bytes,
        pids_max: limits.pids_max,
        disk_bytes: limits.disk_bytes,
    });
    if jail
        .resources
        .is_some_and(|limits| limits.validate().is_err())
    {
        return Err(invalid());
    }
    // A denial over the root or a writable grant would leave the command no
    // workspace; that is a host error, not a weaker jail.
    if jail.deny_read.iter().any(|denied| {
        std::iter::once(&jail.root)
            .chain(&jail.read_write)
            .any(|granted| granted.starts_with(denied))
    }) {
        return Err(invalid());
    }
    // Inside the root or a grant, only a backend that subtracts from grants
    // can keep the denial; outside them nothing grants the path anyway.
    if !backend.carves_denials()
        && jail.deny_read.iter().any(|denied| {
            std::iter::once(&jail.root)
                .chain(&jail.read_only)
                .chain(&jail.read_write)
                .any(|granted| denied.starts_with(granted))
        })
    {
        return Err(unavailable());
    }
    backend
        .require_resources(&jail)
        .map_err(|_| unavailable())?;
    match config.enforcement {
        JailEnforcement::Enforced => backend.require(&jail).map_err(|_| unavailable())?,
        JailEnforcement::Declared => {
            if backend
                .plan_check(&jail)
                .constraints
                .iter()
                .any(|(_, support)| *support == tinybox_core::Enforcement::Unsupported)
            {
                return Err(unavailable());
            }
        }
    }
    Ok(jail)
}

/// Prepare the distinct 2.1 subset request, preserving the existing 2.0
/// `NativeJailConfig` and rewriting the execution into the trusted namespace
/// launcher. The target environment is carried only by bubblewrap's explicit
/// `--setenv` arguments, never by systemd-run or bwrap setup.
pub(super) fn prepare_with_resources(
    root: &Path,
    request: &tinybox_bus::NativeJailRequest,
    command: &mut tinybox_core::ExecRequest,
    backend: &dyn JailBackend,
) -> Result<Jail> {
    if !cfg!(target_os = "linux") {
        return Err(unavailable());
    }
    if request.jail.resources.is_some() {
        // The legacy all-four request has different semantics and is handled
        // only by StartJailedExec; never reinterpret it as a subset.
        return Err(unavailable());
    }
    let limits = request.resources.ok_or_else(unavailable)?;
    if limits.cpu_millis.is_none()
        && limits.memory_bytes.is_none()
        && limits.pids_max.is_none()
        && limits.disk_bytes.is_none()
    {
        return Err(unavailable());
    }
    let mut jail = prepare(root, &request.jail, command, backend)?;
    jail.native_resources = Some(limits);
    backend
        .require_resources(&jail)
        .map_err(|_| unavailable())?;

    let native = tinybox_linux::NativeJailCommand {
        root: jail.root.clone(),
        cwd: command.cwd.clone().ok_or_else(invalid)?,
        read_only: jail.read_only.clone(),
        read_write: jail.read_write.clone(),
        deny_read: jail.deny_read.clone(),
        allow_net: jail.allow_net,
        allow_subprocess: jail.allow_subprocess,
        cpu_millis: limits.cpu_millis,
        memory_bytes: limits.memory_bytes,
        pids_max: limits.pids_max,
        argv: command.argv.clone(),
        env: command.env.clone(),
    };
    command.argv = tinybox_linux::native_jail_argv(&native).map_err(|_| unavailable())?;
    command.env = launcher_environment();
    command.cwd = None;
    Ok(jail)
}

fn launcher_environment() -> std::collections::BTreeMap<String, String> {
    // systemd-run needs the user's session bus coordinates. Values capable of
    // changing dynamic loading or shell startup are intentionally excluded.
    [
        "PATH",
        "HOME",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "SYSTEMD_BUS_ADDRESS",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    ]
    .into_iter()
    .filter_map(|key| std::env::var(key).ok().map(|value| (key.to_owned(), value)))
    .collect()
}

#[cfg(target_os = "linux")]
pub(super) fn resource_backend() -> Arc<dyn JailBackend> {
    Arc::new(NativeResourceBackend)
}

#[cfg(target_os = "linux")]
struct NativeResourceBackend;

#[cfg(target_os = "linux")]
impl JailBackend for NativeResourceBackend {
    fn name(&self) -> &'static str {
        "native-resource-namespace"
    }
    fn is_available(&self) -> bool {
        fn on_path(program: &str) -> bool {
            std::env::var_os("PATH").is_some_and(|path| {
                std::env::split_paths(&path).any(|dir| dir.join(program).is_file())
            })
        }
        on_path("systemd-run") && on_path("bwrap")
    }
    fn constraint_support(&self) -> tinybox_core::ConstraintSupport {
        use tinybox_core::{Constraint, ConstraintSupport, Enforcement};
        ConstraintSupport::NONE
            .with(Constraint::Filesystem, Enforcement::Enforced)
            .with(Constraint::Network, Enforcement::Enforced)
            .with(Constraint::Cpu, Enforcement::Enforced)
            .with(Constraint::Memory, Enforcement::Enforced)
            .with(Constraint::Pids, Enforcement::Enforced)
    }
    fn isolation(&self) -> tinybox_core::IsolationLevel {
        tinybox_core::IsolationLevel::Kernel
    }
    fn carves_denials(&self) -> bool {
        true
    }
    fn spawn(
        &self,
        jail: &Jail,
        mut command: std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        if jail.native_resources.is_none()
            || command.get_program() != std::ffi::OsStr::new("systemd-run")
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "resource backend accepts only the prepared systemd-run launcher",
            ));
        }
        command.spawn()
    }
}
fn grants(paths: &[String]) -> Result<Vec<std::path::PathBuf>> {
    paths
        .iter()
        .map(|value| {
            let path = Path::new(value);
            if value.len() > tinybox_bus::MAX_FILE_PATH_BYTES
                || value.contains('\0')
                || !path.is_absolute()
                || path
                    .components()
                    .any(|part| matches!(part, Component::ParentDir))
            {
                return Err(invalid());
            }
            path.canonicalize().map_err(|_| invalid())
        })
        .collect()
}
/// Denied paths, validated like grants; a path that does not exist cannot be
/// read and is dropped, an existing one is canonicalized so the backend matches
/// the real location behind a symlink.
fn denials(paths: &[String]) -> Result<Vec<std::path::PathBuf>> {
    let mut denied = Vec::new();
    for value in paths {
        let path = Path::new(value);
        if value.len() > tinybox_bus::MAX_FILE_PATH_BYTES
            || value.contains('\0')
            || !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir))
        {
            return Err(invalid());
        }
        match path.canonicalize() {
            Ok(path) => denied.push(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(invalid()),
        }
    }
    Ok(denied)
}
fn invalid() -> Error {
    super::resources::failure(
        tinybox_bus::INVALID_FILE_PATH,
        "invalid native jail grant or working directory",
    )
}
fn unavailable() -> Error {
    super::resources::failure(
        tinybox_bus::UNSUPPORTED_OPERATION,
        "requested native jail enforcement is unavailable",
    )
}

pub(super) fn collector(
    root: &Path,
    config: &NativeJailConfig,
    command: &tinybox_core::ExecRequest,
) -> Result<Arc<tinybox_host::JailLocalHost>> {
    let backend = tinybox_jail::default_backend();
    let jail = prepare(root, config, command, backend.as_ref())?;
    tinybox_host::JailLocalHost::with_backend(jail, backend, tinybox_bus::MAX_OUTPUT_BYTES)
        .map(Arc::new)
        .map_err(|_| unavailable())
}

pub(super) fn collector_with_resources(
    root: &Path,
    config: &tinybox_bus::NativeJailRequest,
    command: &mut tinybox_core::ExecRequest,
) -> Result<Arc<tinybox_host::JailLocalHost>> {
    #[cfg(target_os = "linux")]
    {
        let backend = resource_backend();
        let jail = prepare_with_resources(root, config, command, backend.as_ref())?;
        tinybox_host::JailLocalHost::with_backend(jail, backend, tinybox_bus::MAX_OUTPUT_BYTES)
            .map(Arc::new)
            .map_err(|_| unavailable())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, config, command);
        Err(unavailable())
    }
}

#[cfg(test)]
#[path = "native_jail_tests.rs"]
mod tests;
