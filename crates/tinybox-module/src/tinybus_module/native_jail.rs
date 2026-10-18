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

#[cfg(test)]
#[path = "native_jail_tests.rs"]
mod tests;
