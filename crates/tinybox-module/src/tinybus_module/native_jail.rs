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
    // A denial over the root or a writable grant would leave the command no
    // workspace; that is a host error, not a weaker jail.
    if jail.deny_read.iter().any(|denied| {
        jail.root.starts_with(denied)
            || jail
                .read_write
                .iter()
                .any(|granted| overlaps(denied, granted))
    }) {
        return Err(invalid());
    }
    // Inside the root or a grant, only a backend that subtracts from grants
    // can keep the denial; outside them nothing grants the path anyway.
    if !backend.carves_denials()
        && jail.deny_read.iter().any(|denied| {
            std::iter::once(&jail.root)
                .chain(&jail.read_only)
                .any(|granted| overlaps(denied, granted))
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
/// Keep lexical prospective paths as well as canonical aliases for existing
/// ancestors. Missing credential stores must remain denied if created later.
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
        denied.push(path.to_path_buf());
        match canonicalize_prospective(path) {
            Ok(canonical) if canonical != path => denied.push(canonical),
            Ok(_) => {}
            Err(_) => return Err(invalid()),
        }
    }
    denied.sort();
    denied.dedup();
    Ok(denied)
}

fn canonicalize_prospective(path: &Path) -> std::io::Result<std::path::PathBuf> {
    match path.canonicalize() {
        Ok(canonical) => return Ok(canonical),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut ancestor = path;
    let mut suffix = Vec::new();
    loop {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                // Resolve existing aliases for prospective descendants, but
                // refuse dangling links and loops that have no stable target.
                let mut canonical = ancestor.canonicalize()?;
                for component in suffix.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let name = ancestor.file_name().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no existing path ancestor")
        })?;
        suffix.push(name.to_os_string());
        ancestor = ancestor.parent().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no existing path ancestor")
        })?;
        match ancestor.canonicalize() {
            Ok(mut canonical) => {
                for component in suffix.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
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
    backend: Arc<dyn JailBackend>,
) -> Result<Arc<tinybox_host::JailLocalHost>> {
    let jail = prepare(root, config, command, backend.as_ref())?;
    tinybox_host::JailLocalHost::with_backend(jail, backend, tinybox_bus::MAX_OUTPUT_BYTES)
        .map(Arc::new)
        .map_err(|_| unavailable())
}

#[cfg(test)]
#[path = "native_jail_tests.rs"]
mod tests;
