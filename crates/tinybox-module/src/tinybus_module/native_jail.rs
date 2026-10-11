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
    if config.read_only.len() + config.read_write.len() > tinybox_bus::MAX_NATIVE_JAIL_GRANTS {
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
    if config.enforcement == JailEnforcement::Enforced {
        backend.require(&jail).map_err(|_| unavailable())?;
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
