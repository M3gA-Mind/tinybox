//! Native shell preparation; the retained context owns private scratch and cleanup.
use std::{
    path::{Component, Path},
    sync::Arc,
};
use tinybox_bus::ShellExecRequest;
use tinybus::Result;

mod types;
pub(super) use types::ShellContext;
use types::ShellHost;
impl ShellContext {
    pub(super) async fn prepare_owned(
        request: ShellExecRequest,
        root: std::path::PathBuf,
        resolved: tinybox_core::ExecRequest,
    ) -> Result<Arc<Self>> {
        Self::prepare_owned_with(move || Self::prepare(request, &root, &resolved)).await
    }
    async fn prepare_owned_with(
        prepare: impl FnOnce() -> Result<Arc<Self>> + Send + 'static,
    ) -> Result<Arc<Self>> {
        prepare()
    }
    pub(super) fn prepare(
        request: ShellExecRequest,
        root: &Path,
        resolved: &tinybox_core::ExecRequest,
    ) -> Result<Arc<Self>> {
        Self::prepare_with_backend(request, root, resolved, tinybox_jail::default_backend())
    }
    fn prepare_with_backend(
        request: ShellExecRequest,
        root: &Path,
        resolved: &tinybox_core::ExecRequest,
        backend: Arc<dyn tinybox_jail::JailBackend>,
    ) -> Result<Arc<Self>> {
        if request.timeout_ms == 0
            || request.timeout_ms > 86_400_000
            || request.shell.command.contains('\0')
        {
            return Err(invalid());
        }
        let state = Path::new(&request.state_dir);
        if request.state_dir.len() > tinybox_bus::MAX_FILE_PATH_BYTES
            || request.state_dir.contains('\0')
            || !state.is_absolute()
            || state
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(invalid());
        }
        let state = state.canonicalize().map_err(|_| invalid())?;
        if !state.is_dir() {
            return Err(invalid());
        }
        let scratch_root = state.join("artifacts/sandbox-scratch");
        std::fs::create_dir_all(&scratch_root).map_err(|_| invalid())?;
        let scratch = tempfile::Builder::new()
            .prefix("shell-")
            .tempdir_in(scratch_root)
            .map_err(|_| invalid())?;
        let selection = tinybox_host::select_shell(&request.shell);
        let mut environment = std::collections::BTreeMap::new();
        for name in [
            "PATH", "HOME", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "USER", "SHELL", "TMPDIR",
        ]
        .into_iter()
        .chain(selection.bootstrap_environment.iter().map(String::as_str))
        {
            if let Ok(value) = std::env::var(name) {
                if value.is_empty() {
                    return Err(invalid());
                }
                environment.insert(name.to_owned(), value);
            }
        }
        for (name, value) in &request.extra_env {
            if name.is_empty() || name.contains(['=', '\0']) || value.contains('\0') {
                return Err(invalid());
            }
            if cfg!(windows) {
                environment.retain(|key, _| !key.eq_ignore_ascii_case(name));
            }
            environment.insert(name.clone(), value.clone());
        }
        for name in ["TMPDIR", "TEMP", "TMP"] {
            if !request.extra_env.keys().any(|key| {
                if cfg!(windows) {
                    key.eq_ignore_ascii_case(name)
                } else {
                    key == name
                }
            }) {
                environment.insert(
                    name.into(),
                    scratch.path().to_str().ok_or_else(invalid)?.into(),
                );
            }
        }
        for name in selection.remove_environment {
            environment.remove(&name);
        }
        let host = if let Some(config) = &request.jail {
            let mut jail = super::native_jail::prepare(root, config, resolved, backend.as_ref())?;
            jail.read_write.push(scratch.path().to_path_buf());
            if config.enforcement == tinybox_bus::JailEnforcement::Enforced {
                backend.require(&jail).map_err(|_| invalid())?;
            } else if backend
                .plan_check(&jail)
                .constraints
                .iter()
                .any(|(_, support)| *support == tinybox_core::Enforcement::Unsupported)
            {
                return Err(invalid());
            }
            ShellHost::Jailed(
                tinybox_host::JailLocalHost::with_backend(
                    jail,
                    backend,
                    tinybox_bus::MAX_OUTPUT_BYTES,
                )
                .map_err(|_| invalid())?,
            )
        } else {
            ShellHost::Local(tinybox_host::LimitedLocalHost::new(
                tinybox_bus::MAX_OUTPUT_BYTES,
            ))
        };
        Ok(Arc::new(Self {
            request,
            environment,
            scratch: Arc::new(std::sync::Mutex::new(Some(scratch))),
            scratch_cleanup_failed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            host,
        }))
    }
    pub(super) async fn run(
        &self,
        resolved: &tinybox_core::ExecRequest,
        observer: Arc<super::output::OutputJournal>,
    ) -> tinybox_core::Result<tinybox_core::ExecOutput> {
        let mut command = tinybox_host::build_shell_command(&self.request.shell);
        command.env_clear().envs(&self.environment);
        if let Some(cwd) = &resolved.cwd {
            command.current_dir(cwd);
        }
        match &self.host {
            ShellHost::Local(host) => {
                host.run_command_observed(command, self.request.stdin.clone(), observer)
                    .await
            }
            ShellHost::Jailed(host) => {
                host.run_command_observed(command, self.request.stdin.clone(), observer)
                    .await
            }
        }
    }
    pub(super) fn pending(&self) -> bool {
        if self
            .scratch_cleanup_failed
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return true;
        }
        match &self.host {
            ShellHost::Local(host) => host.has_pending_cleanup(),
            ShellHost::Jailed(host) => host.has_pending_cleanup(),
        }
    }
    pub(super) async fn drain(&self) -> tinybox_core::Result<()> {
        match &self.host {
            ShellHost::Local(host) => host.drain_checked().await?,
            ShellHost::Jailed(host) => host.drain_checked().await?,
        }
        Ok(())
    }
    pub(super) async fn dispose_scratch(&self) -> tinybox_core::Result<()> {
        self.dispose_scratch_with(|path| std::fs::remove_dir_all(path))
            .await
    }
    async fn dispose_scratch_with(
        &self,
        remove: impl FnOnce(&Path) -> std::io::Result<()> + Send + 'static,
    ) -> tinybox_core::Result<()> {
        let scratch = self.scratch.clone();
        let failed = self.scratch_cleanup_failed.clone();
        tokio::task::spawn_blocking(move || {
            let mut scratch = scratch
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(directory) = scratch.as_ref() {
                // Keep the TempDir and its path until deletion succeeds; close() consumes
                // ownership even on failure and would make cleanup impossible to retry.
                if let Err(error) = remove(directory.path())
                    && error.kind() != std::io::ErrorKind::NotFound
                {
                    failed.store(true, std::sync::atomic::Ordering::SeqCst);
                    return Err(tinybox_core::Error::io("remove shell scratch", &error));
                }
                scratch.take();
            }
            failed.store(false, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
        .await
        .map_err(|error| {
            tinybox_core::Error::io("join shell scratch cleanup", &std::io::Error::other(error))
        })?
    }
}
fn invalid() -> tinybus::Error {
    super::resources::failure(
        tinybox_bus::INVALID_SHELL_EXEC,
        "invalid native shell environment, state directory or runtime budget",
    )
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
