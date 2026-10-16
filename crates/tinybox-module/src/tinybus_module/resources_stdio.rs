//! Admission, lookup and cleanup for interactive jailed stdio processes.
use super::{
    Arc, Error, ProcessRef, ReserveRequest, ResourceId, Resources, Result, backend_error,
    check_resource_open, command, failure, validate_id,
};
use crate::tinybus_module::stdio::StdioSession;
use tinybox_bus::{StdioChunk, StdioStartRequest, StdioStatus};
use tinybox_jail::JailBackend;

pub(super) enum StdioSlot {
    /// Admitted and counted against limits while the child starts.
    Starting(ProcessRef),
    Ready(ProcessRef, Arc<StdioSession>),
}

impl StdioSlot {
    fn target(&self) -> &ProcessRef {
        match self {
            Self::Starting(target) | Self::Ready(target, _) => target,
        }
    }
}

/// Parent variables a server commonly needs; everything else is dropped so the
/// module's own environment (credentials included) never leaks into the child.
const SAFE_ENV: [&str; 9] = [
    "PATH", "HOME", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "USER", "SHELL", "TMPDIR",
];

fn invalid(message: &str) -> Error {
    failure(tinybox_bus::INVALID_STDIO, message)
}

fn validate_request(request: &StdioStartRequest) -> Result<()> {
    validate_id(&request.process)?;
    validate_id(&request.resource)?;
    if request.argv.is_empty()
        || request.argv.iter().any(|arg| arg.contains('\0'))
        || request.argv[0].is_empty()
    {
        return Err(invalid("stdio argv must name a program without NUL bytes"));
    }
    if request
        .env
        .iter()
        .any(|(name, value)| name.is_empty() || name.contains(['=', '\0']) || value.contains('\0'))
    {
        return Err(invalid("invalid stdio environment"));
    }
    Ok(())
}

fn build_command(resolved: &tinybox_core::ExecRequest) -> std::process::Command {
    let mut native = std::process::Command::new(&resolved.argv[0]);
    native.args(&resolved.argv[1..]).env_clear();
    for name in SAFE_ENV {
        if let Some(value) = std::env::var_os(name) {
            native.env(name, value);
        }
    }
    native.envs(&resolved.env);
    if let Some(cwd) = &resolved.cwd {
        native.current_dir(cwd);
    }
    native
}

impl Resources {
    pub(in crate::tinybus_module) async fn start_stdio(
        &self,
        request: StdioStartRequest,
    ) -> Result<ProcessRef> {
        self.start_stdio_with(request, tinybox_jail::default_backend())
            .await
    }

    pub(super) async fn start_stdio_with(
        &self,
        request: StdioStartRequest,
        backend: Arc<dyn JailBackend>,
    ) -> Result<ProcessRef> {
        validate_request(&request)?;
        let target = ProcessRef {
            resource: request.resource.clone(),
            process: request.process.clone(),
        };
        if let Some(existing) = self.stdio_session(&target)? {
            return if existing.request() == &request {
                Ok(target)
            } else {
                Err(failure(
                    tinybox_bus::INVALID_ID,
                    "stdio identifier belongs to another command",
                ))
            };
        }
        let (root, resolved) = self.resolve_stdio(&request).await?;
        // The same preflight as StartJailedExec: refuse before any admission
        // when the backend cannot meet the requested floor.
        let jail = {
            let (config, backend, resolved) =
                (request.jail.clone(), backend.clone(), resolved.clone());
            tokio::task::spawn_blocking(move || {
                super::super::native_jail::prepare(&root, &config, &resolved, backend.as_ref())
            })
            .await
            .map_err(|_| {
                failure(
                    tinybox_bus::BACKEND_ERROR,
                    "stdio preparation worker failed",
                )
            })??
        };
        self.admit_stdio(&request, &target).await?;
        let started =
            StdioSession::spawn(request.clone(), backend, jail, build_command(&resolved)).await;
        let session = match started {
            Ok(session) => session,
            Err(error) => {
                self.remove_stdio(&target);
                return Err(error);
            }
        };
        self.stdio
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                target.process.clone(),
                StdioSlot::Ready(target.clone(), session.clone()),
            );
        // A Close that began while the child started must not leave it alive.
        let open = {
            let state = self.state.lock().await;
            let executions = self
                .executions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            check_resource_open(&state, &executions, &target.resource).and_then(|()| {
                if state.entries.contains_key(&target.resource) {
                    Ok(())
                } else {
                    Err(failure(tinybox_bus::UNKNOWN_RESOURCE, "closed resource"))
                }
            })
        };
        if let Err(error) = open {
            self.remove_stdio(&target);
            let _ = session.kill().await;
            return Err(error);
        }
        log::debug!(
            "[tinybox:stdio] admitted resource={} process={}",
            target.resource.0,
            target.process.0
        );
        Ok(target)
    }

    /// Check the resource and reservation, and resolve the command inside it.
    async fn resolve_stdio(
        &self,
        request: &StdioStartRequest,
    ) -> Result<(std::path::PathBuf, tinybox_core::ExecRequest)> {
        let slot = self.slot(&request.resource).await?;
        {
            let guard = slot.lock().await;
            let entry = guard
                .as_ref()
                .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "closed resource"))?;
            let (Some(sandbox), Some(root)) = (&entry.local_sandbox, &entry.workspace_root) else {
                return Err(failure(
                    tinybox_bus::UNSUPPORTED_OPERATION,
                    "stdio requires a local passthrough directory resource",
                ));
            };
            if !entry.native_host {
                return Err(failure(
                    tinybox_bus::UNSUPPORTED_OPERATION,
                    "stdio requires local passthrough execution",
                ));
            }
            {
                let mut state = self.state.lock().await;
                let executions = self
                    .executions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                check_resource_open(&state, &executions, &request.resource)?;
                self.check_reservation(
                    &mut state,
                    &request.process,
                    &ReserveRequest::Process(request.resource.clone()),
                )?;
            }
            let native = command(tinybox_bus::ExecRequest {
                resource: request.resource.clone(),
                argv: request.argv.clone(),
                cwd: request.cwd.clone(),
                env: request.env.clone(),
                stdin: None,
            });
            let resolved = sandbox
                .resolve_command(&entry.id, &native)
                .map_err(|error| backend_error(&error))?;
            Ok((root.clone(), resolved))
        }
    }

    async fn admit_stdio(&self, request: &StdioStartRequest, target: &ProcessRef) -> Result<()> {
        let mut state = self.state.lock().await;
        let executions = self
            .executions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        check_resource_open(&state, &executions, &request.resource)?;
        let mut stdio = self
            .stdio
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if stdio.contains_key(&request.process) {
            return Err(failure(
                tinybox_bus::DUPLICATE_ID,
                "stdio start is already in progress",
            ));
        }
        if stdio.len() >= tinybox_bus::MAX_STDIO_PROCESSES
            || stdio
                .values()
                .filter(|slot| slot.target().resource == request.resource)
                .count()
                >= tinybox_bus::MAX_PROCESSES_PER_RESOURCE
        {
            return Err(failure(
                tinybox_bus::RESOURCE_LIMIT,
                "stdio process limit reached",
            ));
        }
        self.consume(
            &mut state,
            &request.process,
            &ReserveRequest::Process(request.resource.clone()),
        )?;
        stdio.insert(request.process.clone(), StdioSlot::Starting(target.clone()));
        Ok(())
    }

    fn remove_stdio(&self, target: &ProcessRef) {
        self.stdio
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&target.process);
    }

    fn stdio_session(&self, target: &ProcessRef) -> Result<Option<Arc<StdioSession>>> {
        validate_id(&target.resource)?;
        validate_id(&target.process)?;
        let stdio = self
            .stdio
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match stdio.get(&target.process) {
            None => Ok(None),
            Some(slot) if slot.target().resource != target.resource => Err(failure(
                tinybox_bus::INVALID_ID,
                "stdio process belongs to another resource",
            )),
            Some(StdioSlot::Starting(_)) => Err(failure(
                tinybox_bus::DUPLICATE_ID,
                "stdio start is already in progress",
            )),
            Some(StdioSlot::Ready(_, session)) => Ok(Some(session.clone())),
        }
    }

    fn require_stdio(&self, target: &ProcessRef) -> Result<Arc<StdioSession>> {
        self.stdio_session(target)?
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_PROCESS, "unknown stdio process"))
    }

    pub(in crate::tinybus_module) async fn write_stdio(
        &self,
        request: tinybox_bus::StdioWriteRequest,
    ) -> Result<()> {
        if request.data.len() > tinybox_bus::MAX_STDIO_WRITE_BYTES {
            return Err(failure(
                tinybox_bus::RESOURCE_LIMIT,
                "stdio write exceeds the chunk limit",
            ));
        }
        self.require_stdio(&request.process)?
            .write(&request.data)
            .await
    }

    pub(in crate::tinybus_module) async fn read_stdio(
        &self,
        request: tinybox_bus::StdioReadRequest,
    ) -> Result<StdioChunk> {
        Ok(self
            .require_stdio(&request.process)?
            .read(request.max_bytes, request.wait_ms)
            .await)
    }

    pub(in crate::tinybus_module) async fn close_stdin(&self, process: &ProcessRef) -> Result<()> {
        self.require_stdio(process)?.close_stdin().await;
        Ok(())
    }

    pub(in crate::tinybus_module) fn stdio_status(
        &self,
        process: &ProcessRef,
    ) -> Result<StdioStatus> {
        Ok(self.require_stdio(process)?.status())
    }

    /// Kill, reap and release one process. An unknown process is already gone.
    pub(in crate::tinybus_module) async fn kill_stdio(&self, process: &ProcessRef) -> Result<()> {
        let Some(session) = self.stdio_session(process)? else {
            return Ok(());
        };
        session.kill().await?;
        self.remove_stdio(process);
        Ok(())
    }

    /// Kill every stdio process of a closing resource; failures stay retained
    /// so a later Close can retry them.
    pub(super) async fn close_stdio(&self, resource: &ResourceId) -> Result<()> {
        let sessions: Vec<(ProcessRef, Arc<StdioSession>)> = self
            .stdio
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter_map(|slot| match slot {
                StdioSlot::Ready(target, session) if target.resource == *resource => {
                    Some((target.clone(), session.clone()))
                }
                _ => None,
            })
            .collect();
        let mut failure = None;
        for (target, session) in sessions {
            match session.kill().await {
                Ok(()) => self.remove_stdio(&target),
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
#[path = "resources_stdio_tests.rs"]
mod tests;
