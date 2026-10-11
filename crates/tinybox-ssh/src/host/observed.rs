//! Remote process-group ownership for live SSH execution.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use tinybox_core::{Error, ExecRequest, ExecutionObserver, OutputStream, Result};
use tokio::sync::Notify;
use uuid::Uuid;

use super::SshTarget;

#[derive(Debug, Clone)]
pub(super) struct RemoteCleanupState(Arc<Mutex<BTreeMap<String, Entry>>>);

#[derive(Debug, Clone)]
struct Entry {
    directory: String,
    pending: bool,
}

impl Default for RemoteCleanupState {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(BTreeMap::new())))
    }
}

impl RemoteCleanupState {
    pub(super) fn reserve(&self) -> (String, String) {
        let id = Uuid::new_v4().simple().to_string();
        let directory = format!("/tmp/.tinybox-observed-{id}");
        self.entries().insert(
            id.clone(),
            Entry {
                directory: directory.clone(),
                pending: false,
            },
        );
        (id, directory)
    }

    pub(super) fn reserve_guard(&self, id: String) -> ReservationGuard {
        ReservationGuard {
            state: self.clone(),
            id,
        }
    }

    pub(super) fn pending(&self) -> Vec<(String, String)> {
        self.entries()
            .iter()
            .filter(|(_, entry)| entry.pending)
            .map(|(id, entry)| (id.clone(), entry.directory.clone()))
            .collect()
    }

    pub(super) fn has_pending(&self) -> bool {
        self.entries().values().any(|entry| entry.pending)
    }

    pub(super) fn mark_pending(&self, id: &str) {
        if let Some(entry) = self.entries().get_mut(id) {
            entry.pending = true;
        }
    }

    pub(super) fn remove(&self, id: &str) {
        self.entries().remove(id);
    }

    pub(super) fn contains(&self, id: &str) -> bool {
        self.entries().contains_key(id)
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Entry>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Marks an unfinished reservation as pending if observed execution unwinds.
#[derive(Debug)]
pub(super) struct ReservationGuard {
    state: RemoteCleanupState,
    id: String,
}

impl Drop for ReservationGuard {
    fn drop(&mut self) {
        self.state.mark_pending(&self.id);
    }
}

pub(super) fn prepare_request(target: &SshTarget, id: &str, directory: &str) -> ExecRequest {
    let owner_file = format!("{directory}/owner");
    let wrapper = format!(
        "umask 077; dir={dir}; owner={owner}; \
         if ! mkdir \"$dir\" 2>/dev/null; then exit 125; fi; \
         if ! printf '%s\\n' {id} > \"$owner\"; then rm -rf \"$dir\"; exit 125; fi; \
         printf 'ready\\n'",
        dir = tinybox_core::shell::quote(directory),
        owner = tinybox_core::shell::quote(&owner_file),
        id = tinybox_core::shell::quote(id),
    );
    ssh_request(target, &wrapper)
}

pub(super) fn request(
    target: &SshTarget,
    request: &ExecRequest,
    id: &str,
    directory: &str,
) -> Result<ExecRequest> {
    if request.argv.is_empty() {
        return Err(Error::EmptyCommand {
            sandbox: super::NAME.to_owned(),
        });
    }
    let pid_file = format!("{directory}/pid");
    let owner_file = format!("{directory}/owner");
    let script = tinybox_core::shell::script(&request.argv, request.cwd.as_deref(), &request.env);
    let child = format!(
        "printf '%s\\n' \"$$\" > {} && exec /bin/sh -c {}",
        tinybox_core::shell::quote(&pid_file),
        tinybox_core::shell::quote(&script)
    );
    let wrapper = format!(
        "exec 3<&0; dir={dir}; pid_file={pid}; owner={owner}; \
         if [ ! -d \"$dir\" ] || [ \"$(cat \"$owner\" 2>/dev/null)\" != {id} ]; then exit 125; fi; \
         ( exec setsid /bin/sh -c {child} <&3 ) & launcher=$!; \
         count=0; while [ ! -f \"$pid_file\" ]; do \
           if ! kill -0 \"$launcher\" 2>/dev/null; then wait \"$launcher\"; code=$?; exit \"$code\"; fi; \
           count=$((count + 1)); if [ \"$count\" -ge 1000 ]; then kill -KILL \"$launcher\" 2>/dev/null || true; wait \"$launcher\" 2>/dev/null || true; exit 125; fi; \
           sleep 0.01; \
         done; \
         wait \"$launcher\"; code=$?; \
         group=$(cat \"$pid_file\" 2>/dev/null); case \"$group\" in ''|*[!0-9]*) exit 125;; esac; \
         kill -TERM -\"$group\" 2>/dev/null || true; \
         count=0; while kill -0 -\"$group\" 2>/dev/null; do \
           count=$((count + 1)); if [ \"$count\" -ge 100 ]; then break; fi; sleep 0.01; \
         done; \
         if kill -0 -\"$group\" 2>/dev/null; then kill -KILL -\"$group\" 2>/dev/null || true; fi; \
         count=0; while kill -0 -\"$group\" 2>/dev/null; do \
           count=$((count + 1)); if [ \"$count\" -ge 1000 ]; then exit 124; fi; sleep 0.01; \
         done; \
         printf 'done\\n' > \"$dir/done\" && rm -rf \"$dir\" || exit 125; exit \"$code\"",
        dir = tinybox_core::shell::quote(directory),
        pid = tinybox_core::shell::quote(&pid_file),
        owner = tinybox_core::shell::quote(&owner_file),
        id = tinybox_core::shell::quote(id),
        child = tinybox_core::shell::quote(&child),
    );
    let mut forwarded = ssh_request(target, &wrapper);
    forwarded.stdin.clone_from(&request.stdin);
    Ok(forwarded)
}

pub(super) fn cleanup_request(
    target: &SshTarget,
    id: &str,
    directory: &str,
    allow_unstarted: bool,
) -> ExecRequest {
    let pid_file = format!("{directory}/pid");
    let owner_file = format!("{directory}/owner");
    let empty_behavior = if allow_unstarted {
        "rm -rf \"$dir\"; printf 'clean\\n'; exit 0"
    } else {
        "printf 'pending\\n'; exit 1"
    };
    let wrapper = format!(
        "dir={dir}; pid_file={pid}; owner={owner}; \
         if [ ! -d \"$dir\" ]; then printf 'clean\\n'; exit 0; fi; \
         if [ ! -f \"$owner\" ] || [ \"$(cat \"$owner\" 2>/dev/null)\" != {id} ]; then printf 'clean\\n'; exit 0; fi; \
         count=0; while [ ! -f \"$pid_file\" ] && [ -d \"$dir\" ]; do \
           count=$((count + 1)); if [ \"$count\" -ge 1000 ]; then {empty}; fi; sleep 0.01; \
         done; \
         if [ ! -f \"$pid_file\" ]; then {empty}; fi; \
         pid=$(cat \"$pid_file\"); case \"$pid\" in ''|*[!0-9]*) printf 'pending\\n'; exit 1;; esac; \
         kill -TERM -\"$pid\" 2>/dev/null || true; \
         count=0; while [ -d \"$dir\" ] && [ ! -f \"$dir/done\" ]; do \
           count=$((count + 1)); if [ \"$count\" -ge 100 ]; then break; fi; sleep 0.01; \
         done; \
         if [ -d \"$dir\" ] && [ ! -f \"$dir/done\" ]; then kill -KILL -\"$pid\" 2>/dev/null || true; fi; \
         count=0; while [ -d \"$dir\" ]; do \
           count=$((count + 1)); if [ \"$count\" -ge 100 ]; then printf 'pending\\n'; exit 1; fi; sleep 0.01; \
         done; printf 'clean\\n'",
        dir = tinybox_core::shell::quote(directory),
        pid = tinybox_core::shell::quote(&pid_file),
        owner = tinybox_core::shell::quote(&owner_file),
        id = tinybox_core::shell::quote(id),
        empty = empty_behavior,
    );
    ssh_request(target, &wrapper)
}

pub(super) fn supports_process_groups(target: &SshTarget) -> ExecRequest {
    ssh_request(target, "command -v setsid >/dev/null 2>&1")
}

fn ssh_request(target: &SshTarget, remote_command: &str) -> ExecRequest {
    let mut argv = vec!["ssh".to_owned()];
    argv.extend(target.connection_flags());
    // Cleanup must settle even when the remote is unreachable; a bounded
    // connection attempt leaves its owner handle available for explicit retry.
    argv.extend(["-o".to_owned(), "ConnectTimeout=10".to_owned()]);
    argv.push(target.destination().to_owned());
    argv.push("--".to_owned());
    argv.push(remote_command.to_owned());
    ExecRequest::new(argv)
}

pub(super) fn cleanup_result(output: &tinybox_core::ExecOutput) -> Result<()> {
    if output.exit_code == 0 && output.stdout == b"clean\n" {
        Ok(())
    } else {
        Err(Error::ObservedCleanupPending {
            provider: super::NAME.to_owned(),
        })
    }
}

pub(super) fn unsupported_process_groups() -> Error {
    Error::UnsupportedStreaming {
        provider: "ssh without remote process-group support".to_owned(),
    }
}

#[derive(Debug)]
pub(super) struct Bridge {
    observer: Arc<dyn ExecutionObserver>,
    inner: Arc<dyn tinybox_core::Host>,
    target: SshTarget,
    state: RemoteCleanupState,
    id: String,
    directory: String,
    failed_output: Mutex<Option<Error>>,
    stop: Notify,
    cleanup_lock: tokio::sync::Mutex<()>,
}

impl Bridge {
    pub(super) fn new(
        observer: Arc<dyn ExecutionObserver>,
        inner: Arc<dyn tinybox_core::Host>,
        target: SshTarget,
        state: RemoteCleanupState,
        id: String,
        directory: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            observer,
            inner,
            target,
            state,
            id,
            directory,
            failed_output: Mutex::new(None),
            stop: Notify::new(),
            cleanup_lock: tokio::sync::Mutex::new(()),
        })
    }

    pub(super) async fn cleanup(&self) -> Result<()> {
        self.cleanup_with(false).await
    }

    pub(super) async fn cleanup_finished(&self) -> Result<()> {
        self.cleanup_with(true).await
    }

    async fn cleanup_with(&self, allow_unstarted: bool) -> Result<()> {
        let _guard = self.cleanup_lock.lock().await;
        if !self.state.contains(&self.id) {
            return Ok(());
        }
        let command = cleanup_request(&self.target, &self.id, &self.directory, allow_unstarted);
        match self.inner.run(&command).await {
            Ok(output) => match cleanup_result(&output) {
                Ok(()) => {
                    self.state.remove(&self.id);
                    Ok(())
                }
                Err(error) => Err(error),
            },
            Err(_) => Err(Error::ObservedCleanupPending {
                provider: super::NAME.to_owned(),
            }),
        }
    }

    pub(super) fn take_output_error(&self) -> Option<Error> {
        self.failed_output
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

#[async_trait]
impl ExecutionObserver for Bridge {
    fn output(&self, stream: OutputStream, bytes: &[u8]) -> Result<()> {
        if let Err(error) = self.observer.output(stream, bytes) {
            let mut failure = self
                .failed_output
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if failure.is_none() {
                *failure = Some(error);
                self.stop.notify_one();
            }
        }
        Ok(())
    }

    async fn cancelled(&self) {
        let stopped = self.stop.notified();
        tokio::pin!(stopped);
        stopped.as_mut().enable();
        if self
            .failed_output
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none()
        {
            tokio::select! {
                () = self.observer.cancelled() => {},
                () = stopped => {},
            }
        }
        let _ = self.cleanup().await;
    }
}
