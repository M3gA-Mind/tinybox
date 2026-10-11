//! Remote streaming, cancellation, and retained cleanup regressions.
use super::*;
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use tinybox_core::{ExecutionObserver, OutputStream};
use tokio::sync::Notify;

fn fixture_error(operation: &'static str) -> Error {
    Error::Backend {
        sandbox: "SSH test fixture".to_owned(),
        operation,
        message: "required fixture value is missing".to_owned(),
    }
}

fn last_arg<'a>(request: &'a ExecRequest, operation: &'static str) -> Result<&'a str> {
    request
        .argv
        .last()
        .map(String::as_str)
        .ok_or_else(|| fixture_error(operation))
}

fn is_cleanup_request(request: &ExecRequest) -> bool {
    request
        .argv
        .last()
        .is_some_and(|value| value.contains("kill -TERM -") && !value.contains("exec 3<&0"))
}

#[derive(Debug, Default)]
struct MockHost {
    requests: Mutex<Vec<ExecRequest>>,
    cancel_execution: AtomicBool,
    fail_cleanup: AtomicUsize,
    no_process_groups: AtomicBool,
    fail_prepare: AtomicBool,
    panic_observed: AtomicBool,
    observed_started: Notify,
    inner_cleanup_pending: AtomicBool,
    fail_inner_retry: AtomicBool,
    inner_retry_calls: AtomicUsize,
    fail_support_transport: AtomicBool,
    fail_support_with_255: AtomicBool,
    fail_prepare_transport: AtomicBool,
    fail_cleanup_transport: AtomicBool,
}

impl MockHost {
    fn requests(&self) -> Vec<ExecRequest> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn record(&self, request: &ExecRequest) {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request.clone());
    }
}

#[async_trait]
impl Host for MockHost {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        self.record(request);
        let remote = request.argv.last().map(String::as_str).unwrap_or_default();
        if remote == "command -v setsid >/dev/null 2>&1" {
            if self.fail_support_transport.load(Ordering::SeqCst) {
                return Err(fixture_error("probe SSH transport"));
            }
            return Ok(ExecOutput::new(
                if self.fail_support_with_255.load(Ordering::SeqCst) {
                    255
                } else {
                    i32::from(self.no_process_groups.load(Ordering::SeqCst))
                },
                Vec::new(),
                Vec::new(),
            ));
        }
        if remote.starts_with("umask 077") {
            if self.fail_prepare_transport.load(Ordering::SeqCst) {
                return Err(fixture_error("prepare remote cleanup reservation"));
            }
            if self.fail_prepare.load(Ordering::SeqCst) {
                return Ok(ExecOutput::new(1, b"not-ready\n".to_vec(), Vec::new()));
            }
            return Ok(ExecOutput::new(0, b"ready\n".to_vec(), Vec::new()));
        }
        if remote.starts_with("dir=") {
            if self.fail_cleanup_transport.load(Ordering::SeqCst) {
                return Err(fixture_error("acknowledge remote cleanup"));
            }
            let remaining = self.fail_cleanup.load(Ordering::SeqCst);
            if remaining > 0
                && self
                    .fail_cleanup
                    .compare_exchange(remaining, remaining - 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                return Ok(ExecOutput::new(1, b"pending\n".to_vec(), Vec::new()));
            }
            return Ok(ExecOutput::new(0, b"clean\n".to_vec(), Vec::new()));
        }
        Ok(ExecOutput::new(0, Vec::new(), Vec::new()))
    }

    async fn run_observed(
        &self,
        request: &ExecRequest,
        observer: Arc<dyn ExecutionObserver>,
    ) -> Result<ExecOutput> {
        self.record(request);
        if self.panic_observed.load(Ordering::SeqCst) {
            std::panic::resume_unwind(Box::new("injected observed-provider panic"));
        }
        self.observed_started.notify_waiters();
        let stdout = [0, 255, 1, 2];
        observer.output(OutputStream::Stdout, &stdout)?;
        observer.output(OutputStream::Stderr, b"remote-error-bytes")?;
        if self.cancel_execution.load(Ordering::SeqCst) {
            observer.cancelled().await;
            return Err(Error::Backend {
                sandbox: "local".to_owned(),
                operation: "collect output",
                message: "execution cancelled".to_owned(),
            });
        }
        Ok(ExecOutput::new(
            7,
            stdout.to_vec(),
            b"remote-error-bytes".to_vec(),
        ))
    }

    fn has_pending_observed_cleanup(&self) -> bool {
        self.inner_cleanup_pending.load(Ordering::SeqCst)
    }

    async fn retry_observed_cleanup(&self) -> Result<()> {
        self.inner_retry_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_inner_retry.load(Ordering::SeqCst) {
            return Err(Error::ObservedCleanupPending {
                provider: "inner test host".to_owned(),
            });
        }
        self.inner_cleanup_pending.store(false, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct CollectingObserver {
    chunks: Mutex<Vec<(OutputStream, Vec<u8>)>>,
}

#[async_trait]
impl ExecutionObserver for CollectingObserver {
    fn output(&self, stream: OutputStream, bytes: &[u8]) -> Result<()> {
        self.chunks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((stream, bytes.to_vec()));
        Ok(())
    }
}

#[derive(Debug)]
struct CancelObserver {
    cancelled: AtomicBool,
    notify: Notify,
}

impl CancelObserver {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
}

#[async_trait]
impl ExecutionObserver for CancelObserver {
    fn output(&self, _: OutputStream, _: &[u8]) -> Result<()> {
        Ok(())
    }

    async fn cancelled(&self) {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if !self.cancelled.load(Ordering::SeqCst) {
            notified.await;
        }
    }
}

#[tokio::test]
async fn observed_ssh_preserves_binary_pipes_and_execution_inputs() -> Result<()> {
    let inner = Arc::new(MockHost::default());
    let host = SshHost::new(inner.clone(), SshTarget::new("builder")?);
    let observer = Arc::new(CollectingObserver::default());
    let request = ExecRequest::new(["python", "-c", "print(1)"])
        .with_cwd("/workspace/build")
        .with_env("TOKEN", "opaque")
        .with_stdin([0, 1, 255]);

    let output = host.run_observed(&request, observer.clone()).await?;

    assert_eq!(output.exit_code, 7);
    assert_eq!(output.stdout, [0, 255, 1, 2]);
    assert_eq!(output.stderr, b"remote-error-bytes");
    assert_eq!(
        observer
            .chunks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_slice(),
        &[
            (OutputStream::Stdout, vec![0, 255, 1, 2]),
            (OutputStream::Stderr, b"remote-error-bytes".to_vec())
        ]
    );
    let requests = inner.requests();
    let launch = requests
        .iter()
        .find(|request| request.stdin.is_some())
        .ok_or_else(|| fixture_error("find supervised SSH request"))?;
    assert_eq!(launch.stdin.as_deref(), Some([0, 1, 255].as_slice()));
    let script = last_arg(launch, "read supervised SSH script")?;
    assert!(script.contains("setsid"));
    assert!(script.contains("/workspace/build"));
    assert!(script.contains("TOKEN=opaque"));
    let cleanup = requests
        .iter()
        .find(|request| is_cleanup_request(request))
        .ok_or_else(|| fixture_error("find remote process group cleanup"))?;
    let cleanup = last_arg(cleanup, "read remote cleanup script")?;
    assert!(cleanup.contains("kill -TERM -"));
    assert!(cleanup.contains("kill -KILL -"));
    assert!(cleanup.contains("clean\\n"));
    Ok(())
}

#[tokio::test]
async fn cancellation_waits_for_remote_group_cleanup_acknowledgement() -> Result<()> {
    let inner = Arc::new(MockHost {
        cancel_execution: AtomicBool::new(true),
        ..MockHost::default()
    });
    let host = SshHost::new(inner.clone(), SshTarget::new("builder")?);
    let observer = Arc::new(CancelObserver {
        cancelled: AtomicBool::new(false),
        notify: Notify::new(),
    });
    let cancel = observer.clone();
    let cancel_task = tokio::spawn(async move {
        tokio::task::yield_now().await;
        cancel.cancel();
    });

    let result = host
        .run_observed(&ExecRequest::new(["sleep", "600"]), observer)
        .await;
    cancel_task.await.map_err(|error| Error::Backend {
        sandbox: "test".to_owned(),
        operation: "join cancellation fixture",
        message: error.to_string(),
    })?;

    assert!(matches!(result, Err(Error::Backend { .. })));
    assert!(!host.has_pending_observed_cleanup());
    let requests = inner.requests();
    let cleanup_index = requests
        .iter()
        .position(is_cleanup_request)
        .ok_or_else(|| fixture_error("find cleanup SSH invocation"))?;
    let execution_index = requests
        .iter()
        .position(|request| {
            request
                .argv
                .last()
                .is_some_and(|value| value.contains("exec setsid"))
        })
        .ok_or_else(|| fixture_error("find supervised remote command"))?;
    assert!(cleanup_index > execution_index);
    Ok(())
}

#[tokio::test]
async fn failed_remote_kill_keeps_a_retryable_cleanup_handle() -> Result<()> {
    let inner = Arc::new(MockHost {
        cancel_execution: AtomicBool::new(true),
        fail_cleanup: AtomicUsize::new(2),
        ..MockHost::default()
    });
    let host = SshHost::new(inner.clone(), SshTarget::new("builder")?);
    let observer = Arc::new(CancelObserver {
        cancelled: AtomicBool::new(false),
        notify: Notify::new(),
    });
    let cancel = observer.clone();
    let cancel_task = tokio::spawn(async move {
        tokio::task::yield_now().await;
        cancel.cancel();
    });

    assert!(matches!(
        host.run_observed(&ExecRequest::new(["sleep", "600"]), observer)
            .await,
        Err(Error::ObservedCleanupPending { .. })
    ));
    cancel_task.await.map_err(|error| Error::Backend {
        sandbox: "test".to_owned(),
        operation: "join cleanup retry fixture",
        message: error.to_string(),
    })?;
    assert!(host.has_pending_observed_cleanup());

    host.retry_observed_cleanup().await?;

    assert!(!host.has_pending_observed_cleanup());
    assert_eq!(
        inner
            .requests()
            .iter()
            .filter(|request| is_cleanup_request(request))
            .count(),
        3,
        "two failed attempts are followed by one explicit retained-handle retry"
    );
    Ok(())
}

#[tokio::test]
async fn cleanup_retry_attempts_remote_and_inner_owners_even_when_one_fails() -> Result<()> {
    let inner = Arc::new(MockHost {
        inner_cleanup_pending: AtomicBool::new(true),
        fail_inner_retry: AtomicBool::new(true),
        ..MockHost::default()
    });
    let host = SshHost::new(inner.clone(), SshTarget::new("builder")?);
    let (remote_id, _) = host.observed_cleanup.reserve();
    host.observed_cleanup.mark_pending(&remote_id);

    assert!(host.has_pending_observed_cleanup());
    assert!(matches!(
        host.retry_observed_cleanup().await,
        Err(Error::ObservedCleanupPending { .. })
    ));
    assert_eq!(inner.inner_retry_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        inner
            .requests()
            .iter()
            .filter(|request| is_cleanup_request(request))
            .count(),
        1,
        "remote cleanup is attempted despite the inner cleanup failure"
    );
    assert!(!host.observed_cleanup.has_pending());
    assert!(host.has_pending_observed_cleanup());

    inner.fail_inner_retry.store(false, Ordering::SeqCst);
    host.retry_observed_cleanup().await?;
    assert_eq!(inner.inner_retry_calls.load(Ordering::SeqCst), 2);
    assert!(!host.has_pending_observed_cleanup());
    Ok(())
}

#[tokio::test]
async fn inner_cleanup_retry_runs_even_when_remote_cleanup_fails() -> Result<()> {
    let inner = Arc::new(MockHost {
        fail_cleanup: AtomicUsize::new(1),
        inner_cleanup_pending: AtomicBool::new(true),
        ..MockHost::default()
    });
    let host = SshHost::new(inner.clone(), SshTarget::new("builder")?);
    let (remote_id, _) = host.observed_cleanup.reserve();
    host.observed_cleanup.mark_pending(&remote_id);

    assert!(matches!(
        host.retry_observed_cleanup().await,
        Err(Error::ObservedCleanupPending { .. })
    ));
    assert_eq!(inner.inner_retry_calls.load(Ordering::SeqCst), 1);
    assert!(host.observed_cleanup.has_pending());
    assert!(!inner.has_pending_observed_cleanup());
    assert!(host.has_pending_observed_cleanup());

    host.retry_observed_cleanup().await?;
    assert_eq!(inner.inner_retry_calls.load(Ordering::SeqCst), 2);
    assert!(!host.has_pending_observed_cleanup());
    Ok(())
}

#[tokio::test]
async fn dropping_the_caller_keeps_the_remote_cleanup_owner_alive() -> Result<()> {
    let inner = Arc::new(MockHost {
        cancel_execution: AtomicBool::new(true),
        fail_cleanup: AtomicUsize::new(2),
        ..MockHost::default()
    });
    let host = SshHost::new(inner.clone(), SshTarget::new("builder")?);
    let observer = Arc::new(CancelObserver {
        cancelled: AtomicBool::new(false),
        notify: Notify::new(),
    });
    let started = inner.observed_started.notified();
    tokio::pin!(started);
    started.as_mut().enable();
    let caller_host = host.clone();
    let caller_observer = observer.clone();
    let caller = tokio::spawn(async move {
        caller_host
            .run_observed(&ExecRequest::new(["sleep", "600"]), caller_observer)
            .await
    });
    started.await;
    caller.abort();
    observer.cancel();

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !host.has_pending_observed_cleanup() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|error| Error::Backend {
        sandbox: "test".to_owned(),
        operation: "await retained SSH cleanup owner",
        message: error.to_string(),
    })?;
    host.retry_observed_cleanup().await?;
    assert!(!host.has_pending_observed_cleanup());
    Ok(())
}

#[derive(Debug)]
struct RefusingObserver;

#[async_trait]
impl ExecutionObserver for RefusingObserver {
    fn output(&self, _: OutputStream, _: &[u8]) -> Result<()> {
        Err(Error::io(
            "deliver SSH output fixture",
            &std::io::Error::other("receiver closed"),
        ))
    }
}

#[tokio::test]
async fn output_refusal_triggers_remote_cleanup_before_returning_the_error() -> Result<()> {
    let inner = Arc::new(MockHost {
        cancel_execution: AtomicBool::new(true),
        ..MockHost::default()
    });
    let host = SshHost::new(inner.clone(), SshTarget::new("builder")?);

    let result = host
        .run_observed(
            &ExecRequest::new(["sleep", "600"]),
            Arc::new(RefusingObserver),
        )
        .await;

    assert!(matches!(
        result,
        Err(Error::Io {
            operation: "deliver SSH output fixture",
            ..
        })
    ));
    assert!(!host.has_pending_observed_cleanup());
    assert!(inner.requests().iter().any(is_cleanup_request));
    Ok(())
}

#[derive(Debug)]
struct BlockingObserver {
    entered: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
    first: AtomicBool,
}

#[async_trait]
impl ExecutionObserver for BlockingObserver {
    fn output(&self, _: OutputStream, _: &[u8]) -> Result<()> {
        if !self.first.swap(true, Ordering::SeqCst) {
            self.entered.wait();
            self.release.wait();
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_provider_obeys_synchronous_output_backpressure() -> Result<()> {
    let inner = Arc::new(MockHost::default());
    let host = SshHost::new(inner, SshTarget::new("builder")?);
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let observer = Arc::new(BlockingObserver {
        entered: entered.clone(),
        release: release.clone(),
        first: AtomicBool::new(false),
    });
    let task = tokio::spawn(async move {
        host.run_observed(&ExecRequest::new(["producer"]), observer)
            .await
    });

    tokio::task::spawn_blocking(move || entered.wait())
        .await
        .map_err(|error| Error::Backend {
            sandbox: "test".to_owned(),
            operation: "join output backpressure fixture",
            message: error.to_string(),
        })?;
    assert!(
        !task.is_finished(),
        "command completion waits for output acceptance"
    );
    tokio::task::spawn_blocking(move || release.wait())
        .await
        .map_err(|error| Error::Backend {
            sandbox: "test".to_owned(),
            operation: "release output backpressure fixture",
            message: error.to_string(),
        })?;
    let output = task.await.map_err(|error| Error::Backend {
        sandbox: "test".to_owned(),
        operation: "join observed output fixture",
        message: error.to_string(),
    })??;
    assert_eq!(output.exit_code, 7, "non-zero command status is a result");
    Ok(())
}

#[tokio::test]
async fn remote_process_group_support_is_checked_before_execution() -> Result<()> {
    let inner = Arc::new(MockHost {
        no_process_groups: AtomicBool::new(true),
        ..MockHost::default()
    });
    let host = SshHost::new(inner.clone(), SshTarget::new("builder")?);
    let result = host
        .run_observed(
            &ExecRequest::new(["sleep", "600"]),
            Arc::new(CollectingObserver::default()),
        )
        .await;
    assert!(matches!(result, Err(Error::UnsupportedStreaming { .. })));
    assert_eq!(inner.requests().len(), 1, "only the capability probe runs");
    Ok(())
}

#[tokio::test]
async fn empty_command_is_rejected_before_remote_probes() -> Result<()> {
    let inner = Arc::new(MockHost::default());
    let host = SshHost::new(inner.clone(), SshTarget::new("builder")?);

    assert!(matches!(
        host.run_observed(
            &ExecRequest::new(std::iter::empty::<&str>()),
            Arc::new(CollectingObserver::default())
        )
        .await,
        Err(Error::EmptyCommand { .. })
    ));
    assert!(inner.requests().is_empty());
    Ok(())
}

#[tokio::test]
async fn support_probe_transport_failures_are_reported_before_reservation() -> Result<()> {
    for inner in [
        Arc::new(MockHost {
            fail_support_transport: AtomicBool::new(true),
            ..MockHost::default()
        }),
        Arc::new(MockHost {
            fail_support_with_255: AtomicBool::new(true),
            ..MockHost::default()
        }),
    ] {
        let host = SshHost::new(inner.clone(), SshTarget::new("builder")?);
        assert!(matches!(
            host.run_observed(
                &ExecRequest::new(["echo", "safe"]),
                Arc::new(CollectingObserver::default())
            )
            .await,
            Err(Error::Backend { .. })
        ));
        assert_eq!(inner.requests().len(), 1);
        assert!(!host.has_pending_observed_cleanup());
    }
    Ok(())
}

#[tokio::test]
async fn prepare_transport_error_is_returned_after_successful_reservation_cleanup() -> Result<()> {
    let inner = Arc::new(MockHost {
        fail_prepare_transport: AtomicBool::new(true),
        ..MockHost::default()
    });
    let host = SshHost::new(inner.clone(), SshTarget::new("builder")?);

    assert!(matches!(
        host.run_observed(
            &ExecRequest::new(["echo", "safe"]),
            Arc::new(CollectingObserver::default())
        )
        .await,
        Err(Error::Backend { .. })
    ));
    assert!(inner.requests().iter().any(is_cleanup_request));
    assert!(!host.has_pending_observed_cleanup());
    Ok(())
}

#[tokio::test]
async fn malformed_reservation_response_is_cleaned_before_returning() -> Result<()> {
    let inner = Arc::new(MockHost {
        fail_prepare: AtomicBool::new(true),
        ..MockHost::default()
    });
    let host = SshHost::new(inner.clone(), SshTarget::new("builder")?);

    assert!(matches!(
        host.run_observed(
            &ExecRequest::new(["echo", "safe"]),
            Arc::new(CollectingObserver::default())
        )
        .await,
        Err(Error::Backend {
            operation: "reserve remote execution cleanup",
            ..
        })
    ));
    assert!(inner.requests().iter().any(is_cleanup_request));
    assert!(!host.has_pending_observed_cleanup());
    Ok(())
}

#[tokio::test]
async fn invalid_remote_command_request_releases_its_reservation() -> Result<()> {
    let inner = Arc::new(MockHost::default());
    let host = SshHost::new(inner.clone(), SshTarget::new("builder")?);

    assert!(matches!(
        host.run_observed_owned(
            &ExecRequest::new(std::iter::empty::<&str>()),
            Arc::new(CollectingObserver::default())
        )
        .await,
        Err(Error::EmptyCommand { .. })
    ));
    assert!(!host.has_pending_observed_cleanup());
    Ok(())
}

#[tokio::test]
async fn failed_reservation_acknowledgement_retains_cleanup_for_retry() -> Result<()> {
    let inner = Arc::new(MockHost {
        fail_cleanup: AtomicUsize::new(1),
        fail_prepare: AtomicBool::new(true),
        ..MockHost::default()
    });
    let host = SshHost::new(inner.clone(), SshTarget::new("builder")?);

    assert!(matches!(
        host.run_observed(
            &ExecRequest::new(["sleep", "600"]),
            Arc::new(CollectingObserver::default())
        )
        .await,
        Err(Error::ObservedCleanupPending { .. })
    ));
    assert!(host.has_pending_observed_cleanup());

    host.retry_observed_cleanup().await?;

    assert!(!host.has_pending_observed_cleanup());
    assert_eq!(
        inner
            .requests()
            .iter()
            .filter(|request| is_cleanup_request(request))
            .count(),
        2,
        "one failed reservation cleanup is followed by one explicit retry"
    );
    Ok(())
}

#[tokio::test]
async fn a_provider_panic_retains_the_remote_cleanup_reservation() -> Result<()> {
    let inner = Arc::new(MockHost {
        panic_observed: AtomicBool::new(true),
        ..MockHost::default()
    });
    let host = SshHost::new(inner, SshTarget::new("builder")?);

    assert!(matches!(
        host.run_observed(
            &ExecRequest::new(["sleep", "600"]),
            Arc::new(CollectingObserver::default())
        )
        .await,
        Err(Error::Backend { .. })
    ));
    assert!(host.has_pending_observed_cleanup());

    host.retry_observed_cleanup().await?;

    assert!(!host.has_pending_observed_cleanup());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn generated_remote_supervisor_kills_and_waits_for_its_process_group() -> Result<()> {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let target = SshTarget::new("builder")?;
    let state = observed::RemoteCleanupState::default();
    let (id, directory) = state.reserve();
    let prepare = observed::prepare_request(&target, &id, &directory);
    let prepare_script = last_arg(&prepare, "read remote setup script")?;
    let prepared = Command::new("/bin/sh")
        .arg("-c")
        .arg(prepare_script)
        .output()
        .map_err(|error| Error::io("reserve local remote-protocol fixture", &error))?;
    assert!(prepared.status.success());
    assert_eq!(prepared.stdout, b"ready\n");
    let launch = observed::request(
        &target,
        &ExecRequest::new(["/bin/sh", "-c", "printf ready; exec sleep 60"]),
        &id,
        &directory,
    )?;
    let pid_file = format!("{directory}/pid");
    let remote_script = last_arg(&launch, "read remote launch script")?;
    let mut process = Command::new("/bin/sh")
        .arg("-c")
        .arg(remote_script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| Error::io("start local SSH protocol fixture", &error))?;

    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&pid_file).exists() && Instant::now() < deadline {
        if let Some(status) = process
            .try_wait()
            .map_err(|error| Error::io("check local SSH protocol fixture", &error))?
        {
            return Err(Error::Backend {
                sandbox: "ssh test".to_owned(),
                operation: "start remote supervisor fixture",
                message: format!("wrapper exited early with {status}"),
            });
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let pid_text = std::fs::read_to_string(&pid_file)
        .map_err(|error| Error::io("read remote supervisor pid", &error))?;
    let pid = pid_text.trim();
    assert!(!pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit()));

    let cleanup = observed::cleanup_request(&target, &id, &directory, true);
    let cleanup_script = last_arg(&cleanup, "read remote cleanup script")?;
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(cleanup_script)
        .output()
        .map_err(|error| Error::io("run local remote-cleanup fixture", &error))?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"clean\n");
    let status = process
        .wait()
        .map_err(|error| Error::io("wait for remote supervisor fixture", &error))?;
    assert!(
        !status.success(),
        "the cancelled command must not report success"
    );
    let group_alive = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("kill -0 -{pid} 2>/dev/null"))
        .status()
        .map_err(|error| Error::io("check remote process group", &error))?
        .success();
    assert!(
        !group_alive,
        "cleanup acknowledgement follows group exit and wait"
    );
    state.remove(&id);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn generated_remote_supervisor_reaps_background_descendants_before_acknowledging() -> Result<()> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let target = SshTarget::new("builder")?;
    let state = observed::RemoteCleanupState::default();
    let (id, directory) = state.reserve();
    let prepare = observed::prepare_request(&target, &id, &directory);
    let prepare_script = last_arg(&prepare, "read remote setup script")?;
    let prepared = Command::new("/bin/sh")
        .arg("-c")
        .arg(prepare_script)
        .output()
        .map_err(|error| Error::io("reserve local descendant fixture", &error))?;
    assert!(prepared.status.success());

    let launch = observed::request(
        &target,
        &ExecRequest::new(["/bin/sh", "-c", "sleep 600 & sleep 0.05; exit 0"]),
        &id,
        &directory,
    )?;
    let pid_file = format!("{directory}/pid");
    let remote_script = last_arg(&launch, "read remote launch script")?;
    let mut process = Command::new("/bin/sh")
        .arg("-c")
        .arg(remote_script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| Error::io("start descendant protocol fixture", &error))?;
    let mut stdout = process
        .stdout
        .take()
        .ok_or_else(|| fixture_error("take descendant fixture stdout"))?;
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        let read = stdout.read_to_end(&mut output);
        let _ = sender.send((read, output));
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&pid_file).exists() && Instant::now() < deadline {
        if let Some(status) = process
            .try_wait()
            .map_err(|error| Error::io("check descendant protocol fixture", &error))?
        {
            return Err(Error::Backend {
                sandbox: "ssh test".to_owned(),
                operation: "start descendant supervisor fixture",
                message: format!("wrapper exited before recording its pid: {status}"),
            });
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let pid_text = std::fs::read_to_string(&pid_file)
        .map_err(|error| Error::io("read descendant supervisor pid", &error))?;
    let pid = pid_text.trim();
    assert!(!pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit()));

    let status = process
        .wait()
        .map_err(|error| Error::io("wait for descendant supervisor", &error))?;
    assert!(
        status.success(),
        "the foreground command exits successfully"
    );
    let pipe_released = receiver.recv_timeout(Duration::from_secs(1)).ok();
    let group_alive = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("kill -0 -{pid} 2>/dev/null"))
        .status()
        .map_err(|error| Error::io("check descendant process group", &error))?
        .success();
    if group_alive {
        let _ = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("kill -KILL -{pid} 2>/dev/null || true"))
            .status();
    }
    let _ = reader.join();
    assert!(
        pipe_released.is_some(),
        "background descendants must not retain the remote output pipe after acknowledgement"
    );
    if let Some((read, _)) = pipe_released {
        read.map_err(|error| Error::io("read descendant fixture output", &error))?;
    }
    assert!(
        !group_alive,
        "supervisor must terminate group descendants before its completion acknowledgement"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn generated_remote_supervisor_forwards_binary_stdin_to_the_foreground_command() -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let target = SshTarget::new("builder")?;
    let state = observed::RemoteCleanupState::default();
    let (id, directory) = state.reserve();
    let prepare = observed::prepare_request(&target, &id, &directory);
    let prepare_script = last_arg(&prepare, "read remote setup script")?;
    let prepared = Command::new("/bin/sh")
        .arg("-c")
        .arg(prepare_script)
        .output()
        .map_err(|error| Error::io("reserve local stdin fixture", &error))?;
    assert!(prepared.status.success());

    let payload = [0, 1, 255, 0, 42];
    let launch = observed::request(&target, &ExecRequest::new(["/bin/cat"]), &id, &directory)?;
    let remote_script = last_arg(&launch, "read remote launch script")?;
    let mut process = Command::new("/bin/sh")
        .arg("-c")
        .arg(remote_script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| Error::io("start local stdin protocol fixture", &error))?;
    process
        .stdin
        .take()
        .ok_or_else(|| fixture_error("take local stdin fixture"))?
        .write_all(&payload)
        .map_err(|error| Error::io("write local binary stdin fixture", &error))?;
    let output = process
        .wait_with_output()
        .map_err(|error| Error::io("wait for local stdin protocol fixture", &error))?;
    assert!(output.status.success());
    assert_eq!(output.stdout, payload);

    let cleanup = observed::cleanup_request(&target, &id, &directory, true);
    let cleanup_script = last_arg(&cleanup, "read local stdin fixture cleanup")?;
    let cleaned = Command::new("/bin/sh")
        .arg("-c")
        .arg(cleanup_script)
        .output()
        .map_err(|error| Error::io("clean local stdin protocol fixture", &error))?;
    assert!(cleaned.status.success());
    Ok(())
}
