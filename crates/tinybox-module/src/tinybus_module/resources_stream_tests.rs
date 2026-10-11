//! Admission and cleanup for module-owned live executions.
use super::*;
use tinybox_bus::{CreateRequest, ExecRequest, ExecutionState, Workspace};

async fn local_resource(resources: &Resources) -> Result<ResourceId> {
    let resource = resources.reserve(ReserveRequest::Resource).await?;
    resources
        .create(CreateRequest {
            resource: resource.clone(),
            backend: "passthrough".into(),
            workspace: Workspace::Directory(".".into()),
            ..Default::default()
        })
        .await?;
    Ok(resource)
}
async fn request(
    resources: &Resources,
    resource: &ResourceId,
    argv: Vec<String>,
) -> Result<SpawnRequest> {
    Ok(SpawnRequest {
        process: resources
            .reserve(ReserveRequest::Process(resource.clone()))
            .await?,
        command: ExecRequest {
            resource: resource.clone(),
            argv,
            cwd: None,
            env: std::collections::BTreeMap::new(),
            stdin: None,
        },
    })
}
fn true_command() -> Vec<String> {
    #[cfg(windows)]
    return vec!["cmd".into(), "/C".into(), "exit 0".into()];
    #[cfg(not(windows))]
    vec!["/bin/true".into()]
}
async fn completed(resources: &Resources, process: &ProcessRef) -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if resources.read_output(process, 0).await?.state != ExecutionState::Running {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| tinybus::Error::failed("native fixture did not complete"))?
}

#[tokio::test]
async fn live_admission_is_bounded_until_outputs_are_explicitly_released() -> Result<()> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let mut processes = Vec::new();
    for _ in 0..MAX_STREAM_EXECUTIONS {
        let request = request(&resources, &resource, true_command()).await?;
        processes.push(resources.start_exec(request).await?);
    }
    let pending = request(&resources, &resource, true_command()).await?;
    assert!(resources.start_exec(pending.clone()).await.is_err());
    for process in processes {
        completed(&resources, &process).await?;
        resources.release_output(&process).await?;
    }
    let process = resources.start_exec(pending).await?;
    completed(&resources, &process).await?;
    resources.release_output(&process).await?;
    resources.release_output(&process).await?;
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
async fn stream_replay_keeps_request_identity_and_rejects_cross_resource_handles() -> Result<()> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let other = local_resource(&resources).await?;
    let request = request(&resources, &resource, true_command()).await?;
    let process = resources.start_exec(request.clone()).await?;
    assert_eq!(process, resources.start_exec(request.clone()).await?);
    let mut wrong = request;
    wrong.command.env.insert("DIFFERENT".into(), "1".into());
    assert!(resources.start_exec(wrong).await.is_err());
    let wrong = ProcessRef {
        resource: other.clone(),
        process: process.process.clone(),
    };
    assert!(resources.read_output(&wrong, 0).await.is_err());
    assert!(resources.cancel(&wrong).await.is_err());
    assert!(resources.release_output(&wrong).await.is_err());
    assert!(resources.read_output(&process, u64::MAX).await.is_err());
    completed(&resources, &process).await?;
    assert!(!resources.is_running(&process).await?);
    resources.release_output(&process).await?;
    assert!(resources.read_output(&process, 0).await.is_err());
    resources.close(&resource).await?;
    resources.close(&other).await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn close_acknowledges_active_stream_cleanup_and_retires_its_output() -> Result<()> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let request = request(
        &resources,
        &resource,
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf ready; exec sleep 600".into(),
        ],
    )
    .await?;
    let process = resources.start_exec(request.clone()).await?;
    assert!(resources.release_output(&process).await.is_err());
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        resources.close(&resource),
    )
    .await
    .map_err(|_| tinybus::Error::failed("Close did not acknowledge native cleanup"))??;
    assert!(resources.stream(&process)?.is_none());
    assert!(resources.start_exec(request).await.is_err());
    resources.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn rejected_start_keeps_its_reservation_and_provider_failures_use_safe_codes() -> Result<()> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let mut empty = request(&resources, &resource, Vec::new()).await?;
    assert!(resources.start_exec(empty.clone()).await.is_err());
    empty.command.argv = vec!["NONEXISTENT_CANARY_PRIVATE_PROGRAM_393932".into()];
    let process = resources.start_exec(empty).await?;
    completed(&resources, &process).await?;
    let batch = resources.read_output(&process, 0).await?;
    assert_eq!(
        batch.state,
        ExecutionState::Failed {
            code: ExecutionFailure::BackendFailed
        }
    );
    assert!(!format!("{:?}", batch.state).contains("CANARY"));
    resources.release_output(&process).await?;
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
async fn an_unowned_collector_or_unsupported_platform_refuses_live_execution() -> Result<()> {
    for platform in [
        crate::tinybus_module::Platform::current(),
        crate::tinybus_module::Platform::Other,
    ] {
        let resources = Resources::default();
        let resource = resources.reserve(ReserveRequest::Resource).await?;
        resources
            .create_on_for_platform(
                CreateRequest {
                    resource: resource.clone(),
                    backend: "passthrough".into(),
                    workspace: Workspace::Directory(".".into()),
                    ..Default::default()
                },
                Arc::new(tinybox_host::LocalHost::new()),
                platform,
            )
            .await?;
        let command = request(&resources, &resource, true_command()).await?;
        assert!(resources.start_exec(command).await.is_err());
        resources.close(&resource).await?;
    }
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::panic,
    reason = "exercise acknowledged ownership after an unexpected execution task panic"
)]
async fn a_panicked_job_is_joined_and_cleanup_failure_stays_owned_until_retry() -> Result<()> {
    let resource = ResourceId("fixture-resource".into());
    let journal = Arc::new(OutputJournal::default());
    let guard = CompletionGuard(journal.clone());
    drop(guard);
    assert!(!journal.cleanup_acknowledged());
    let task = tokio::spawn(async {
        panic!("execution fixture panicked");
    });
    let stream = StreamExecution {
        request: SpawnRequest {
            process: ResourceId("fixture-process".into()),
            command: ExecRequest {
                resource,
                argv: true_command(),
                cwd: None,
                env: std::collections::BTreeMap::new(),
                stdin: None,
            },
        },
        jail: None,
        journal,
        task: Mutex::new(Some(task)),
        collector: Collector::Host(Arc::new(tinybox_host::LimitedLocalHost::new(64)), None),
    };
    assert!(stream.running());
    stream.stop().await?;
    assert!(stream.cleanup_acknowledged());
    assert!(!stream.running());
    stream.stop().await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn exceeding_live_output_budget_stops_the_child_and_reports_a_safe_terminal_code()
-> Result<()> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let request = request(&resources, &resource, vec!["/bin/sh".into(), "-c".into(), "while :; do printf 012345678901234567890123456789012345678901234567890123456789012345; done".into()]).await?;
    let process = resources.start_exec(request).await?;
    completed(&resources, &process).await?;
    let batch = resources.read_output(&process, 0).await?;
    assert_eq!(
        batch.state,
        ExecutionState::Failed {
            code: ExecutionFailure::OutputLimit
        }
    );
    resources.release_output(&process).await?;
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
async fn concurrent_lost_reply_retries_reuse_the_same_execution_instead_of_consuming_twice()
-> Result<()> {
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let request = request(&resources, &resource, true_command()).await?;
    let slot = resources.slot(&resource).await?;
    let slot_guard = slot.lock().await;
    let mut first = Box::pin(resources.start_exec(request.clone()));
    let mut retry = Box::pin(resources.start_exec(request.clone()));
    let mut changed = request;
    changed.command.env.insert("DIFFERENT".into(), "1".into());
    let mut wrong_retry = Box::pin(resources.start_exec(changed));
    poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending());
        assert!(retry.as_mut().poll(cx).is_pending());
        assert!(wrong_retry.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(slot_guard);
    let (first, retry, wrong_retry) = tokio::join!(first, retry, wrong_retry);
    assert!(wrong_retry.is_err());
    let first = first?;
    assert_eq!(first, retry?);
    completed(&resources, &first).await?;
    resources.release_output(&first).await?;
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
async fn jailed_start_rejects_missing_grants_without_consuming_reservation() -> Result<()> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let pending = request(&resources, &resource, true_command()).await?;
    let config = tinybox_bus::NativeJailConfig {
        read_only: vec!["/tinybox-nonexistent-grant-fixture".into()],
        read_write: vec![],
        allow_net: true,
        allow_subprocess: true,
        enforcement: tinybox_bus::JailEnforcement::Declared,
        require_process_isolation: false,
    };
    assert!(
        resources
            .start_jailed_exec(pending.clone(), config)
            .await
            .is_err()
    );
    let process = resources.start_exec(pending).await?;
    completed(&resources, &process).await?;
    resources.close(&resource).await
}

#[derive(Debug)]
struct RemoteObservedFixture {
    pending: std::sync::atomic::AtomicBool,
    reject_retry: std::sync::atomic::AtomicBool,
    collected_calls: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl tinybox_core::Host for RemoteObservedFixture {
    fn name(&self) -> &'static str {
        "ssh"
    }
    async fn run(
        &self,
        _: &tinybox_core::ExecRequest,
    ) -> tinybox_core::Result<tinybox_core::ExecOutput> {
        self.collected_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(tinybox_core::Error::UnsupportedStreaming {
            provider: "fixture".into(),
        })
    }
    async fn run_observed(
        &self,
        _: &tinybox_core::ExecRequest,
        observer: Arc<dyn tinybox_core::ExecutionObserver>,
    ) -> tinybox_core::Result<tinybox_core::ExecOutput> {
        observer.output(tinybox_core::OutputStream::Stdout, &[255, 0])?;
        self.pending
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Err(tinybox_core::Error::ObservedCleanupPending {
            provider: "fixture".into(),
        })
    }
    fn has_pending_observed_cleanup(&self) -> bool {
        self.pending.load(std::sync::atomic::Ordering::SeqCst)
    }
    async fn retry_observed_cleanup(&self) -> tinybox_core::Result<()> {
        if self.reject_retry.load(std::sync::atomic::Ordering::SeqCst) {
            Err(tinybox_core::Error::ObservedCleanupPending {
                provider: "fixture".into(),
            })
        } else {
            self.pending
                .store(false, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }
}
#[tokio::test]
async fn remote_cleanup_failure_keeps_binary_output_and_owner_until_retry_ack() -> Result<()> {
    let host = Arc::new(RemoteObservedFixture {
        pending: std::sync::atomic::AtomicBool::new(false),
        reject_retry: std::sync::atomic::AtomicBool::new(true),
        collected_calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let resource = ResourceId("fixture-resource".into());
    let command = tinybox_core::ExecRequest::new(["fixture"]);
    let stream = StreamExecution::start(
        SpawnRequest {
            process: ResourceId("fixture-process".into()),
            command: ExecRequest {
                resource,
                argv: vec!["fixture".into()],
                cwd: None,
                env: std::collections::BTreeMap::new(),
                stdin: None,
            },
        },
        command,
        Collector::Host(host.clone(), None),
        None,
    );
    assert!(stream.stop().await.is_err());
    assert!(stream.running());
    let batch = stream
        .journal
        .read(0)
        .map_err(|_| tinybus::Error::failed("fixture read failed"))?;
    assert_eq!(
        batch.state,
        ExecutionState::Failed {
            code: ExecutionFailure::CleanupFailed
        }
    );
    assert_eq!(batch.chunks[0].bytes, [255, 0]);
    host.reject_retry
        .store(false, std::sync::atomic::Ordering::SeqCst);
    stream.stop().await?;
    assert!(!stream.running());
    assert!(stream.cleanup_acknowledged());
    assert_eq!(
        host.collected_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn collector_drain_joins_its_owned_active_native_supervisor() -> Result<()> {
    use std::future::Future;
    use std::task::Poll;
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let request = request(
        &resources,
        &resource,
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf ready; exec /bin/sleep 600".into(),
        ],
    )
    .await?;
    let process = resources.start_exec(request).await?;
    loop {
        if !resources.read_output(&process, 0).await?.chunks.is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    let stream = resources
        .stream(&process)?
        .ok_or_else(|| Error::failed("missing fixture stream"))?;
    let mut drain = Box::pin(stream.collector.drain());
    let completion =
        std::future::poll_fn(|context| Poll::Ready(drain.as_mut().poll(context))).await;
    drop(drain);
    resources.cancel(&process).await?;
    resources.release_output(&process).await?;
    resources.close(&resource).await?;
    assert!(
        matches!(completion, Poll::Pending),
        "collector drain must join its owned native supervisor"
    );
    Ok(())
}
