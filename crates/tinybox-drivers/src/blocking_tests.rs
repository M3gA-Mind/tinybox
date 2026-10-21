use super::*;
use std::time::Duration;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn current_thread_call_fails_without_blocking_tasks_that_host_storage_needs()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let bridge = Blocking::new()?;
        let (progress_tx, progress_rx) = tokio::sync::oneshot::channel();
        let progress = tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = progress_tx.send(());
        });
        let (watchdog_tx, watchdog_rx) = tokio::sync::oneshot::channel();
        let watchdog = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            let _ = watchdog_tx.send(());
        });

        let result = bridge.run(async move {
            tokio::select! {
                _ = progress_rx => (),
                _ = watchdog_rx => (),
            }
        });

        assert!(result.is_err(), "the bridge must reject before waiting");
        progress.await?;
        watchdog
            .join()
            .map_err(|_| std::io::Error::other("watchdog thread panicked"))?;
        Ok(())
    })
}

#[test]
fn calls_from_outside_tokio_are_completed_by_the_bridge_runtime()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bridge = Blocking::new()?;
    let value = bridge.run(async {
        tokio::task::yield_now().await;
        42_u8
    })?;
    assert_eq!(value, 42);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn calls_from_multithread_tokio_use_the_blocking_handoff()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bridge = Blocking::new()?;
    assert_eq!(bridge.run(async { "ready" })?, "ready");
    Ok(())
}

#[test]
fn a_stopped_bridge_and_a_bridge_callback_fail_without_waiting() -> TestResult {
    let (jobs, receiver) = tokio::sync::mpsc::unbounded_channel::<Job>();
    drop(receiver);
    let stopped = Blocking { jobs };
    assert!(stopped.run(async { () }).is_err());

    let bridge = Blocking::new()?;
    ON_BRIDGE.with(|flag| flag.set(true));
    let recursive = bridge.run(async { () });
    ON_BRIDGE.with(|flag| flag.set(false));
    assert!(recursive.is_err());
    Ok(())
}

#[test]
fn a_panicking_storage_future_is_reported_as_a_dropped_bridge_reply() -> TestResult {
    let bridge = Blocking::new()?;
    let error = bridge
        .run(async { panic!("simulated storage task panic") })
        .expect_err("the bridge must report a dropped reply");
    assert!(error.to_string().contains("dropped a call"));
    Ok(())
}

#[test]
fn startup_errors_keep_their_context_and_debug_is_redacted() -> TestResult {
    let bridge = Blocking::new()?;
    assert!(format!("{bridge:?}").contains("Blocking"));

    let runtime_error: Result<()> = startup_result(
        "runtime unavailable",
        Err(std::io::Error::other("runtime fixture")),
    );
    let runtime_error = runtime_error.expect_err("startup failures are returned");
    assert!(runtime_error.to_string().contains("runtime unavailable"));

    let thread_error: Result<()> = startup_result(
        "bridge thread unavailable",
        Err(std::io::Error::other("thread fixture")),
    );
    let thread_error = thread_error.expect_err("thread startup failures are returned");
    assert!(
        thread_error
            .to_string()
            .contains("bridge thread unavailable")
    );
    Ok(())
}
