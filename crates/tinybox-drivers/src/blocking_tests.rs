use super::*;
use std::time::Duration;

#[test]
fn current_thread_call_fails_without_blocking_tasks_that_host_storage_needs() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let bridge = Blocking::new().expect("bridge");
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
        progress
            .await
            .expect("caller task must resume after rejection");
        watchdog.join().expect("watchdog thread");
    });
}
