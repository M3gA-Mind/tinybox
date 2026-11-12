//! Linux-only, live: a jail killed during its startup does not outlive the
//! kill.
//!
//! `bwrap` arms `--die-with-parent` inside the sandbox only after the
//! sandbox's setup, so a kill a few milliseconds after the spawn used to leave
//! the jailed command running. Each iteration kills a jail 0-3 ms after its
//! spawn returns and then requires that its command is gone. Skips (with a
//! note) without a working `bwrap`, unless `TINYBOX_REQUIRE_BWRAP=1`.
#![cfg(target_os = "linux")]

use std::io;
use std::time::Instant;

use tinybox_jail::JailBackend;

#[allow(dead_code)]
mod support;

use support::*;

/// Kills, each 0-3 ms after its spawn returns.
const ITERATIONS: u32 = 100;

#[test]
fn live_a_jail_killed_during_its_startup_leaves_nothing_running() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let jail = jail(root.path()).deny_net();
    backend
        .require(&jail)
        .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))?;
    let survivors = kill_during_startup(&backend, &jail, "47", ITERATIONS, 4)?;
    assert!(
        survivors.is_empty(),
        "{} of {ITERATIONS} jails outlived a kill during startup: pids {survivors:?}",
        survivors.len()
    );
    done("startup kill", start);
    Ok(())
}
