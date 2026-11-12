//! Making a jail killed during its startup die with its launcher.
//!
//! `bwrap` arms `--die-with-parent` inside the sandbox only once the
//! sandbox's own setup is done. A launcher killed before that moment, even a
//! few milliseconds after the spawn, used to leave the sandbox running with
//! nothing left to stop it.
//!
//! `bwrap` reports the sandbox's first process, pid 1 of the jail's pid
//! namespace, on `--json-status-fd` right after creating it, and is the only
//! holder of that pipe's writer from then until it exits (the sandbox closes
//! its copy first thing). [`hold`] waits for that report before a spawn
//! returns, takes a pidfd for the process, and leaves a watcher that kills it
//! once the pipe reaches end-of-file: the launcher is gone, however it went.
//! Killing pid 1 takes the whole pid namespace with it, at any stage of its
//! setup. Through a pidfd the kill cannot reach a reused pid, and killing a
//! process that already exited is harmless.

use std::fs::File;
use std::io::{self, BufRead as _, BufReader, Read as _};
use std::os::fd::OwnedFd;
use std::process::Child;
use std::sync::mpsc;
use std::time::Duration;

use rustix::process::{Pid, PidfdFlags, Signal, kill_process_group, pidfd_open, pidfd_send_signal};

/// How long `bwrap` may take to create the sandbox.
const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Waits until the sandbox `launcher` starts is held by a watcher that kills
/// it when `launcher` exits. `status` is the read end of the pipe `bwrap`
/// writes `--json-status-fd` to.
///
/// # Errors
/// When `bwrap` exits before creating the sandbox, does not create it within
/// [`READY_TIMEOUT`], reports a process that cannot be held, or the watcher
/// cannot start. `launcher` has then been
/// killed and reaped, so no half-started jail is handed back.
pub(super) fn hold(launcher: &mut Child, status: File) -> io::Result<()> {
    hold_within(launcher, status, READY_TIMEOUT)
}

/// [`hold`] with its own deadline.
fn hold_within(launcher: &mut Child, status: File, timeout: Duration) -> io::Result<()> {
    let outer = launcher.id();
    let (ready, reported) = mpsc::sync_channel(1);
    let watcher = std::thread::Builder::new()
        .name("tinybox-bwrap-reaper".into())
        .spawn(move || watch(status, outer, &ready));
    if let Err(error) = watcher {
        return Err(stop(launcher, &error));
    }
    match reported.recv_timeout(timeout) {
        Ok(Report::Held) => Ok(()),
        Ok(Report::Unheld) => Err(stop(
            launcher,
            &io::Error::other("bubblewrap reported a sandbox process that cannot be held"),
        )),
        Ok(Report::NotStarted) | Err(mpsc::RecvTimeoutError::Disconnected) => Err(stop(
            launcher,
            &io::Error::other("bubblewrap exited before it started the sandbox"),
        )),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(stop(
            launcher,
            &io::Error::new(
                io::ErrorKind::TimedOut,
                "bubblewrap did not start the sandbox in time",
            ),
        )),
    }
}

/// What the watcher found on the status pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Report {
    /// The sandbox is held, or already gone.
    Held,
    /// The pipe ended without a report.
    NotStarted,
    /// A report named a process the watcher could not hold.
    Unheld,
}

/// Kills and reaps `launcher` after a failed start, keeping `error` but adding
/// what `bwrap` said when its stderr was captured.
fn stop(launcher: &mut Child, error: &io::Error) -> io::Error {
    let _ = launcher.kill();
    // A sandbox `bwrap` created but never reported is still in the launcher's
    // process group until its own setup moves it to a new session; the group
    // goes too. Before the wait, so the unreaped launcher still pins its pid
    // as the group id and the signal cannot reach anyone else's group.
    if let Some(group) = i32::try_from(launcher.id()).ok().and_then(Pid::from_raw) {
        let _ = kill_process_group(group, Signal::KILL);
    }
    let status = launcher.wait();
    let mut said = String::new();
    if let Some(mut stderr) = launcher.stderr.take() {
        let _ = stderr.read_to_string(&mut said);
    }
    let said = said.trim();
    let status = status.map_or_else(|_| "unknown status".to_owned(), |s| s.to_string());
    if said.is_empty() {
        io::Error::new(error.kind(), format!("{error} ({status})"))
    } else {
        io::Error::new(error.kind(), format!("{error} ({status}): {said}"))
    }
}

/// The watcher: reports whether the sandbox was created, then waits for the
/// launcher to go and kills the sandbox.
fn watch(status: File, outer: u32, ready: &mpsc::SyncSender<Report>) {
    let mut status = BufReader::new(status);
    let mut first = String::new();
    let reported = match status.read_line(&mut first) {
        Ok(read) if read > 0 => child_pid(&first),
        _ => None,
    };
    // Open before reporting: from here the process cannot be mistaken for a
    // later one with the same pid.
    let sandbox = reported.map(|pid| open_child(pid, outer));
    let _ = ready.send(match sandbox {
        Some(Ok(_)) => Report::Held,
        Some(Err(Unheld)) => Report::Unheld,
        None => Report::NotStarted,
    });
    // `bwrap` writes its exit status here later; keep reading so it never
    // writes to a closed pipe.
    let _ = io::copy(&mut status, &mut io::sink());
    if let Some(Ok(Some(sandbox))) = sandbox {
        let _ = pidfd_send_signal(&sandbox, Signal::KILL);
    }
}

/// A pidfd for `pid` while it is still the child of `outer`; `None` when it
/// already exited, and with it the whole jail.
///
/// # Errors
/// When no pidfd can be had, or `pid` names a process that is not `outer`'s
/// child: then nothing could reliably stop the sandbox, so the start fails
/// closed.
fn open_child(pid: i32, outer: u32) -> Result<Option<OwnedFd>, Unheld> {
    let Some(raw) = Pid::from_raw(pid) else {
        return Err(Unheld);
    };
    let pidfd = match pidfd_open(raw, PidfdFlags::empty()) {
        Ok(pidfd) => pidfd,
        Err(rustix::io::Errno::SRCH) => return Ok(None),
        // No pidfd (a kernel before 5.3, or out of descriptors): nothing
        // could stop the sandbox if the launcher died now.
        Err(_) => return Err(Unheld),
    };
    let parent = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| parent_pid(&stat));
    match parent {
        Some(parent) if parent == outer => Ok(Some(pidfd)),
        // Exited between the two calls: the pidfd stays valid but names a
        // finished process, so there is nothing left to kill.
        None if !std::path::Path::new(&format!("/proc/{pid}")).exists() => Ok(None),
        _ => {
            // Orphaned already: `bwrap` died between its report and here. The
            // init of a pid namespace other than this one is that sandbox (an
            // unrelated process that reused the pid would share this one), so
            // it is killed before the start fails.
            if starts_a_pid_namespace(pid) {
                let _ = pidfd_send_signal(&pidfd, Signal::KILL);
            }
            Err(Unheld)
        }
    }
}

/// Whether `pid` lives in a pid namespace other than this process's: true of
/// a `bwrap` sandbox's first process, created with its own.
fn starts_a_pid_namespace(pid: i32) -> bool {
    let namespace = |of: &str| std::fs::read_link(format!("/proc/{of}/ns/pid")).ok();
    matches!(
        (namespace(&pid.to_string()), namespace("self")),
        (Some(theirs), Some(ours)) if theirs != ours
    )
}

/// A sandbox process the watcher could not take hold of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Unheld;

/// The `child-pid` in a `--json-status-fd` line.
pub(super) fn child_pid(line: &str) -> Option<i32> {
    let value = serde_json::from_str::<serde_json::Value>(line).ok()?;
    let pid = value.get("child-pid")?.as_i64()?;
    i32::try_from(pid).ok().filter(|pid| *pid > 0)
}

/// The parent pid in a `/proc/<pid>/stat` line. The command name may hold
/// spaces and parentheses, so the fields are read after its last `)`.
pub(super) fn parent_pid(stat: &str) -> Option<u32> {
    let (_, fields) = stat.rsplit_once(')')?;
    fields.split_whitespace().nth(1)?.parse().ok()
}

#[cfg(test)]
#[path = "reaper_tests.rs"]
mod tests;
