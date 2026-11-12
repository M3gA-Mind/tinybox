//! Tests for holding a sandbox so it dies with its launcher.

use super::*;
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::time::Instant;

/// A launcher whose stdout is the status pipe, as `bwrap`'s
/// `--json-status-fd` is, running `script` under `sh -c` in its own process
/// group, as the backend's captured spawns do.
fn launcher(script: &str) -> io::Result<(Child, File)> {
    let (status, writer) = io::pipe()?;
    let child = Command::new("/bin/sh")
        .args(["-c", script])
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .stderr(Stdio::piped())
        .spawn()?;
    Ok((child, File::from(OwnedFd::from(status))))
}

/// Whether `pid` names a process that has not exited.
fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            stat.rsplit_once(')')
                .and_then(|(_, fields)| fields.split_whitespace().next().map(str::to_owned))
        })
        .is_some_and(|state| state != "Z" && state != "X")
}

fn gone_within(pid: u32, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while alive(pid) {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    true
}

#[test]
fn reads_the_child_pid_from_a_status_line() {
    assert_eq!(child_pid("{ \"child-pid\": 4242 }\n"), Some(4242));
    assert_eq!(
        child_pid("{ \"child-pid\": 17, \"cgroup-namespace\": 4026531835 }"),
        Some(17)
    );
    for refused in [
        "",
        "not json",
        "{ \"exit-code\": 1 }",
        "{ \"child-pid\": 0 }",
        "{ \"child-pid\": -5 }",
        "{ \"child-pid\": \"12\" }",
        "{ \"child-pid\": 99999999999 }",
    ] {
        assert_eq!(child_pid(refused), None, "{refused}");
    }
}

#[test]
fn reads_the_parent_pid_past_a_command_name_with_spaces_and_parentheses() {
    assert_eq!(parent_pid("123 (sleep) S 77 123 77 0"), Some(77));
    assert_eq!(parent_pid("123 (a b) (c)) R 9 1"), Some(9));
    assert_eq!(parent_pid("no parentheses"), None);
    assert_eq!(parent_pid("1 (x)"), None);
}

#[test]
fn a_held_sandbox_is_killed_when_its_launcher_is() -> io::Result<()> {
    // The background sleep stands in for the sandbox: the launcher's child,
    // reported on the status pipe, outside its process group's reach once
    // the launcher is gone, and not holding the pipe itself.
    let (mut child, status) = launcher(
        "sleep 30 >/dev/null 2>&1 </dev/null & echo \"{ \\\"child-pid\\\": $! }\"; exec sleep 30",
    )?;
    hold(&mut child, status)?;
    let sandbox =
        std::fs::read_to_string(format!("/proc/{}/task/{}/children", child.id(), child.id()))?
            .split_whitespace()
            .next()
            .and_then(|pid| pid.parse::<u32>().ok())
            .ok_or_else(|| io::Error::other("the launcher has no child"))?;
    assert!(alive(sandbox));

    child.kill()?;
    child.wait()?;
    assert!(
        gone_within(sandbox, Duration::from_secs(5)),
        "the sandbox {sandbox} outlived its launcher"
    );
    Ok(())
}

#[test]
fn a_launcher_that_exits_without_reporting_fails_and_is_reaped() -> io::Result<()> {
    let (mut child, status) = launcher("echo bwrap: no such option >&2; exit 1")?;
    let error = hold(&mut child, status)
        .err()
        .ok_or_else(|| io::Error::other("a launcher that never reported was held"))?;
    assert!(
        error
            .to_string()
            .contains("exited before it started the sandbox"),
        "{error}"
    );
    assert!(error.to_string().contains("no such option"), "{error}");
    assert!(child.try_wait()?.is_some(), "the launcher was not reaped");
    Ok(())
}

#[test]
fn a_launcher_that_never_reports_times_out_and_is_killed() -> io::Result<()> {
    let (mut child, status) = launcher("exec sleep 30")?;
    let error = hold_within(&mut child, status, Duration::from_millis(200))
        .err()
        .ok_or_else(|| io::Error::other("a launcher that never reported was held"))?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
    let status = child
        .try_wait()?
        .ok_or_else(|| io::Error::other("the launcher was left running"))?;
    assert!(!status.success());
    Ok(())
}

#[test]
fn a_reported_process_that_is_not_the_launchers_child_fails_closed() -> io::Result<()> {
    // This test process is alive but no child of the launcher.
    let script = format!(
        "echo \"{{ \\\"child-pid\\\": {} }}\"; exec sleep 30",
        std::process::id()
    );
    let (mut child, status) = launcher(&script)?;
    let error = hold(&mut child, status)
        .err()
        .ok_or_else(|| io::Error::other("a foreign process was held as the sandbox"))?;
    assert!(error.to_string().contains("cannot be held"), "{error}");
    assert!(child.try_wait()?.is_some(), "the launcher was left running");
    Ok(())
}

#[test]
fn a_sandbox_that_already_exited_needs_no_hold() -> io::Result<()> {
    // The reported child exits before the watcher opens it: the jail is gone,
    // so the launch can go on.
    let (mut child, status) =
        launcher("true & pid=$!; wait $pid; echo \"{ \\\"child-pid\\\": $pid }\"; exec sleep 30")?;
    let held = hold(&mut child, status);
    child.kill()?;
    child.wait()?;
    held
}

#[test]
fn a_sandbox_created_but_never_reported_goes_with_the_launchers_group() -> io::Result<()> {
    // The background sleep stands in for a sandbox `bwrap` created before
    // dying unreported: still in the launcher's process group.
    let (mut child, status) =
        launcher("sleep 30 >/dev/null 2>&1 </dev/null & echo \"sandbox=$!\" >&2; exit 1")?;
    let error = hold(&mut child, status)
        .err()
        .ok_or_else(|| io::Error::other("a launcher that never reported was held"))?;
    let sandbox = error
        .to_string()
        .split("sandbox=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next()?.parse::<u32>().ok())
        .ok_or_else(|| io::Error::other(format!("no sandbox pid in {error}")))?;
    assert!(
        gone_within(sandbox, Duration::from_secs(5)),
        "the unreported sandbox {sandbox} outlived the failed start"
    );
    Ok(())
}

#[test]
fn only_a_process_in_another_pid_namespace_counts_as_a_sandbox() {
    assert!(!starts_a_pid_namespace(
        i32::try_from(std::process::id()).unwrap_or(i32::MAX)
    ));
    assert!(!starts_a_pid_namespace(i32::MAX));
}
