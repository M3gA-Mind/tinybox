//! The fd-leak regression test lives alone in its own process: it holds an
//! inheritable descriptor open, which would make concurrent spawns in the same
//! process fail closed.
#![cfg(target_os = "linux")]

#[allow(dead_code)]
mod support;

use std::io;
use std::os::fd::AsRawFd;
use std::time::Instant;

use support::{backend, done, jail, sh};

#[test]
fn inheritable_host_descriptors_do_not_reach_the_sandbox() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let secret = tempfile::NamedTempFile::new()?;
    std::fs::write(secret.path(), "host-secret")?;
    // Simulate libraries that opened descriptors without O_CLOEXEC. Enough of
    // them that some are above 9, which a plain `sh` launcher cannot close.
    let mut files = Vec::new();
    for _ in 0..12 {
        let file = std::fs::File::open(secret.path())?;
        rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::empty())?;
        files.push(file);
    }
    let fds: Vec<i32> = files.iter().map(AsRawFd::as_raw_fd).collect();
    assert!(fds.iter().any(|fd| *fd > 9), "{fds:?}");
    let mut script = String::new();
    for fd in &fds {
        script.push_str("cat /proc/self/fd/");
        script.push_str(&fd.to_string());
        script.push_str(" 2>/dev/null; ");
    }
    let (_, out) = sh(&backend, &jail(root.path()).deny_net(), &script)?;
    assert!(
        !out.contains("host-secret"),
        "descriptors {fds:?} leaked: {out}"
    );
    // The host's own descriptor is untouched.
    assert_eq!(files.len(), 12);
    done("fd-leak", start);
    Ok(())
}
