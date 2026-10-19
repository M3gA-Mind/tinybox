//! The fd-leak regression test lives alone in its own process: it holds an
//! inheritable descriptor open, which would make concurrent spawns in the same
//! process fail closed.
#![cfg(target_os = "linux")]

#[allow(dead_code)]
mod support;

use std::io;
use std::os::fd::AsRawFd as _;
use std::time::Instant;

use support::{backend, done, jail, refused, sh};

#[test]
fn inheritable_host_descriptors_do_not_reach_the_sandbox() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let secret = tempfile::NamedTempFile::new()?;
    std::fs::write(secret.path(), "host-secret")?;
    let file = std::fs::File::open(secret.path())?;
    // Simulate a library that opened a descriptor without O_CLOEXEC.
    rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::empty())?;
    let fd = file.as_raw_fd();
    if fd > 9 {
        // `sh` cannot close it, so the spawn must fail closed instead.
        assert_eq!(
            refused(&backend, &jail(root.path()).deny_net()),
            Some(io::ErrorKind::InvalidInput)
        );
        done("fd-leak-refused", start);
        return Ok(());
    }
    let (_, out) = sh(
        &backend,
        &jail(root.path()).deny_net(),
        &format!("cat /proc/self/fd/{fd} 2>/dev/null; cat <&{fd} 2>/dev/null"),
    )?;
    assert!(
        !out.contains("host-secret"),
        "descriptor {fd} leaked: {out}"
    );
    // The host's own descriptor is untouched.
    drop(file);
    done("fd-leak", start);
    Ok(())
}
