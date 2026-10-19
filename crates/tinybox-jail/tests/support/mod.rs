//! Helpers shared by the bubblewrap integration tests.

use std::io;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use tinybox_jail::{BubblewrapBackend, Jail, JailBackend, spawn_captured_with};

/// The backend, `None` to skip, or an error when it is required but absent.
pub(crate) fn backend() -> io::Result<Option<BubblewrapBackend>> {
    let backend = BubblewrapBackend::new();
    if backend.is_available() {
        return Ok(Some(backend));
    }
    if std::env::var_os("TINYBOX_REQUIRE_BWRAP").is_some_and(|v| v == "1") {
        return Err(io::Error::other(
            "TINYBOX_REQUIRE_BWRAP=1 but no working bwrap (install bubblewrap and allow \
             unprivileged user namespaces)",
        ));
    }
    eprintln!("skipped: bwrap or unprivileged user namespaces unavailable");
    Ok(None)
}

pub(crate) fn done(name: &str, start: Instant) {
    eprintln!("[bwrap-real] {name} ok in {:?}", start.elapsed());
}

pub(crate) fn run(
    backend: &BubblewrapBackend,
    jail: &Jail,
    cmd: Command,
) -> io::Result<std::process::Output> {
    backend
        .require(jail)
        .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))?;
    spawn_captured_with(backend, jail, cmd)?.wait_with_output()
}

/// Runs `script` under `sh -c` inside `jail`; returns (success, stdout).
pub(crate) fn sh(
    backend: &BubblewrapBackend,
    jail: &Jail,
    script: &str,
) -> io::Result<(bool, String)> {
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg(script);
    let out = run(backend, jail, cmd)?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    ))
}

pub(crate) fn jail(root: &Path) -> Jail {
    Jail::new(root, "bwrap-it")
}

/// Like `sh` but returns the spawn error kind when the jail is refused.
pub(crate) fn refused(backend: &BubblewrapBackend, jail: &Jail) -> Option<io::ErrorKind> {
    let mut cmd = Command::new("/bin/true");
    cmd.arg("x");
    spawn_captured_with(backend, jail, cmd)
        .err()
        .map(|e| e.kind())
}
