//! Inherited file descriptors.
//!
//! `bwrap` passes every descriptor it inherits to the sandboxed program, so a
//! descriptor the host opened without `O_CLOEXEC` (a database handle, a
//! socket-activation fd) would be readable inside the jail. Rust opens its own
//! descriptors close-on-exec, but a library may not. Without `unsafe` (the
//! workspace forbids it) the child cannot be made to close them with
//! `pre_exec`, so the launcher is wrapped in a `sh` that closes them just
//! before `exec`ing `bwrap`.

use std::io;

/// `O_CLOEXEC` as it appears in `/proc/self/fdinfo/N` (octal on Linux).
const O_CLOEXEC: u32 = 0o2_000_000;

/// The shell can only close descriptors 0-9 portably (`dash`).
const MAX_SHELL_FD: i32 = 9;

/// Open descriptors above stderr that would survive an `exec`.
///
/// # Errors
/// Returns the error from reading `/proc/self/fd`.
pub(super) fn leaked_fds() -> io::Result<Vec<i32>> {
    let mut leaked = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let name = entry?.file_name();
        let Some(fd) = name.to_str().and_then(|n| n.parse::<i32>().ok()) else {
            continue;
        };
        if fd <= 2 {
            continue;
        }
        // The directory iterator's own descriptor is gone by now: unreadable.
        let Ok(info) = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")) else {
            continue;
        };
        if !has_cloexec(&info) {
            leaked.push(fd);
        }
    }
    leaked.sort_unstable();
    Ok(leaked)
}

/// Whether `/proc/<pid>/fdinfo/<fd>` text says the descriptor is close-on-exec.
pub(super) fn has_cloexec(fdinfo: &str) -> bool {
    fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("flags:"))
        .and_then(|flags| u32::from_str_radix(flags.trim(), 8).ok())
        .is_some_and(|flags| flags & O_CLOEXEC != 0)
}

/// The `sh -c` script that closes `leaked` and then runs `"$0" "$@"`.
///
/// # Errors
/// `InvalidInput` when a leaked descriptor is above 9, which `sh` cannot
/// close: the spawn fails closed instead of leaking it.
pub(super) fn closing_script(leaked: &[i32]) -> io::Result<String> {
    if let Some(fd) = leaked.iter().find(|fd| **fd > MAX_SHELL_FD) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "file descriptor {fd} is inherited without close-on-exec and cannot be closed \
                 before the sandbox starts; mark it close-on-exec"
            ),
        ));
    }
    let mut script = String::from("exec ");
    for fd in leaked {
        script.push_str(&fd.to_string());
        script.push_str(">&- ");
    }
    script.push_str("; exec \"$0\" \"$@\"");
    Ok(script)
}

#[cfg(test)]
#[path = "fds_tests.rs"]
mod tests;
