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

/// `/bin/sh` can only close descriptors 0-9 portably (`dash`).
const MAX_SH_FD: i32 = 9;

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

/// The shell script that closes `leaked` and then runs `"$0" "$@"`.
#[must_use]
pub(super) fn closing_script(leaked: &[i32]) -> String {
    let mut script = String::from("exec ");
    for fd in leaked {
        script.push_str(&fd.to_string());
        script.push_str(">&- ");
    }
    script.push_str("; exec \"$0\" \"$@\"");
    script
}

/// The shell able to run [`closing_script`] for `leaked`: `/bin/sh` closes
/// descriptors 0-9 only (`dash`), so a higher one needs `bash`.
///
/// # Errors
/// `InvalidInput` when a descriptor above 9 leaked and no `bash` exists: the
/// spawn fails closed instead of leaking it.
pub(super) fn shell_for(leaked: &[i32], exists: impl Fn(&str) -> bool) -> io::Result<&'static str> {
    if leaked.iter().all(|fd| *fd <= MAX_SH_FD) {
        return Ok("/bin/sh");
    }
    ["/bin/bash", "/usr/bin/bash"]
        .into_iter()
        .find(|path| exists(path))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "file descriptor {} is inherited without close-on-exec and no bash is \
                     available to close it before the sandbox starts; mark it close-on-exec",
                    leaked.iter().max().copied().unwrap_or_default()
                ),
            )
        })
}

#[cfg(test)]
#[path = "fds_tests.rs"]
mod tests;
