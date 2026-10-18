//! Pure construction of the `bwrap` command line for a [`Jail`].
//!
//! What a sandbox binds and unshares *is* the security boundary, so every
//! decision here is a value a test can assert on. The only I/O is `lstat`-style
//! metadata reads (is a baseline path a symlink, is a denied path a directory).

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use crate::jail::Jail;

/// System directories bound read-only (or re-created as symlinks) so a shell,
/// the dynamic loader and the C library can start. Missing entries are skipped.
pub(super) const SYSTEM_DIRS: &[&str] = &[
    "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
];

/// The few `/etc` entries ordinary programs need (identity, name resolution,
/// TLS roots, the loader cache). Deliberately not all of `/etc`: that would
/// expose host keys and credentials the user can read.
pub(super) const ETC_ENTRIES: &[&str] = &[
    "/etc/passwd",
    "/etc/group",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/etc/localtime",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/etc/pki",
];

fn push(argv: &mut Vec<OsString>, parts: &[&std::ffi::OsStr]) {
    argv.extend(parts.iter().map(|part| (*part).to_os_string()));
}

fn flag(argv: &mut Vec<OsString>, name: &str) {
    argv.push(name.into());
}

fn bind(argv: &mut Vec<OsString>, kind: &str, path: &Path) {
    push(argv, &[kind.as_ref(), path.as_os_str(), path.as_os_str()]);
}

/// Whether `path` lies at or below any of `roots`.
fn under_any(path: &Path, roots: &[&PathBuf]) -> bool {
    roots.iter().any(|root| path.starts_with(root))
}

/// Everything after the `bwrap` program name and before the `--` separator.
///
/// - new user, pid, ipc, uts (and cgroup where supported) namespaces; a new
///   network namespace unless `jail.allow_net`;
/// - `--die-with-parent` and `--new-session`;
/// - a private `/proc`, `/dev` and `/tmp`, then the baseline system paths;
/// - the root and `read_write` grants writable, `read_only` grants read-only,
///   each at its own host path;
/// - `deny_read` paths subtracted last: a path equal to or above a grant drops
///   that grant, a path inside a grant is masked (`--tmpfs` for a directory,
///   `/dev/null` for a file). Anything outside every grant is simply never
///   mounted.
///
/// # Errors
/// Returns `NotFound` when the root or a `read_write` grant does not exist.
pub(super) fn jail_args(jail: &Jail, cwd: Option<&Path>) -> io::Result<Vec<OsString>> {
    let mut argv: Vec<OsString> = Vec::new();
    for name in [
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
    ] {
        flag(&mut argv, name);
    }
    if !jail.allow_net {
        flag(&mut argv, "--unshare-net");
    }
    flag(&mut argv, "--die-with-parent");
    flag(&mut argv, "--new-session");

    // `/tmp` first: a grant living under it (a scratch root) is bound on top.
    push(&mut argv, &["--proc".as_ref(), "/proc".as_ref()]);
    push(&mut argv, &["--dev".as_ref(), "/dev".as_ref()]);
    push(&mut argv, &["--tmpfs".as_ref(), "/tmp".as_ref()]);

    for dir in SYSTEM_DIRS {
        let path = Path::new(dir);
        match std::fs::read_link(path) {
            Ok(target) => push(
                &mut argv,
                &["--symlink".as_ref(), target.as_os_str(), path.as_os_str()],
            ),
            Err(_) => bind(&mut argv, "--ro-bind-try", path),
        }
    }
    for entry in ETC_ENTRIES {
        bind(&mut argv, "--ro-bind-try", Path::new(entry));
    }

    let denied: Vec<&PathBuf> = jail.deny_read.iter().collect();
    let denied_above = |path: &Path| denied.iter().any(|deny| path.starts_with(deny));

    for path in jail.read_only.iter().filter(|p| !denied_above(p)) {
        bind(&mut argv, "--ro-bind-try", path);
    }
    for path in std::iter::once(&jail.root).chain(&jail.read_write) {
        if !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("jail path {} does not exist", path.display()),
            ));
        }
        if !denied_above(path) {
            bind(&mut argv, "--bind", path);
        }
    }

    let grants: Vec<&PathBuf> = std::iter::once(&jail.root)
        .chain(&jail.read_write)
        .chain(&jail.read_only)
        .collect();
    for deny in &jail.deny_read {
        if !under_any(deny, &grants) {
            continue;
        }
        match std::fs::metadata(deny) {
            Ok(meta) if meta.is_dir() => {
                push(&mut argv, &["--tmpfs".as_ref(), deny.as_os_str()]);
            }
            Ok(_) => push(
                &mut argv,
                &[
                    "--ro-bind".as_ref(),
                    "/dev/null".as_ref(),
                    deny.as_os_str(),
                ],
            ),
            // Nothing there to hide.
            Err(_) => {}
        }
    }

    push(
        &mut argv,
        &[
            "--chdir".as_ref(),
            cwd.unwrap_or(&jail.root).as_os_str(),
        ],
    );
    Ok(argv)
}

#[cfg(test)]
#[path = "args_tests.rs"]
mod tests;
