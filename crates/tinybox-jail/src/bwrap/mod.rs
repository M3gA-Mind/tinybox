//! Linux bubblewrap backend: namespace isolation for untrusted code.
//!
//! [`BubblewrapBackend`] runs the command under `bwrap` with fresh user, pid,
//! ipc and uts namespaces (and a net namespace unless the jail allows
//! network). The child sees a private mount tree holding only the baseline
//! system paths plus the jail's grants, so it cannot read an ungranted path,
//! cannot see host processes, cannot create nested user namespaces
//! (`--disable-userns`), and dies with its parent.
//!
//! # Choosing and trusting `bwrap`
//!
//! `bwrap` is the host's privileged-adjacent helper, so it is never looked up
//! on `PATH`. Only `/usr/bin/bwrap`, `/usr/local/bin/bwrap` and `/bin/bwrap`
//! are considered, and only when owned by root and not group- or
//! other-writable. [`BubblewrapBackend::with_program`] lets a host name another
//! binary explicitly. Either way the binary must pass a probe, run once per
//! process: a sandbox that really starts, in which a host-only file is
//! invisible and the pid namespace differs from the parent's. A shim that just
//! runs its arguments fails that probe.
//!
//! The command's environment is **never** applied to the host `bwrap` process
//! (`LD_PRELOAD` there would run caller code unsandboxed). `bwrap` runs with an
//! empty environment and the caller's variables are passed as `--setenv`.
//!
//! # What is claimed
//!
//! [`IsolationLevel::Kernel`] requires `--disable-userns` support (bubblewrap
//! 0.8+); without it the backend still confines the filesystem but reports
//! [`IsolationLevel::None`]. With a shared network namespace (`allow_net`) the
//! per-jail answer drops further, see [`JailBackend::isolation_for`]: host
//! loopback services and abstract sockets are reachable, so such a jail is not
//! suitable for untrusted code. Hosts must ask
//! [`JailBackend::is_suitable_for_untrusted_jail`], not the per-backend form.
//!
//! # Known gaps (not closed in this backend)
//!
//! - No seccomp filter: `keyctl` (the user's kernel keyrings), `ptrace`,
//!   `bpf`, `io_uring` and similar syscalls remain reachable. A filter needs a
//!   file descriptor handed to `bwrap --seccomp`, which cannot be done without
//!   `unsafe` or a helper process.
//! - No CPU, memory or pid limits (`tinybox-linux` offers them through a
//!   `systemd-run` scope; not wired here).
//! - `deny_read` paths must exist when the jail starts, and one nested more
//!   than a level inside a writable grant is refused.
//! - Landlock is not layered inside: the kernel denies `mount` and
//!   `pivot_root` to a Landlock-restricted thread, which would break `bwrap`'s
//!   own setup.
//!
//! # Other behaviour
//!
//! Subprocess denial is not enforced and is refused. Stdio configured on the
//! original `Command` is not recoverable from `std` (as with Seatbelt); use
//! `spawn_captured` for pipes. File descriptors above 2 that the host left
//! inheritable are closed before the sandbox starts (see `fds.rs`).

use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

use tinybox_core::{Constraint, ConstraintSupport, Enforcement, IsolationLevel};

use crate::jail::{Jail, JailBackend};

mod args;
mod fds;

/// Backend name reported by [`BubblewrapBackend`].
pub const BWRAP_BACKEND_NAME: &str = "bubblewrap";

/// Where a trusted `bwrap` may live.
const TRUSTED_PATHS: &[&str] = &["/usr/bin/bwrap", "/usr/local/bin/bwrap", "/bin/bwrap"];

/// One probe per process for the default (trusted-path) `bwrap`.
static DEFAULT_PROBE: OnceLock<Option<Verified>> = OnceLock::new();

/// A `bwrap` shown to create a sandbox, and what it supports.
#[derive(Debug, Clone)]
struct Verified {
    program: PathBuf,
    disable_userns: bool,
}

/// Bubblewrap (`bwrap`) namespace jail backend.
#[derive(Debug, Clone)]
pub struct BubblewrapBackend {
    verified: Option<Verified>,
}

impl Default for BubblewrapBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl BubblewrapBackend {
    /// Finds a trusted `bwrap` and probes it once per process.
    #[must_use]
    pub fn new() -> Self {
        let verified = DEFAULT_PROBE
            .get_or_init(|| {
                let found = TRUSTED_PATHS
                    .iter()
                    .map(PathBuf::from)
                    .find(|path| is_trusted_binary(path));
                let verified = found.and_then(|path| verify(&path));
                if verified.is_none() {
                    log::debug!(
                        "[cwd_jail:bwrap] unavailable: {}",
                        tinybox_linux::NamespaceProbe::detect()
                            .problem()
                            .unwrap_or_else(|| "no trusted bwrap passed the probe".to_owned())
                    );
                }
                verified
            })
            .clone();
        Self { verified }
    }

    /// Uses an explicit `bwrap` binary chosen by the host. The ownership check
    /// is skipped (the host vouches for the path) but the isolation probe is
    /// not. Unavailable if the probe fails.
    #[must_use]
    pub fn with_program(program: impl Into<PathBuf>) -> Self {
        Self {
            verified: verify(&program.into()),
        }
    }

    /// The `bwrap` binary this backend launches, when available.
    #[must_use]
    pub fn program(&self) -> Option<&Path> {
        self.verified.as_ref().map(|v| v.program.as_path())
    }

    /// Test constructor that skips the probe, for fake launchers.
    #[cfg(test)]
    fn unverified(program: impl Into<PathBuf>, disable_userns: bool) -> Self {
        Self {
            verified: Some(Verified {
                program: program.into(),
                disable_userns,
            }),
        }
    }
}

/// Whether `path` is a regular executable owned by root and writable by no one
/// else.
fn is_trusted_binary(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| {
        meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0 && meta.mode() & 0o111 != 0
    })
}

/// Runs throwaway sandboxes to learn whether `program` really isolates, and
/// whether it supports `--disable-userns`.
fn verify(program: &Path) -> Option<Verified> {
    for disable_userns in [true, false] {
        if probe(program, disable_userns) {
            return Some(Verified {
                program: program.to_path_buf(),
                disable_userns,
            });
        }
    }
    None
}

fn probe(program: &Path, disable_userns: bool) -> bool {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let dir = PathBuf::from("/tmp").join(format!(
        "tinybox-bwrap-probe-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let root = dir.join("root");
    let host_only = dir.join("host-only");
    let setup = std::fs::create_dir_all(&root).and_then(|()| std::fs::write(&host_only, "x"));
    let ok = setup.is_ok() && run_probe(program, disable_userns, &root, &host_only);
    let _ = std::fs::remove_dir_all(&dir);
    log::debug!(
        "[cwd_jail:bwrap] probe {} disable_userns={disable_userns} -> {ok}",
        program.display()
    );
    ok
}

fn run_probe(program: &Path, disable_userns: bool, root: &Path, host_only: &Path) -> bool {
    let Ok(parent_pidns) = std::fs::read_link("/proc/self/ns/pid") else {
        return false;
    };
    let jail = Jail::new(root, "bwrap-probe").deny_net();
    let Ok(mut argv) = args::jail_args(&jail, None, args::Options { disable_userns }) else {
        return false;
    };
    argv.extend(
        [
            "--",
            "/bin/sh",
            "-c",
            "test ! -e \"$1\" && test \"$(readlink /proc/self/ns/pid)\" != \"$2\" && echo isolated",
            "probe",
        ]
        .map(Into::into),
    );
    argv.push(host_only.into());
    argv.push(parent_pidns.into());
    // Positive evidence is required: a launcher that exits 0 without running
    // the check (`true`) must not pass.
    Command::new(program)
        .env_clear()
        .args(&argv)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|out| out.status.success() && out.stdout == b"isolated\n")
}

/// Rebuilds `cmd` as a `bwrap` invocation of the same program.
///
/// The returned command carries no environment of its own: variables set on
/// `cmd` reach the child only as `--setenv` arguments.
fn prepare_command(verified: &Verified, jail: &Jail, cmd: &Command) -> io::Result<Command> {
    let mut argv = args::jail_args(
        jail,
        cmd.get_current_dir(),
        args::Options {
            disable_userns: verified.disable_userns,
        },
    )?;
    argv.push("--clearenv".into());
    for (key, value) in cmd.get_envs() {
        if let Some(value) = value {
            argv.extend(["--setenv".into(), key.to_os_string(), value.to_os_string()]);
        }
    }
    argv.push("--".into());
    argv.push(cmd.get_program().to_os_string());
    argv.extend(cmd.get_args().map(std::ffi::OsStr::to_os_string));

    let leaked = fds::leaked_fds()?;
    let mut wrapper = if leaked.is_empty() {
        let mut direct = Command::new(&verified.program);
        direct.args(&argv);
        direct
    } else {
        let shell_path = fds::shell_for(&leaked, |path| Path::new(path).is_file())?;
        let mut shell = Command::new(shell_path);
        shell
            .arg("-c")
            .arg(fds::closing_script(&leaked))
            .arg(&verified.program)
            .args(&argv);
        shell
    };
    wrapper.env_clear();
    Ok(wrapper)
}

impl JailBackend for BubblewrapBackend {
    fn carves_denials(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        BWRAP_BACKEND_NAME
    }

    fn is_available(&self) -> bool {
        self.verified.is_some()
    }

    fn constraint_support(&self) -> ConstraintSupport {
        if self.is_available() {
            ConstraintSupport::NONE
                .with(Constraint::Filesystem, Enforcement::Enforced)
                .with(Constraint::Network, Enforcement::Enforced)
        } else {
            ConstraintSupport::NONE
        }
    }

    fn isolation(&self) -> IsolationLevel {
        match &self.verified {
            Some(v) if v.disable_userns => IsolationLevel::Kernel,
            _ => IsolationLevel::None,
        }
    }

    fn isolation_for(&self, jail: &Jail) -> IsolationLevel {
        // A shared network namespace exposes host loopback services and
        // abstract sockets. `Process` is the closest defined level below
        // `Kernel`.
        match self.isolation() {
            IsolationLevel::Kernel if jail.allow_net => IsolationLevel::Process,
            level => level,
        }
    }

    fn spawn(&self, jail: &Jail, cmd: Command) -> io::Result<Child> {
        self.launch(jail, &cmd, false)
    }

    fn spawn_captured(&self, jail: &Jail, cmd: Command) -> io::Result<Child> {
        self.launch(jail, &cmd, true)
    }
}

impl BubblewrapBackend {
    /// Preflight, rebuild the command as `bwrap`, and spawn it. Pipes must be
    /// set on the wrapper, not the original command, which is discarded.
    fn launch(&self, jail: &Jail, cmd: &Command, captured: bool) -> io::Result<Child> {
        let Some(verified) = &self.verified else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "bubblewrap is not available (no trusted working bwrap or user namespaces disabled)",
            ));
        };
        self.constraint_support()
            .require(self.name(), &jail.constraints())
            .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))?;
        log::debug!("[cwd_jail:bwrap] spawning label={}", jail.label);
        let mut wrapper = prepare_command(verified, jail, cmd)?;
        if captured {
            wrapper
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                // Own process group, as the Seatbelt backend does, so the host
                // can signal the whole sandbox.
                .process_group(0);
        }
        wrapper.spawn()
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
