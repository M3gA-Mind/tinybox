//! Linux bubblewrap backend: namespace isolation for untrusted code.
//!
//! [`BubblewrapBackend`] runs the command under `bwrap` with fresh user, pid,
//! ipc and uts namespaces (and a net namespace unless the jail allows
//! network). The child sees a private mount tree holding only the baseline
//! system paths in [`args`] plus the jail's grants, so it cannot read an
//! ungranted path, cannot see host processes, and dies with its parent. That
//! is real process isolation, which Landlock alone does not provide, so this
//! backend reports [`IsolationLevel::Kernel`] and is suitable for untrusted
//! code.
//!
//! # Availability
//!
//! `bwrap` must be on `PATH` and the kernel must let an unprivileged process
//! create user namespaces (Ubuntu 24.04 needs an `AppArmor` profile for
//! `bwrap`; Debian needs `kernel.unprivileged_userns_clone=1`). Both are
//! checked once per process by actually running a probe sandbox, since sysctls
//! alone miss container and LSM restrictions. When the probe fails the backend
//! reports unavailable and [`crate::detect::pick_backend`] falls back to
//! Landlock, which keeps refusing configs that require process isolation.
//!
//! # Why Landlock is not layered inside
//!
//! The kernel denies `mount` and `pivot_root` to a Landlock-restricted thread,
//! so restricting the thread that spawns `bwrap` would break the sandbox
//! setup. The mount namespace already enforces the same filesystem policy.
//!
//! # Limits
//!
//! Subprocess denial is not enforced (the child may fork inside its pid
//! namespace) and is refused before spawn. Stdio configured on the original
//! `Command` is not recoverable from `std`, as with the Seatbelt backend, and
//! its environment is rebuilt from explicit `env` calls only: nothing from the
//! parent is inherited.

use std::io;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::OnceLock;

use tinybox_core::{Constraint, ConstraintSupport, Enforcement, IsolationLevel};

use crate::jail::{Jail, JailBackend};

mod args;

/// Backend name reported by [`BubblewrapBackend`].
pub const BWRAP_BACKEND_NAME: &str = "bubblewrap";

/// Result of the one-time probe against the `bwrap` found on `PATH`.
static PATH_PROBE: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Bubblewrap (`bwrap`) namespace jail backend.
#[derive(Debug, Clone)]
pub struct BubblewrapBackend {
    /// A `bwrap` that has been shown to create a sandbox, if any.
    program: Option<PathBuf>,
}

impl Default for BubblewrapBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl BubblewrapBackend {
    /// Finds `bwrap` on `PATH` and probes it once per process.
    #[must_use]
    pub fn new() -> Self {
        let program = PATH_PROBE
            .get_or_init(|| {
                let found = tinybox_linux::NamespaceProbe::detect().bwrap;
                found.filter(|path| probe(path))
            })
            .clone();
        Self { program }
    }

    /// Uses an explicit `bwrap` binary, probing it now. Unavailable if the
    /// probe sandbox cannot start.
    #[must_use]
    pub fn with_program(program: impl Into<PathBuf>) -> Self {
        let program = program.into();
        Self {
            program: probe(&program).then_some(program),
        }
    }

    /// The `bwrap` binary this backend launches, when available.
    #[must_use]
    pub fn program(&self) -> Option<&std::path::Path> {
        self.program.as_deref()
    }
}

/// Runs a throwaway sandbox to learn whether user namespaces really work here.
fn probe(program: &std::path::Path) -> bool {
    let jail = Jail::new(std::env::temp_dir(), "bwrap-probe").deny_net();
    let Ok(mut argv) = args::jail_args(&jail, None) else {
        return false;
    };
    argv.push("--".into());
    argv.push("true".into());
    let ok = Command::new(program)
        .args(&argv)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    log::debug!("[cwd_jail:bwrap] probe of {} -> {ok}", program.display());
    ok
}

/// Rebuilds `cmd` as a `bwrap` invocation of the same program.
fn prepare_command(program: &std::path::Path, jail: &Jail, cmd: &Command) -> io::Result<Command> {
    let mut wrapper = Command::new(program);
    // Fail closed for environment authority: nothing is inherited.
    wrapper.env_clear();
    wrapper.args(args::jail_args(jail, cmd.get_current_dir())?);
    wrapper
        .arg("--")
        .arg(cmd.get_program())
        .args(cmd.get_args());
    for (key, value) in cmd.get_envs() {
        if let Some(value) = value {
            wrapper.env(key, value);
        }
    }
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
        self.program.is_some()
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
        if self.is_available() {
            IsolationLevel::Kernel
        } else {
            IsolationLevel::None
        }
    }

    fn spawn(&self, jail: &Jail, cmd: Command) -> io::Result<Child> {
        let Some(program) = self.program.as_deref() else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "bubblewrap is not available (bwrap missing or user namespaces disabled)",
            ));
        };
        let unmet: Vec<_> = jail
            .constraints()
            .into_iter()
            .filter(|c| *c != Constraint::Filesystem)
            .collect();
        self.constraint_support()
            .require(self.name(), &unmet)
            .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))?;
        log::debug!("[cwd_jail:bwrap] spawning label={}", jail.label);
        prepare_command(program, jail, &cmd)?.spawn()
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
