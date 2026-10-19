//! Cross-platform directory-jail facade.
//!
//! A [`Jail`] describes *what* the agent is allowed to see; a [`JailBackend`]
//! enforces it on a specific OS. Callers only interact with [`Jail`] and the
//! top-level [`crate::spawn`] function — they
//! never pick a backend by name.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};

const RESOURCE_CONSTRAINTS: [tinybox_core::Constraint; 4] = [
    tinybox_core::Constraint::Cpu,
    tinybox_core::Constraint::Memory,
    tinybox_core::Constraint::Pids,
    tinybox_core::Constraint::Disk,
];

/// Declarative description of a directory jail.
///
/// One `root` (read/write), zero or more extra `read_write` paths, zero or
/// more `read_only` paths, and a network toggle.
/// Backends translate this into Landlock rules, a Seatbelt profile, or an
/// `AppContainer` ACL.
#[derive(Debug, Clone)]
pub struct Jail {
    /// Primary read/write root. The child cannot escape this directory for
    /// writes. Must be an existing, canonicalizable directory.
    pub root: PathBuf,
    /// Extra paths the child may read (e.g. `/usr/lib`, the runtime-node
    /// install). Writes are still denied.
    pub read_only: Vec<PathBuf>,
    /// Extra paths outside the root the child may read **and write**, with
    /// the same access the root gets. Meant for host-owned scratch the child
    /// must write to without it landing inside the root (e.g. a per-call
    /// output-capture directory). Grant the narrowest directory that works.
    pub read_write: Vec<PathBuf>,
    /// Paths the child may neither read nor write. A backend that
    /// [`carves_denials`](JailBackend::carves_denials) subtracts them from
    /// grants; allow-list backends deny paths outside grants by default. The
    /// native module rejects overlaps that an allow-list backend cannot enforce.
    /// Missing paths are retained so backend rules can cover later creation.
    pub deny_read: Vec<PathBuf>,
    /// Optional hard CPU, memory, process and writable-disk limits.
    ///
    /// Backends include the corresponding constraints in preflight. A backend
    /// that does not enforce every requested limit refuses before spawning.
    pub resources: Option<tinybox_core::Resources>,
    /// Contract 2.1 resource subset for the namespace-backed native jail.
    /// This does not change the all-four-dimensions legacy `resources` field.
    pub native_resources: Option<tinybox_bus::NativeJailResourceRequest>,
    /// Allow outbound network. Most agent tools need this; some risky tools
    /// (untrusted code execution) should disable it.
    pub allow_net: bool,
    /// Allow the child to spawn further child processes. `AppContainer` and
    /// Seatbelt can deny this; Landlock cannot.
    pub allow_subprocess: bool,
    /// Free-form label used by audit logs and (on Windows) as the basis for
    /// the `AppContainer` profile name. Keep it short and ASCII.
    pub label: String,
}

impl Jail {
    /// Convenience: read/write jail rooted at `root` with networking enabled
    /// and no additional read-only mounts.
    pub fn new(root: impl AsRef<Path>, label: impl Into<String>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            read_only: Vec::new(),
            read_write: Vec::new(),
            deny_read: Vec::new(),
            resources: None,
            native_resources: None,
            allow_net: true,
            allow_subprocess: true,
            label: label.into(),
        }
    }

    /// Grants read (and execute) access to an extra path outside the root.
    #[must_use]
    pub fn add_read_only(mut self, path: impl AsRef<Path>) -> Self {
        self.read_only.push(path.as_ref().to_path_buf());
        self
    }

    /// Grants read and write access to an extra path outside the root.
    ///
    /// Backends grant it exactly what they grant the root: a Landlock rule on
    /// Linux, a `file-write*` subpath on macOS, an `AppContainer` ACL on
    /// Windows. The path should exist before spawning; backends that need an
    /// open handle (Landlock) fail the spawn when it does not.
    #[must_use]
    pub fn add_read_write(mut self, path: impl AsRef<Path>) -> Self {
        self.read_write.push(path.as_ref().to_path_buf());
        self
    }

    /// Requests network denial; strict preflight refuses unsupported backends.
    #[must_use]
    pub fn deny_net(mut self) -> Self {
        self.allow_net = false;
        self
    }

    /// Requests subprocess denial; strict preflight refuses unsupported backends.
    #[must_use]
    pub fn deny_subprocess(mut self) -> Self {
        self.allow_subprocess = false;
        self
    }

    /// Hard constraints implied by this jail's grants and denial flags.
    #[must_use]
    pub fn constraints(&self) -> Vec<tinybox_core::Constraint> {
        use tinybox_core::Constraint;
        let mut constraints = vec![Constraint::Filesystem];
        if !self.allow_net {
            constraints.push(Constraint::Network);
        }
        if !self.allow_subprocess {
            constraints.push(Constraint::Subprocess);
        }
        if self.resources.is_some() {
            constraints.extend([
                Constraint::Cpu,
                Constraint::Memory,
                Constraint::Pids,
                Constraint::Disk,
            ]);
        } else if let Some(resources) = self.native_resources {
            if resources.cpu_millis.is_some() {
                constraints.push(Constraint::Cpu);
            }
            if resources.memory_bytes.is_some() {
                constraints.push(Constraint::Memory);
            }
            if resources.pids_max.is_some() {
                constraints.push(Constraint::Pids);
            }
            if resources.disk_bytes.is_some() {
                constraints.push(Constraint::Disk);
            }
        }
        constraints
    }

    /// Canonicalize `root`, `read_only` and `read_write` so backends never see `..` or
    /// symlink trickery. Returns an error if `root` does not exist.
    ///
    /// # Errors
    ///
    /// Returns the filesystem error encountered while canonicalizing `root`.
    pub fn canonicalize(&mut self) -> std::io::Result<()> {
        self.root = self.root.canonicalize()?;
        for p in self
            .read_only
            .iter_mut()
            .chain(self.read_write.iter_mut())
            .chain(self.deny_read.iter_mut())
        {
            if let Ok(c) = p.canonicalize() {
                *p = c;
            }
        }
        self.deny_read = self
            .deny_read
            .iter()
            .map(|path| crate::registry::canonicalize_missing(path))
            .collect::<std::io::Result<Vec<_>>>()?;
        self.deny_read.sort();
        self.deny_read.dedup();
        Ok(())
    }

    /// Refuse denials that a non-carving backend cannot preserve against its
    /// explicit and implicit grants after path canonicalization.
    pub(crate) fn validate_denials(
        &self,
        carves_denials: bool,
        implicit_grants: &[PathBuf],
    ) -> std::io::Result<()> {
        if carves_denials || self.deny_read.is_empty() {
            return Ok(());
        }
        let implicit_grants = implicit_grants
            .iter()
            .map(|path| crate::registry::canonicalize_missing(path))
            .collect::<std::io::Result<Vec<_>>>()?;
        for denied in &self.deny_read {
            if std::iter::once(&self.root)
                .chain(&self.read_only)
                .chain(&self.read_write)
                .chain(&implicit_grants)
                .any(|granted| denied.starts_with(granted) || granted.starts_with(denied))
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "denied path overlaps an allow-list or implicit grant",
                ));
            }
        }
        Ok(())
    }

    /// Best-effort canonicalize that swallows errors and logs them. Most
    /// callers should use the validating [`Jail::canonicalize`] path that
    /// [`crate::spawn`] runs automatically.
    pub fn canonicalize_or_log(&mut self) {
        if let Err(e) = self.canonicalize() {
            log::warn!(
                "[cwd_jail] failed to canonicalize jail root {}: {}",
                self.root.display(),
                e
            );
        }
    }
}

/// OS-specific enforcement of a [`Jail`].
///
/// We model spawning rather than `Command` mutation because Windows
/// `AppContainer` requires custom `CreateProcess` flags that `std`'s
/// `Command::spawn` does not expose.
pub trait JailBackend: Send + Sync {
    /// Paths the backend implicitly grants in addition to explicit jail roots.
    ///
    /// Callers enforcing hard denials use these paths to detect overlaps that
    /// the backend's allow rules would otherwise override. Backends should
    /// report every recursively granted baseline path; the default means the
    /// backend has no implicit filesystem grants.
    fn implicit_grants(&self) -> Vec<PathBuf> {
        Vec::new()
    }

    /// Whether [`Jail::deny_read`] is enforced even inside the root or a grant.
    /// Allow-list backends (Landlock, `AppContainer`) cannot subtract from a
    /// grant, so they keep the default `false`.
    fn carves_denials(&self) -> bool {
        false
    }

    /// Stable identifier, used in logs / audit ("landlock", "seatbelt",
    /// "appcontainer", "noop").
    fn name(&self) -> &'static str;

    /// Whether the backend can actually enforce the jail in this process /
    /// on this kernel build. Auto-detection consults this before returning
    /// a backend.
    fn is_available(&self) -> bool;

    /// Declares implemented constraints; unknown backends claim nothing.
    fn constraint_support(&self) -> tinybox_core::ConstraintSupport {
        tinybox_core::ConstraintSupport::NONE
    }

    /// Process isolation provided by this backend, independent of path checks.
    fn isolation(&self) -> tinybox_core::IsolationLevel {
        tinybox_core::IsolationLevel::None
    }

    /// Whether the backend confines processes sufficiently for untrusted code.
    fn is_suitable_for_untrusted_code(&self) -> bool {
        self.isolation() >= tinybox_core::IsolationLevel::Kernel
            && self
                .constraint_support()
                .enforcement(tinybox_core::Constraint::Filesystem)
                == tinybox_core::Enforcement::Enforced
    }

    /// Inspect all hard constraints a directory jail requests.
    fn plan_check(&self, jail: &Jail) -> tinybox_core::PlanCheck {
        self.constraint_support().plan_check(&jail.constraints())
    }

    /// Refuse incomplete filesystem, network or subprocess confinement.
    ///
    /// # Errors
    /// Returns a typed constraint refusal before any child is spawned.
    fn require(&self, jail: &Jail) -> tinybox_core::Result<()> {
        self.constraint_support()
            .require(self.name(), &jail.constraints())
    }

    /// Require full enforcement for every resource limit present on a jail.
    ///
    /// Resource limits are hard requirements even when the caller accepts
    /// declared filesystem, network, or subprocess enforcement.
    ///
    /// # Errors
    /// Returns a typed refusal if any requested resource constraint is not
    /// fully enforced.
    fn require_resources(&self, jail: &Jail) -> tinybox_core::Result<()> {
        if let Some(resources) = jail.resources {
            resources.validate()?;
            self.constraint_support()
                .require(self.name(), &RESOURCE_CONSTRAINTS)?;
        } else if let Some(resources) = jail.native_resources {
            for (limit, value) in [
                ("cpu_millis", resources.cpu_millis),
                ("memory_bytes", resources.memory_bytes),
                ("pids_max", resources.pids_max),
                ("disk_bytes", resources.disk_bytes),
            ] {
                if value == Some(0) {
                    return Err(tinybox_core::Error::ZeroResourceLimit { limit });
                }
            }
            if resources.cpu_millis.is_none()
                && resources.memory_bytes.is_none()
                && resources.pids_max.is_none()
                && resources.disk_bytes.is_none()
            {
                return Err(tinybox_core::Error::ConstraintNotEnforced {
                    sandbox: self.name().to_owned(),
                    constraint: tinybox_core::Constraint::Cpu,
                    enforcement: tinybox_core::Enforcement::Unsupported,
                });
            }
            self.constraint_support()
                .require(self.name(), &jail.constraints())?;
        }
        Ok(())
    }

    /// Spawn `cmd` under the jail described by `jail`. Callers must run
    /// [`JailBackend::require_resources`] before calling this method when
    /// `jail.resources` is present. Backends own how the
    /// jail is materialized (Landlock ruleset, sandbox-exec wrapper,
    /// `AppContainer` profile + restricted token).
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot apply the jail or spawn command.
    fn spawn(&self, jail: &Jail, cmd: Command) -> std::io::Result<Child>;

    /// Spawn with module-owned stdin, stdout, and stderr pipes.
    /// Wrapping providers must apply these pipes to their actual launcher.
    /// Callers must run [`JailBackend::require_resources`] first when
    /// `jail.resources` is present.
    /// # Errors
    /// Returns the provider's confinement or native startup error.
    fn spawn_captured(&self, jail: &Jail, mut cmd: Command) -> std::io::Result<Child> {
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        self.spawn(jail, cmd)
    }
}

#[cfg(test)]
#[path = "jail_tests.rs"]
mod tests;
