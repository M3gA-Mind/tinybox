//! Platform shell selection and quote-preserving native command construction.

use tinybox_bus::{SelectShellRequest, ShellFlavor, ShellInvocation};

const WINDOWS_BOOTSTRAP_ENVIRONMENT: &[&str] = &[
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
];

/// Select this machine's shell without starting a process or returning secrets.
/// Unix uses Bash at a standard path with pipefail unless preservation was
/// requested; minimal hosts fall back to sh. Windows uses cmd with raw payload.
#[must_use]
pub fn select_shell(request: &SelectShellRequest) -> ShellInvocation {
    let flavor = if cfg!(windows) {
        ShellFlavor::Cmd
    } else {
        ShellFlavor::Posix
    };
    selection_for(request, flavor, bash_path())
}

/// Build the selected native command without spawning it. The execution
/// provider remains responsible for environment, confinement, pipes and lifecycle.
#[must_use]
pub fn build_shell_command(request: &SelectShellRequest) -> std::process::Command {
    let selection = select_shell(request);
    let mut command = std::process::Command::new(selection.program);
    command.args(selection.arguments);
    for name in selection.remove_environment {
        command.env_remove(name);
    }
    #[cfg(windows)]
    if let Some(raw) = selection.raw_arguments {
        use std::os::windows::process::CommandExt;
        command.raw_arg(raw);
    }
    command
}

fn selection_for(
    request: &SelectShellRequest,
    flavor: ShellFlavor,
    bash: Option<&str>,
) -> ShellInvocation {
    match flavor {
        ShellFlavor::Cmd => ShellInvocation {
            flavor,
            program: "cmd".into(),
            // Disable registry AutoRun and make cmd strip exactly our outer
            // wrapper, preserving quoted executable/argument pairs inside.
            arguments: vec![
                "/D".into(),
                "/E:ON".into(),
                "/V:OFF".into(),
                "/S".into(),
                "/C".into(),
            ],
            raw_arguments: Some(format!("\"{}\"", request.command)),
            bootstrap_environment: WINDOWS_BOOTSTRAP_ENVIRONMENT
                .iter()
                .map(|name| (*name).into())
                .collect(),
            remove_environment: Vec::new(),
        },
        ShellFlavor::Posix => ShellInvocation {
            flavor,
            program: bash.unwrap_or("sh").into(),
            arguments: {
                let mut arguments = Vec::new();
                if bash.is_some() {
                    // Privileged startup ignores exported functions even when
                    // environment overrides are applied after command construction.
                    arguments.push("-p".into());
                }
                arguments.extend([
                    "-c".into(),
                    if bash.is_some() && !request.preserve_pipeline_status {
                        format!("set -o pipefail\n{}", request.command)
                    } else {
                        request.command.clone()
                    },
                ]);
                arguments
            },
            raw_arguments: None,
            bootstrap_environment: Vec::new(),
            remove_environment: vec![
                "BASH_ENV".into(),
                "ENV".into(),
                "SHELLOPTS".into(),
                "BASHOPTS".into(),
            ],
        },
    }
}

fn bash_path() -> Option<&'static str> {
    bash_path_in(&["/usr/bin/bash", "/bin/bash"])
}

fn bash_path_in(paths: &[&'static str]) -> Option<&'static str> {
    static BASH: std::sync::OnceLock<Option<&'static str>> = std::sync::OnceLock::new();
    *BASH.get_or_init(|| {
        paths
            .iter().copied()
            .find(|path| std::path::Path::new(path).is_file())
    })
}

#[cfg(test)]
#[path = "shell_tests.rs"]
mod tests;
