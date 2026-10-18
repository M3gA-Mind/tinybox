//! Linux-only: a bubblewrap-jailed process is really isolated. Each test
//! returns early (with a note) when `bwrap` or user namespaces are missing.
#![cfg(target_os = "linux")]

use std::io;
use std::process::Command;

use tinybox_jail::{BubblewrapBackend, Jail, JailBackend, spawn_captured_with};

fn backend() -> Option<BubblewrapBackend> {
    let backend = BubblewrapBackend::new();
    if !backend.is_available() {
        eprintln!("skipped: bwrap or unprivileged user namespaces unavailable");
        return None;
    }
    Some(backend)
}

/// Hard preflight, then spawn with owned pipes (the wrapper cannot see the
/// original command's stdio) and collect the output.
fn run(backend: &BubblewrapBackend, jail: &Jail, cmd: Command) -> io::Result<std::process::Output> {
    backend
        .require(jail)
        .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))?;
    spawn_captured_with(backend, jail, cmd)?.wait_with_output()
}

/// Runs `script` under `sh -c` inside `jail`; returns (success, stdout).
fn sh(backend: &BubblewrapBackend, jail: &Jail, script: &str) -> io::Result<(bool, String)> {
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg(script);
    let out = run(backend, jail, cmd)?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    ))
}

fn jail(root: &std::path::Path) -> Jail {
    Jail::new(root, "bwrap-it")
}

#[test]
fn backend_is_suitable_for_untrusted_code() {
    let Some(backend) = backend() else { return };
    assert!(backend.is_suitable_for_untrusted_code());
}

#[test]
fn ungranted_paths_cannot_be_read() -> io::Result<()> {
    let Some(backend) = backend() else {
        return Ok(());
    };
    let root = tempfile::tempdir()?;
    let secret = tempfile::tempdir()?;
    let file = secret.path().join("secret");
    std::fs::write(&file, "token")?;
    let (ok, _) = sh(
        &backend,
        &jail(root.path()),
        &format!("cat '{}'", file.display()),
    )?;
    assert!(!ok, "an ungranted file must not be readable");
    Ok(())
}

#[test]
fn granted_paths_are_readable_and_root_is_writable() -> io::Result<()> {
    let Some(backend) = backend() else {
        return Ok(());
    };
    let root = tempfile::tempdir()?;
    let shared = tempfile::tempdir()?;
    std::fs::write(shared.path().join("f"), "hello")?;
    let j = jail(root.path()).add_read_only(shared.path());
    let script = format!(
        "cat '{}' && echo w > '{}' && ! echo w > '{}'",
        shared.path().join("f").display(),
        root.path().join("out").display(),
        shared.path().join("nope").display(),
    );
    let (ok, out) = sh(&backend, &j, &script)?;
    assert!(ok, "stdout: {out}");
    assert_eq!(out, "hello");
    assert_eq!(std::fs::read_to_string(root.path().join("out"))?, "w\n");
    Ok(())
}

#[test]
fn deny_read_masks_a_file_inside_the_root() -> io::Result<()> {
    let Some(backend) = backend() else {
        return Ok(());
    };
    let root = tempfile::tempdir()?;
    let secret = root.path().join("secret");
    std::fs::write(&secret, "token")?;
    let mut j = jail(root.path());
    j.deny_read = vec![secret.clone()];
    let (_, out) = sh(&backend, &j, &format!("cat '{}'", secret.display()))?;
    assert!(!out.contains("token"), "denied file leaked: {out}");
    Ok(())
}

#[test]
fn host_processes_are_invisible() -> io::Result<()> {
    let Some(backend) = backend() else {
        return Ok(());
    };
    let root = tempfile::tempdir()?;
    let (ok, out) = sh(&backend, &jail(root.path()), "ls /proc | grep -c '^[0-9]'")?;
    assert!(ok);
    let visible: u32 = out.trim().parse().unwrap_or(u32::MAX);
    assert!(visible <= 8, "only the jail's own processes: {visible}");
    Ok(())
}

#[test]
fn network_namespace_is_empty_when_denied() -> io::Result<()> {
    let Some(backend) = backend() else {
        return Ok(());
    };
    let root = tempfile::tempdir()?;
    let (ok, out) = sh(
        &backend,
        &jail(root.path()).deny_net(),
        "cut -d: -f1 /proc/net/dev | tail -n +3 | tr -d ' '",
    )?;
    assert!(ok);
    let routable = out.lines().any(|name| {
        ["eth", "en", "wl", "veth", "docker", "br"]
            .iter()
            .any(|p| name.starts_with(p))
    });
    assert!(
        out.lines().any(|n| n == "lo") && !routable,
        "no host NIC: {out}"
    );
    Ok(())
}

#[test]
fn parent_environment_is_not_inherited() -> io::Result<()> {
    let Some(backend) = backend() else {
        return Ok(());
    };
    let root = tempfile::tempdir()?;
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("printf %s \"$A-${HOME:-none}\"")
        .env("A", "1");
    let out = run(&backend, &jail(root.path()), cmd)?;
    assert_eq!(String::from_utf8_lossy(&out.stdout), "1-none");
    Ok(())
}
