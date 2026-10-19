//! Linux-only: a bubblewrap-jailed process is really isolated.
//!
//! Each test skips (with a note) when `bwrap` or unprivileged user namespaces
//! are missing, unless `TINYBOX_REQUIRE_BWRAP=1`, in which case a missing
//! sandbox is a failure. CI sets that variable so a skip can never pass for a
//! run. Every test that executes prints a `[bwrap-real]` line with its
//! duration for the CI log.
#![cfg(target_os = "linux")]

use std::io;
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use tinybox_jail::{JailBackend, spawn_captured_with};

#[allow(dead_code)]
mod support;

use support::*;

#[test]
fn backend_is_suitable_for_untrusted_code_only_without_shared_network() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let closed = jail(root.path()).deny_net();
    // The stricter claim needs `--disable-userns` (bubblewrap 0.8+).
    assert_eq!(
        backend.is_suitable_for_untrusted_jail(&closed),
        backend.is_suitable_for_untrusted_code()
    );
    assert!(!backend.is_suitable_for_untrusted_jail(&jail(root.path())));
    done("suitability", start);
    Ok(())
}

#[test]
fn ungranted_paths_cannot_be_read() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let secret = tempfile::tempdir()?;
    let file = secret.path().join("secret");
    std::fs::write(&file, "token")?;
    let (ok, out) = sh(
        &backend,
        &jail(root.path()),
        &format!("cat '{}'", file.display()),
    )?;
    assert!(!ok && !out.contains("token"), "an ungranted file leaked");
    done("ungranted", start);
    Ok(())
}

#[test]
fn granted_paths_are_readable_and_root_is_writable() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
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
    done("granted", start);
    Ok(())
}

#[test]
fn a_read_only_grant_nested_in_the_root_stays_read_only() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let nested = root.path().join("vendor");
    std::fs::create_dir(&nested)?;
    std::fs::write(nested.join("lib"), "orig")?;
    // The read-only grant is declared; the jail's own root is writable.
    let j = jail(root.path()).add_read_only(&nested);
    let script = format!(
        "! echo evil > '{0}/lib' && ! touch '{0}/new' && echo ok > '{1}/free'",
        nested.display(),
        root.path().display()
    );
    let (ok, out) = sh(&backend, &j, &script)?;
    assert!(ok, "nested read-only grant was writable: {out}");
    assert_eq!(std::fs::read_to_string(nested.join("lib"))?, "orig");
    done("nested-ro", start);
    Ok(())
}

#[test]
fn a_read_only_grant_nested_in_a_read_write_grant_stays_read_only() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let rw = tempfile::tempdir()?;
    let nested = rw.path().join("sub").join("ro");
    std::fs::create_dir_all(&nested)?;
    let j = jail(root.path())
        .add_read_only(&nested)
        .add_read_write(rw.path());
    let script = format!(
        "! touch '{}/x' && touch '{}/y'",
        nested.display(),
        rw.path().display()
    );
    let (ok, _) = sh(&backend, &j, &script)?;
    assert!(ok);
    assert!(!nested.join("x").exists());
    done("nested-ro-in-rw", start);
    Ok(())
}

#[test]
fn grants_replacing_private_mounts_are_refused() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    for bad in ["/", "/tmp", "/proc", "/dev"] {
        let j = jail(root.path()).add_read_only(bad);
        assert_eq!(
            refused(&backend, &j),
            Some(io::ErrorKind::InvalidInput),
            "{bad}"
        );
    }
    done("private-mount-grants", start);
    Ok(())
}

#[test]
fn deny_read_masks_a_file_inside_the_root() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let secret = root.path().join("secret");
    std::fs::write(&secret, "token")?;
    let mut j = jail(root.path());
    j.deny_read = vec![secret.clone()];
    let (_, out) = sh(&backend, &j, &format!("cat '{}'", secret.display()))?;
    assert!(!out.contains("token"), "denied file leaked: {out}");
    done("deny-file", start);
    Ok(())
}

#[test]
fn deny_read_masks_a_runtime_directory() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let dir = root.path().join("run");
    std::fs::create_dir(&dir)?;
    std::fs::write(dir.join("socket-token"), "token")?;
    let mut j = jail(root.path());
    j.deny_read = vec![dir.clone()];
    let script = format!("ls '{0}'; cat '{0}/socket-token'", dir.display());
    let (_, out) = sh(&backend, &j, &script)?;
    assert!(
        !out.contains("socket-token") && !out.contains("token"),
        "{out}"
    );
    done("deny-dir", start);
    Ok(())
}

#[test]
fn deny_read_nested_in_a_writable_grant_is_refused() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let nested = root.path().join("a").join("secret");
    std::fs::create_dir_all(&nested)?;
    let mut j = jail(root.path());
    j.deny_read = vec![nested];
    assert_eq!(refused(&backend, &j), Some(io::ErrorKind::InvalidInput));
    done("deny-nested-refused", start);
    Ok(())
}

#[test]
fn deny_read_under_baseline_mounts_is_enforced() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let mut j = jail(root.path());
    let mut denied = vec![];
    for candidate in ["/etc/hosts", "/usr/lib/os-release"] {
        if Path::new(candidate).exists() {
            denied.push(candidate);
        }
    }
    j.deny_read = denied.iter().map(Into::into).collect();
    for path in &denied {
        let (_, out) = sh(&backend, &j, &format!("cat '{path}'"))?;
        assert!(out.is_empty(), "{path} leaked: {out}");
    }
    // The rest of the baseline still works.
    let (ok, _) = sh(&backend, &j, "ls /usr/bin >/dev/null")?;
    assert!(ok);
    done("deny-baseline", start);
    Ok(())
}

#[test]
fn host_processes_are_invisible() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let (ok, out) = sh(&backend, &jail(root.path()), "ls /proc | grep -c '^[0-9]'")?;
    assert!(ok);
    let visible: u32 = out.trim().parse().unwrap_or(u32::MAX);
    assert!(visible <= 8, "only the jail's own processes: {visible}");
    done("pids", start);
    Ok(())
}

#[test]
fn network_is_unreachable_when_denied_and_reachable_when_shared() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    if Command::new("bash").arg("-c").arg("true").status().is_err() {
        eprintln!("skipped: bash is needed for /dev/tcp");
        return Ok(());
    }
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let connect = format!("exec 3<>/dev/tcp/127.0.0.1/{port}");
    let mut cmd = Command::new("/usr/bin/env");
    cmd.args(["bash", "-c", &connect]);
    let denied = run(&backend, &jail(root.path()).deny_net(), cmd)?;
    assert!(!denied.status.success(), "connect must fail under deny_net");

    // Control: with the host network shared the same connect succeeds, which
    // is exactly the exposure `allow_net` carries.
    let mut cmd = Command::new("/usr/bin/env");
    cmd.args(["bash", "-c", &connect]);
    let shared = run(&backend, &jail(root.path()), cmd)?;
    assert!(
        shared.status.success(),
        "control connect should reach the host listener"
    );
    done("network", start);
    Ok(())
}

#[test]
fn parent_environment_is_not_inherited_and_explicit_env_is_passed() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("printf %s \"$A-${HOME:-none}\"")
        .env("A", "1");
    let out = run(&backend, &jail(root.path()), cmd)?;
    assert_eq!(String::from_utf8_lossy(&out.stdout), "1-none");
    done("env", start);
    Ok(())
}

#[test]
fn caller_env_is_not_applied_to_the_host_bwrap_process() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let mut cmd = Command::new("/bin/sleep");
    cmd.arg("5")
        .env("LD_PRELOAD", "/nonexistent/evil.so")
        .env("TINYBOX_CANARY", "1");
    let mut child = spawn_captured_with(&backend, &jail(root.path()).deny_net(), cmd)?;
    // The child is the host-side bwrap (or its launcher): its environment is
    // what a loader hook would run in.
    let environ = std::fs::read(format!("/proc/{}/environ", child.id()))?;
    let _ = child.kill();
    let _ = child.wait();
    let text = String::from_utf8_lossy(&environ);
    assert!(
        !text.contains("LD_PRELOAD") && !text.contains("TINYBOX_CANARY"),
        "host bwrap saw the caller's env: {text:?}"
    );
    done("host-env", start);
    Ok(())
}

#[test]
fn nested_user_namespaces_are_blocked_on_a_hardened_backend() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    if !backend.is_suitable_for_untrusted_code() {
        eprintln!("skipped: bwrap lacks --disable-userns");
        return Ok(());
    }
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let (ok, _) = sh(&backend, &jail(root.path()).deny_net(), "unshare -U true")?;
    assert!(!ok, "a nested user namespace could be created");
    done("disable-userns", start);
    Ok(())
}
