//! Linux-only, live: an `allow_net` jail on a private `pasta` network reaches
//! the internet but not the host, and leaves no `pasta` behind.
//!
//! These need `bwrap`, `pasta` and `nsenter` and outbound network access, so
//! each skips (with a note) unless the backend reports
//! [`tinybox_jail::BubblewrapBackend::networks_privately`]. With
//! `TINYBOX_REQUIRE_PASTA=1` a missing private network is a failure instead;
//! CI sets it on the job that installs `passt`.
#![cfg(target_os = "linux")]

use std::io;
use std::net::TcpListener;
use std::os::linux::net::SocketAddrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::{SocketAddr, UnixListener};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use tinybox_jail::{BubblewrapBackend, JailBackend, spawn_captured_with};

#[allow(dead_code)]
mod support;

use support::*;

/// The backend when it networks privately, `None` to skip, or an error when
/// `TINYBOX_REQUIRE_PASTA=1` and it does not.
fn private() -> io::Result<Option<BubblewrapBackend>> {
    let Some(backend) = backend()? else {
        return Ok(None);
    };
    if backend.networks_privately() {
        return Ok(Some(backend));
    }
    if std::env::var_os("TINYBOX_REQUIRE_PASTA").is_some_and(|v| v == "1") {
        return Err(io::Error::other(
            "TINYBOX_REQUIRE_PASTA=1 but bwrap has no private network (install passt; \
             pasta and nsenter must be root-owned at /usr/bin)",
        ));
    }
    eprintln!("skipped: no working pasta private network");
    Ok(None)
}

#[test]
fn live_a_private_network_reaches_out_but_not_the_host() -> io::Result<()> {
    let Some(backend) = private()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let loopback = TcpListener::bind("127.0.0.1:0")?;
    let port = loopback.local_addr()?.port();
    let name = format!("tinybox-pasta-live-{}", std::process::id());
    let _abstract = UnixListener::bind_addr(&SocketAddr::from_abstract_name(name.as_bytes())?)?;
    let script = format!(
        r#"echo started
reach() {{ timeout 5 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$1" "$2" 2>/dev/null && echo "$3=reached" || echo "$3=refused"; }}
reach example.com 443 outbound
reach 127.0.0.1 {port} loopback
gw=$(ip route 2>/dev/null | awk '/default/{{print $3; exit}}')
reach "${{gw:-0.0.0.0}}" {port} gateway
python3 -c 'import socket,sys; socket.socket(socket.AF_UNIX).connect("\0"+sys.argv[1])' {name} 2>/dev/null \
  && echo abstract=reached || echo abstract=refused
# Only stdio may be open here: the holder's namespace and writer descriptors
# were closed before bwrap ran (3 is this listing's own directory handle).
echo "fds=$(cd /proc/self/fd && ls | sort -n | tr '\n' ' ')""#
    );
    let mut cmd = Command::new("/usr/bin/env");
    cmd.args(["bash", "-c", &script]);
    let (_, out) = started(&run(&backend, &jail(root.path()), cmd)?)?;
    for expected in [
        "outbound=reached",
        "loopback=refused",
        "gateway=refused",
        "abstract=refused",
    ] {
        assert!(
            out.lines().any(|line| line == expected),
            "expected {expected} in {out:?}"
        );
    }
    let fds = out
        .lines()
        .find_map(|line| line.strip_prefix("fds="))
        .ok_or_else(|| io::Error::other(format!("no fd listing in {out:?}")))?;
    assert!(
        fds.split_whitespace()
            .all(|fd| matches!(fd, "0" | "1" | "2" | "3")),
        "only stdio may be open in the jail, got {fds}"
    );
    assert!(backend.is_suitable_for_untrusted_jail(&jail(root.path())));
    done("pasta reachability", start);
    Ok(())
}

#[test]
fn live_killing_a_jail_leaves_no_pasta_behind() -> io::Result<()> {
    let Some(backend) = private()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", "echo started; sleep 30"]);
    let jail = jail(root.path());
    backend
        .require(&jail)
        .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))?;
    let mut child = spawn_captured_with(&backend, &jail, cmd)?;
    // A running jail: one killed during its startup is the next test's case.
    let mut line = String::new();
    let stdout = child
        .stdout
        .as_mut()
        .ok_or_else(|| io::Error::other("the jail's stdout was not captured"))?;
    io::BufRead::read_line(&mut io::BufReader::new(stdout), &mut line)?;
    assert_eq!(line, "started\n", "the jail never started");
    let pasta = eventually(|| pasta_of(child.id()))
        .ok_or_else(|| io::Error::other("no pasta serves the jail's network"))?;
    child.kill()?;
    child.wait()?;
    assert!(
        eventually(|| (!Path::new(&format!("/proc/{pasta}")).exists()).then_some(())).is_some(),
        "pasta {pasta} outlived the killed jail"
    );
    done("pasta after kill", start);
    Ok(())
}

#[test]
fn live_a_jail_that_exits_leaves_no_pasta_behind() -> io::Result<()> {
    let Some(backend) = private()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    // Long enough to find its pasta, then a normal exit.
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", "sleep 1"]);
    let jail = jail(root.path());
    backend
        .require(&jail)
        .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))?;
    let child = spawn_captured_with(&backend, &jail, cmd)?;
    let pasta = eventually(|| pasta_of(child.id()))
        .ok_or_else(|| io::Error::other("no pasta serves the jail's network"))?;
    assert!(child.wait_with_output()?.status.success());
    assert!(
        eventually(|| (!Path::new(&format!("/proc/{pasta}")).exists()).then_some(())).is_some(),
        "pasta {pasta} outlived the jail"
    );
    done("pasta after exit", start);
    Ok(())
}

#[test]
fn live_a_jail_killed_during_its_startup_leaves_no_jail_or_pasta_behind() -> io::Result<()> {
    let Some(backend) = private()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let jail = jail(root.path());
    backend
        .require(&jail)
        .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))?;
    // A duration no other process here will be sleeping for.
    let marker = format!("53.{}", std::process::id());
    let mut pastas = Vec::new();
    for iteration in 0..50_u64 {
        let mut cmd = Command::new("/bin/sleep");
        cmd.arg(&marker);
        let mut child = spawn_captured_with(&backend, &jail, cmd)?;
        // The network is up before the spawn returns, so its pasta is there.
        pastas.push(
            pasta_of(child.id())
                .ok_or_else(|| io::Error::other("no pasta serves the jail's network"))?,
        );
        std::thread::sleep(Duration::from_millis(iteration % 4));
        child.kill()?;
        child.wait()?;
    }
    let wanted = format!("/bin/sleep\0{marker}\0");
    let left = eventually(|| {
        let jails = std::fs::read_dir("/proc")
            .ok()?
            .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u32>().ok())
            .filter(|pid| {
                std::fs::read(format!("/proc/{pid}/cmdline"))
                    .is_ok_and(|line| line == wanted.as_bytes())
            })
            .count();
        let pastas = pastas
            .iter()
            .filter(|pasta| Path::new(&format!("/proc/{pasta}")).exists())
            .count();
        (jails == 0 && pastas == 0).then_some(())
    });
    assert!(
        left.is_some(),
        "a jail killed during its startup left its command or its pasta running"
    );
    done("pasta after a startup kill", start);
    Ok(())
}

/// Retries `check` for up to five seconds.
fn eventually<T>(mut check: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(value) = check() {
            return Some(value);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The `pasta` whose holder shares the network namespace of process `jail`.
/// Tests run in parallel, so matching by namespace keeps each to its own.
fn pasta_of(jail: u32) -> Option<u32> {
    let net = std::fs::metadata(format!("/proc/{jail}/ns/net")).ok()?;
    let own = std::fs::metadata("/proc/self/ns/net").ok()?;
    if net.ino() == own.ino() {
        return None;
    }
    std::fs::read_dir("/proc")
        .ok()?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            // On x86 with AVX2, pasta re-executes itself as `pasta.avx2`.
            std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .is_ok_and(|c| c.trim().starts_with("pasta"))
        })
        .find(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
                .ok()
                .and_then(|c| c.split_whitespace().next()?.parse::<u32>().ok())
                .and_then(|holder| std::fs::metadata(format!("/proc/{holder}/ns/net")).ok())
                .is_some_and(|holder| holder.ino() == net.ino() && holder.dev() == net.dev())
        })
}
