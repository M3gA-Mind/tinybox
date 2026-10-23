//! Tests that drive a real Docker daemon.
//!
//! Gated behind `TINYBOX_LIVE_DOCKER=1` and named `live_*` so an ordinary
//! `cargo test` skips them: they need a daemon, pull images, and are far slower
//! than the unit suite. Everything about argument construction is covered
//! without a daemon in `src/sandbox/test.rs`; what is here is what only a real
//! daemon can answer.
//!
//! The isolation tests assert **negatively** — that the box *cannot* see the
//! host — because a positive assertion would pass just as happily against a
//! sandbox that confines nothing.
//!
//! Run them with:
//!
//! ```sh
//! TINYBOX_LIVE_DOCKER=1 cargo test -p tinybox-docker --test live_docker
//! ```
//!
//! CI also sets `TINYBOX_REQUIRE_LIVE_DOCKER=1`; in that mode the focused
//! connectivity test fails if the opt-in gate was not enabled.

use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    process::Command,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use tinybox_core::{
    BoxSpec, Error, ExecRequest, Host as _, HostRef, MemoryStore, NetworkPolicy, Placement, Result,
    Sandbox, SandboxRef, WorkspaceSource,
};
use tinybox_docker::DockerSandbox;
use tinybox_host::LocalHost;

/// The image every live test uses. Small, and it ships a shell.
const IMAGE: &str = "alpine:3";

/// Whether the live suite should run at all.
fn enabled() -> bool {
    std::env::var_os("TINYBOX_LIVE_DOCKER").is_some()
}

fn live_docker_enabled() -> Result<bool> {
    let enabled = enabled();
    if std::env::var_os("TINYBOX_REQUIRE_LIVE_DOCKER").is_some() && !enabled {
        return Err(Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "run required live network test",
            message: "TINYBOX_REQUIRE_LIVE_DOCKER is set but TINYBOX_LIVE_DOCKER is not enabled"
                .to_owned(),
        });
    }
    Ok(enabled)
}

fn docker_bridge_gateway() -> Result<Ipv4Addr> {
    let output = Command::new("docker")
        .args([
            "network",
            "inspect",
            "bridge",
            "--format",
            "{{(index .IPAM.Config 0).Gateway}}",
        ])
        .output()
        .map_err(|error| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "inspect the default bridge gateway",
            message: error.to_string(),
        })?;
    if !output.status.success() {
        return Err(Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "inspect the default bridge gateway",
            message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .map_err(|error| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "parse the default bridge gateway",
            message: format!(
                "{}: {error}",
                String::from_utf8_lossy(&output.stdout).trim()
            ),
        })
}

fn accept_before(listener: &TcpListener, deadline: Instant) -> std::io::Result<TcpStream> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "timed out waiting for the Docker network probe",
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn http_probe_command(address: SocketAddr) -> String {
    format!("wget -q -T 3 -O - http://{address}/probe")
}

fn prove_host_can_reach_listener(listener: &TcpListener, address: SocketAddr) -> Result<()> {
    let host = TcpStream::connect_timeout(&address, Duration::from_secs(3)).map_err(|error| {
        Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "connect the host positive control",
            message: error.to_string(),
        }
    })?;
    let _accepted_host =
        accept_before(listener, Instant::now() + Duration::from_secs(3)).map_err(|error| {
            Error::Backend {
                sandbox: "docker".to_owned(),
                operation: "accept the host positive control",
                message: error.to_string(),
            }
        })?;
    drop(host);
    Ok(())
}

/// A sandbox in its own namespace.
///
/// Every test allocates `box-0` from a fresh store, so without a per-test
/// namespace they would all fight over one container name on the daemon — which
/// is exactly the collision the namespace exists to prevent.
fn sandbox(namespace: &str) -> Result<DockerSandbox> {
    DockerSandbox::with_namespace(
        Arc::new(LocalHost::new()),
        Arc::new(MemoryStore::new()),
        namespace,
    )
}

fn spec_from(source: WorkspaceSource) -> Result<BoxSpec> {
    Ok(BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new("docker")?),
        source,
    ))
}

fn spec() -> Result<BoxSpec> {
    spec_from(WorkspaceSource::OciImage(IMAGE.to_owned()))
}

/// Run `argv` in a box and return its trimmed standard output.
async fn output_of(
    sandbox: &DockerSandbox,
    id: &tinybox_core::BoxId,
    argv: &[&str],
) -> Result<String> {
    let output = sandbox.exec(id, &ExecRequest::new(argv.to_vec())).await?;
    Ok(output.stdout_lossy().trim().to_owned())
}

#[tokio::test]
async fn live_a_box_runs_a_command_in_a_real_container() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-abraciarc")?;
    let info = sandbox.create(&spec()?).await?;

    let result = output_of(&sandbox, &info.id, &["echo", "from-the-container"]).await;

    sandbox.destroy(&info.id).await?;
    assert_eq!(result?, "from-the-container");
    Ok(())
}

#[tokio::test]
async fn live_the_box_cannot_see_host_processes() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-tbcshp")?;
    let info = sandbox.create(&spec()?).await?;

    let result = output_of(
        &sandbox,
        &info.id,
        &["sh", "-c", "ls /proc | grep -c '^[0-9]*$'"],
    )
    .await;

    sandbox.destroy(&info.id).await?;

    // The host has hundreds of processes. A PID-namespaced container sees only
    // its own handful, so a large count here means the isolation is not real.
    let visible: usize = result?.parse().unwrap_or(usize::MAX);
    assert!(
        visible < 20,
        "expected a private process table, saw {visible} processes"
    );
    Ok(())
}

#[tokio::test]
async fn live_the_box_has_its_own_root_filesystem() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-tbhiorf")?;
    let info = sandbox.create(&spec()?).await?;

    // A file that exists on the host checkout must not be visible inside.
    let result = output_of(
        &sandbox,
        &info.id,
        &[
            "sh",
            "-c",
            "test -e /etc/alpine-release && echo alpine; test -e /home/enamakel && echo LEAKED",
        ],
    )
    .await;

    sandbox.destroy(&info.id).await?;
    let seen = result?;
    assert!(seen.contains("alpine"));
    assert!(!seen.contains("LEAKED"), "the host filesystem was visible");
    Ok(())
}

#[tokio::test]
async fn live_a_denied_network_really_is_denied() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-adnrid")?;
    let info = sandbox.create(&spec()?).await?;

    // With `--network none` the container has only a loopback interface.
    let result = output_of(&sandbox, &info.id, &["sh", "-c", "ip -o link | wc -l"]).await;

    sandbox.destroy(&info.id).await?;
    let interfaces: usize = result?.parse().unwrap_or(usize::MAX);
    assert_eq!(interfaces, 1, "expected loopback only");
    Ok(())
}

#[tokio::test]
async fn live_egress_is_available_when_the_policy_allows_it() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-eiawtpai")?;
    let info = sandbox
        .create(&spec()?.with_network(NetworkPolicy::Egress))
        .await?;

    let result = output_of(&sandbox, &info.id, &["sh", "-c", "ip -o link | wc -l"]).await;

    sandbox.destroy(&info.id).await?;
    let interfaces: usize = result?.parse().unwrap_or(0);
    assert!(interfaces > 1, "expected more than loopback");
    Ok(())
}

#[tokio::test]
async fn live_network_policy_controls_host_listener_connectivity() -> Result<()> {
    if !live_docker_enabled()? {
        return Ok(());
    }

    let gateway = docker_bridge_gateway()?;
    let listener = TcpListener::bind((gateway, 0)).map_err(|error| Error::Backend {
        sandbox: "docker".to_owned(),
        operation: "bind the controlled bridge-gateway listener",
        message: error.to_string(),
    })?;
    listener
        .set_nonblocking(true)
        .map_err(|error| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "configure the controlled listener",
            message: error.to_string(),
        })?;
    let address = listener.local_addr().map_err(|error| Error::Backend {
        sandbox: "docker".to_owned(),
        operation: "read the controlled listener address",
        message: error.to_string(),
    })?;

    // Prove the local endpoint is reachable before it is used as a sandbox
    // policy probe.
    prove_host_can_reach_listener(&listener, address)?;

    let egress_sandbox = sandbox("ns-docker-network-egress")?;
    let egress_info = egress_sandbox
        .create(&spec()?.with_network(NetworkPolicy::Egress))
        .await?;
    let egress_listener = listener.try_clone().map_err(|error| Error::Backend {
        sandbox: "docker".to_owned(),
        operation: "clone the controlled listener",
        message: error.to_string(),
    })?;
    let egress_server = thread::spawn(move || -> std::io::Result<()> {
        let mut stream = accept_before(&egress_listener, Instant::now() + Duration::from_secs(5))?;
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request)?;
        stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\ndocker-ok",
        )
    });
    let egress_result = egress_sandbox
        .exec(
            &egress_info.id,
            &ExecRequest::new(["sh", "-c", &http_probe_command(address)]),
        )
        .await;
    let egress_server_result = egress_server.join().map_err(|_| Error::Backend {
        sandbox: "docker".to_owned(),
        operation: "join the Egress listener",
        message: "listener thread panicked".to_owned(),
    })?;
    let egress_destroy = egress_sandbox.destroy(&egress_info.id).await;
    egress_server_result.map_err(|error| Error::Backend {
        sandbox: "docker".to_owned(),
        operation: "accept the Egress container connection",
        message: error.to_string(),
    })?;
    let egress = egress_result?;
    egress_destroy?;
    assert_eq!(
        egress.exit_code,
        0,
        "Egress container could not reach the listener: {}",
        egress.stderr_lossy()
    );
    assert_eq!(egress.stdout_lossy().trim(), "docker-ok");

    let denied_sandbox = sandbox("ns-docker-network-denied")?;
    let denied_info = denied_sandbox.create(&spec()?).await?;
    let denied = denied_sandbox
        .exec(
            &denied_info.id,
            &ExecRequest::new(["sh", "-c", &http_probe_command(address)]),
        )
        .await;
    let no_denied_connection = matches!(
        accept_before(&listener, Instant::now() + Duration::from_millis(250)),
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut
    );
    let denied_destroy = denied_sandbox.destroy(&denied_info.id).await;
    let denied = denied?;
    denied_destroy?;
    assert_ne!(
        denied.exit_code, 0,
        "default-Denied container unexpectedly fetched the local response"
    );
    assert!(
        no_denied_connection,
        "default-Denied container established a connection to the controlled listener"
    );
    Ok(())
}

#[tokio::test]
async fn live_a_memory_limit_is_actually_enforced() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-amliae")?;
    let spec = spec()?.with_resources(tinybox_core::Resources {
        memory_bytes: 64 * 1024 * 1024,
        ..tinybox_core::Resources::DEFAULT
    });
    let info = sandbox.create(&spec).await?;

    // Reading `memory.max` would only prove the cgroup was *configured*, and an
    // earlier version of this test did exactly that. So this allocates for
    // real. The allocation is anonymous memory held by the shell rather than a
    // file write: a write to `/tmp` measures disk in Docker and memory under
    // namespaces, which made an earlier probe silently test nothing at all.
    let over = output_of(
        &sandbox,
        &info.id,
        &["sh", "-c", "x=$(yes a | head -c 100000000); echo SURVIVED"],
    )
    .await;

    // ...and a modest allocation under the same cap still works, so this is
    // measuring a limit rather than a broken container.
    let under = output_of(
        &sandbox,
        &info.id,
        &["sh", "-c", "x=$(yes a | head -c 8000000); echo ok"],
    )
    .await;

    sandbox.destroy(&info.id).await?;
    assert!(
        !over?.contains("SURVIVED"),
        "a 100 MiB allocation was not stopped by a 64 MiB cap"
    );
    assert_eq!(under?, "ok");
    Ok(())
}

#[tokio::test]
async fn live_a_local_directory_is_visible_inside_the_box() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let dir = tempfile::tempdir().map_err(|error| Error::io("tempdir", &error))?;
    std::fs::write(dir.path().join("note.txt"), "mounted\n")
        .map_err(|error| Error::io("write", &error))?;

    let sandbox = sandbox("ns-localdir")?;
    let info = sandbox
        .create(&spec_from(WorkspaceSource::LocalDir(dir.path().into()))?)
        .await?;

    // The bind mount is also the working directory, so a bare filename resolves.
    let result = output_of(&sandbox, &info.id, &["cat", "note.txt"]).await;

    sandbox.destroy(&info.id).await?;
    assert_eq!(result?, "mounted");
    Ok(())
}

#[tokio::test]
async fn live_a_snapshot_captures_a_write_and_a_fork_starts_from_it() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-ascawaafsfi")?;
    let parent = sandbox.create(&spec()?).await?;

    // Write into the parent, then capture it.
    sandbox
        .exec(
            &parent.id,
            &ExecRequest::new(["sh", "-c", "echo captured > /marker"]),
        )
        .await?;
    let snapshot = sandbox.snapshot(&parent.id).await?;

    let forked = sandbox.fork(&snapshot, &spec()?).await?;

    // The fork inherits the parent's filesystem...
    let inherited = output_of(&sandbox, &forked.id, &["cat", "/marker"]).await;

    // ...and writes in the fork do not reach back into the parent.
    sandbox
        .exec(
            &forked.id,
            &ExecRequest::new(["sh", "-c", "echo fork-only > /fork-marker"]),
        )
        .await?;
    let parent_sees_fork = output_of(
        &sandbox,
        &parent.id,
        &[
            "sh",
            "-c",
            "test -e /fork-marker && echo LEAKED || echo isolated",
        ],
    )
    .await;

    sandbox.destroy(&forked.id).await?;
    sandbox.destroy(&parent.id).await?;

    assert_eq!(inherited?, "captured");
    assert_eq!(parent_sees_fork?, "isolated");
    Ok(())
}

#[tokio::test]
async fn live_a_destroyed_box_leaves_no_container_behind() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-adblncb")?;
    let info = sandbox.create(&spec()?).await?;
    let name = tinybox_docker::container_name(sandbox.namespace(), &info.id);

    sandbox.destroy(&info.id).await?;

    let listed = LocalHost::new()
        .run(&ExecRequest::new([
            "docker",
            "ps",
            "--all",
            "--quiet",
            "--filter",
            &format!("name=^{name}$"),
        ]))
        .await?;

    assert!(
        listed.stdout_lossy().trim().is_empty(),
        "container {name} survived destroy"
    );
    Ok(())
}

#[tokio::test]
async fn live_a_missing_image_is_reported_with_dockers_diagnostic() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-amiirwdd")?;

    let outcome = sandbox
        .create(&spec_from(WorkspaceSource::OciImage(
            "tinybox.invalid/no-such-image:0".to_owned(),
        ))?)
        .await;

    assert!(matches!(
        outcome,
        Err(Error::Backend {
            operation: "create the container",
            ..
        })
    ));
    Ok(())
}
