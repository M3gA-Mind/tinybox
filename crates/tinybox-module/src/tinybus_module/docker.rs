//! Module-owned one-shot Docker execution.

use std::path::PathBuf;
use std::time::Duration;

use tinybox_bus::{DockerRunOutput, DockerRunRequest};
use tinybox_docker::{DockerCli, OneShot};
use tinybus::{Error, Result};

/// Run a bounded Docker command using the local Docker CLI.
pub(super) async fn run(request: DockerRunRequest) -> Result<DockerRunOutput> {
    run_with_cli(&DockerCli::new(), request).await
}

async fn run_with_cli(cli: &DockerCli, request: DockerRunRequest) -> Result<DockerRunOutput> {
    validate(&request)?;

    let mut spec = OneShot::new(&request.workspace, &request.command);
    if let Some(image) = &request.image {
        spec = spec.with_image(image);
    }
    if let Some(network) = &request.network {
        spec = spec.with_network(network);
    }
    if let Some(memory) = request.memory_limit_mb {
        spec = spec.with_memory_mb(memory);
    }
    if let Some(cpus) = request.cpus {
        spec = spec.with_cpus(cpus);
    }
    if let Some(read_only) = request.read_only_rootfs {
        spec = spec.with_read_only_rootfs(read_only);
    }
    spec = spec
        .with_read_only_mounts(request.read_only_mounts.iter().map(PathBuf::from))
        .with_extra_cap_drops(request.extra_cap_drops.clone())
        .with_env(
            request
                .env
                .into_iter()
                .map(|(key, value)| (key.into(), value.into())),
        );
    if let Some(label) = request.label {
        spec = spec.with_label(label);
    }

    let outcome = cli
        .run_one_shot(&spec, Duration::from_millis(request.timeout_ms))
        .await
        .map_err(|_| failure("Docker client could not be started"))?;
    Ok(DockerRunOutput {
        exit_code: outcome.exit_code,
        stdout: outcome.stdout,
        stderr: outcome.stderr,
        timed_out: outcome.timed_out,
    })
}

fn validate(request: &DockerRunRequest) -> Result<()> {
    if request.timeout_ms > tinybox_bus::MAX_DOCKER_RUN_TIMEOUT_MS {
        return Err(failure("Docker run request is invalid"));
    }
    Ok(())
}

fn failure(message: &str) -> Error {
    Error::MethodFailed {
        name: tinybox_bus::INVALID_DOCKER_RUN.into(),
        message: message.into(),
    }
}

#[cfg(all(test, unix))]
#[path = "docker_tests.rs"]
mod tests;
