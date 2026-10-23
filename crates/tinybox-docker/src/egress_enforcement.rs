//! Per-box Docker network filtering for explicitly supported native Linux hosts.
//!
//! The controller installs a host firewall before Docker starts the box. It
//! consumes pinned resolver answers and does not use proxy environment
//! variables as an enforcement boundary.

use std::{fmt::Debug, net::IpAddr, sync::Arc};

use async_trait::async_trait;
use tinybox_core::{
    BoxId, EgressAllowlist, Error, ExecOutput, ExecRequest, Host, HostExecutionLocation, Result,
};

use crate::{EgressResolver, PinnedEgressPlan, plan_egress_allowlist};

const DOCKER_SOCKET: &str = "unix:///var/run/docker.sock";
const OWNER_LABEL: &str = "ai.tinyhumans.tinybox.egress.owner";

/// A controller that installs and removes a per-box egress filter.
///
/// Implementations are trusted security components. A controller must verify
/// that it acts on the same daemon and host that run the box, install a
/// default-drop filter before returning from [`prepare`](Self::prepare), and
/// make [`cleanup`](Self::cleanup) idempotent. DockerSandbox uses
/// [`docker_argv`](Self::docker_argv) for every Docker command while the
/// controller is installed, so lifecycle operations address the same daemon.
#[async_trait]
pub trait DockerEgressController: Debug + Send + Sync {
    /// Verify the execution location and required daemon/filter capability.
    async fn validate_host(&self, _host: &dyn Host) -> Result<()> {
        Ok(())
    }

    /// Resolve, pin, and prepare a filtered network for this box.
    ///
    /// Implementations must not start the workload. The returned network name
    /// is supplied to `docker run` only after this method succeeds.
    async fn prepare(
        &self,
        host: &dyn Host,
        namespace: &str,
        id: &BoxId,
        allowlist: &EgressAllowlist,
    ) -> Result<String>;

    /// Remove this box's filter and network after its container has stopped.
    async fn cleanup(&self, host: &dyn Host, namespace: &str, id: &BoxId) -> Result<()>;

    /// Bind a Docker CLI command to the daemon this controller verifies.
    fn docker_argv(&self, argv: Vec<String>) -> Vec<String>;
}

/// Native Linux Engine support using the local rootful Docker socket and
/// `iptables`/`ip6tables` `DOCKER-USER` chains.
///
/// The default [`DockerSandbox`](crate::DockerSandbox) has no controller and
/// continues to refuse allowlists. Install this controller explicitly only on
/// a local native Linux Docker Engine with non-interactive firewall privilege.
/// Docker Desktop, SSH/remote hosts, rootless Docker, Windows containers, and
/// hosts without the expected firewall chains are refused.
#[derive(Debug)]
pub struct NativeLinuxDockerEgressController {
    resolver: Arc<dyn EgressResolver>,
}

impl NativeLinuxDockerEgressController {
    /// Use `resolver` to resolve allowlist names before network creation.
    #[must_use]
    pub fn new(resolver: Arc<dyn EgressResolver>) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl DockerEgressController for NativeLinuxDockerEgressController {
    async fn validate_host(&self, host: &dyn Host) -> Result<()> {
        ensure_supported_host(host)?;
        ensure_linux_target()?;
        verify_engine_and_firewall(host).await
    }

    async fn prepare(
        &self,
        host: &dyn Host,
        namespace: &str,
        id: &BoxId,
        allowlist: &EgressAllowlist,
    ) -> Result<String> {
        ensure_supported_host(host)?;
        ensure_linux_target()?;
        verify_engine_and_firewall(host).await?;

        // Resolve before creating any Docker resources. Every installed rule is
        // based on this one pinned answer set; workload DNS is not trusted for
        // egress decisions.
        let plan = plan_egress_allowlist(allowlist, self.resolver.as_ref())?;
        let names = NetworkNames::for_box(namespace, id);
        let network = docker_success(
            host,
            vec![
                "docker".into(),
                "network".into(),
                "create".into(),
                "--driver".into(),
                "bridge".into(),
                "--ipv6".into(),
                "--opt".into(),
                format!("com.docker.network.bridge.name={}", names.bridge),
                "--label".into(),
                format!("{OWNER_LABEL}={id}"),
                names.network.clone(),
            ],
        )
        .await?;
        if network.is_empty() {
            return Err(unsupported("Docker did not confirm the egress network"));
        }

        let setup = async {
            verify_created_network(host, &names, id).await?;
            install_firewall(host, &names, &plan).await
        }
        .await;
        if let Err(error) = setup {
            let cleanup = cleanup_native(host, namespace, id, true).await;
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(Error::Backend {
                    sandbox: "docker".to_owned(),
                    operation: "roll back egress network setup",
                    message: format!("{error}; cleanup failed: {cleanup_error}"),
                }),
            };
        }

        Ok(names.network)
    }

    async fn cleanup(&self, host: &dyn Host, namespace: &str, id: &BoxId) -> Result<()> {
        ensure_supported_host(host)?;
        ensure_linux_target()?;
        verify_engine_and_firewall(host).await?;
        cleanup_native(host, namespace, id, false).await
    }

    fn docker_argv(&self, argv: Vec<String>) -> Vec<String> {
        force_local_rootful_docker(argv)
    }
}

#[derive(Debug)]
struct NetworkNames {
    network: String,
    bridge: String,
    forward_chain: String,
    input_chain: String,
}

impl NetworkNames {
    fn for_box(namespace: &str, id: &BoxId) -> Self {
        let hash = stable_hash(namespace.as_bytes(), id.as_str().as_bytes());
        let short = format!("{hash:016x}");
        Self {
            network: format!("tinybox-egress-{}", &short[..12]),
            // Linux interface names are limited to IFNAMSIZ - 1 (15 bytes).
            bridge: format!("tbx{}", &short[..12]),
            forward_chain: format!("TBX{}F", &short[..10]),
            input_chain: format!("TBX{}I", &short[..10]),
        }
    }
}

fn stable_hash(namespace: &[u8], id: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in namespace.iter().chain([0].iter()).chain(id) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn ensure_supported_host(host: &dyn Host) -> Result<()> {
    if host.execution_location() != HostExecutionLocation::Local {
        return Err(unsupported(
            "egress filtering requires an explicitly local execution host",
        ));
    }
    Ok(())
}

fn ensure_linux_target() -> Result<()> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err(unsupported(
            "native Docker egress filtering is available only on Linux",
        ))
    }
}

fn unsupported(reason: &str) -> Error {
    let _ = reason;
    Error::ConstraintNotEnforced {
        sandbox: "docker".to_owned(),
        constraint: tinybox_core::Constraint::Network,
        enforcement: tinybox_core::Enforcement::Unsupported,
    }
}

async fn verify_engine_and_firewall(host: &dyn Host) -> Result<()> {
    ensure_supported_host(host)?;
    ensure_linux_target()?;

    let info = docker_output(
        host,
        vec![
            "docker".into(),
            "info".into(),
            "--format".into(),
            "{{.OSType}}|{{.OperatingSystem}}|{{json .SecurityOptions}}".into(),
        ],
    )
    .await?;
    let mut fields = info.splitn(3, '|');
    let os_type = fields.next().unwrap_or_default().trim();
    let operating_system = fields.next().unwrap_or_default().trim();
    let security = fields.next().unwrap_or_default().to_ascii_lowercase();
    if os_type != "linux"
        || operating_system.is_empty()
        || operating_system.to_ascii_lowercase().contains("desktop")
        || security.contains("rootless")
    {
        return Err(unsupported(
            "Docker daemon is not a native rootful Linux Engine",
        ));
    }

    for firewall in ["iptables", "ip6tables"] {
        for chain in ["DOCKER-USER", "INPUT"] {
            let output = host
                .run(&ExecRequest::new([
                    "sudo", "-n", firewall, "-w", "5", "-S", chain,
                ]))
                .await?;
            if !output.succeeded() {
                return Err(unsupported("required root firewall chains are unavailable"));
            }
        }
    }
    Ok(())
}

async fn verify_created_network(host: &dyn Host, names: &NetworkNames, id: &BoxId) -> Result<()> {
    let output = docker_output(
        host,
        vec![
            "docker".into(),
            "network".into(),
            "inspect".into(),
            "--format".into(),
            "{{.Driver}}|{{.EnableIPv6}}|{{index .Options \"com.docker.network.bridge.name\"}}|{{index .Labels \"ai.tinyhumans.tinybox.egress.owner\"}}".into(),
            names.network.clone(),
        ],
    )
    .await?;
    let expected = format!("bridge|true|{}|{id}", names.bridge);
    if output != expected {
        return Err(unsupported(
            "Docker egress network did not match its verified configuration",
        ));
    }
    Ok(())
}

async fn install_firewall(
    host: &dyn Host,
    names: &NetworkNames,
    plan: &PinnedEgressPlan,
) -> Result<()> {
    install_family(host, "iptables", names, plan, false).await?;
    install_family(host, "ip6tables", names, plan, true).await?;
    verify_hook(
        host,
        "iptables",
        "DOCKER-USER",
        &names.bridge,
        &names.forward_chain,
    )
    .await?;
    verify_hook(host, "iptables", "INPUT", &names.bridge, &names.input_chain).await?;
    verify_hook(
        host,
        "ip6tables",
        "DOCKER-USER",
        &names.bridge,
        &names.forward_chain,
    )
    .await?;
    verify_hook(
        host,
        "ip6tables",
        "INPUT",
        &names.bridge,
        &names.input_chain,
    )
    .await?;
    Ok(())
}

async fn install_family(
    host: &dyn Host,
    firewall: &str,
    names: &NetworkNames,
    plan: &PinnedEgressPlan,
    ipv6: bool,
) -> Result<()> {
    let existing = firewall_output(host, firewall, ["-S"]).await?;
    if existing.contains(&names.forward_chain) || existing.contains(&names.input_chain) {
        return Err(unsupported("a stale egress firewall chain already exists"));
    }

    for chain in [&names.forward_chain, &names.input_chain] {
        firewall_success(host, firewall, ["-N", chain]).await?;
    }
    for rule in deny_rules(ipv6) {
        let mut command = vec!["-A".to_owned(), names.forward_chain.clone()];
        command.extend(rule);
        firewall_success(host, firewall, command.iter().map(String::as_str)).await?;
    }
    for target in plan.targets() {
        let address = target.address();
        if is_ipv6(&address) != ipv6 {
            continue;
        }
        for protocol in ["tcp", "udp"] {
            firewall_success(
                host,
                firewall,
                [
                    "-A",
                    &names.forward_chain,
                    "-d",
                    &address.to_string(),
                    "-p",
                    protocol,
                    "--dport",
                    &target.port().to_string(),
                    "-j",
                    "ACCEPT",
                ],
            )
            .await?;
        }
    }
    firewall_success(host, firewall, ["-A", &names.forward_chain, "-j", "DROP"]).await?;
    // Host-origin traffic from the managed bridge is categorically denied.
    // Allowlist entries apply only to routed container egress.
    firewall_success(host, firewall, ["-A", &names.input_chain, "-j", "DROP"]).await?;

    firewall_success(
        host,
        firewall,
        [
            "-I",
            "DOCKER-USER",
            "1",
            "-i",
            &names.bridge,
            "-j",
            &names.forward_chain,
        ],
    )
    .await?;
    firewall_success(
        host,
        firewall,
        [
            "-I",
            "INPUT",
            "1",
            "-i",
            &names.bridge,
            "-j",
            &names.input_chain,
        ],
    )
    .await?;

    // Confirm both custom chains contain the final drop before allowing Docker
    // to attach an image entrypoint to the network.
    for chain in [&names.forward_chain, &names.input_chain] {
        let rules = firewall_output(host, firewall, ["-S", chain]).await?;
        if !rules.lines().any(|line| line.ends_with("-j DROP")) {
            return Err(unsupported("default-drop egress rules were not verified"));
        }
    }
    Ok(())
}

fn deny_rules(ipv6: bool) -> Vec<Vec<String>> {
    if ipv6 {
        ["::1/128", "fe80::/10", "fd00:ec2::254/128"]
            .into_iter()
            .map(|prefix| vec!["-d".into(), prefix.into(), "-j".into(), "DROP".into()])
            .collect()
    } else {
        ["127.0.0.0/8", "169.254.0.0/16", "100.100.100.200/32"]
            .into_iter()
            .map(|prefix| vec!["-d".into(), prefix.into(), "-j".into(), "DROP".into()])
            .collect()
    }
}

fn is_ipv6(address: &IpAddr) -> bool {
    matches!(address, IpAddr::V6(_))
}

async fn verify_hook(
    host: &dyn Host,
    firewall: &str,
    parent: &str,
    bridge: &str,
    chain: &str,
) -> Result<()> {
    firewall_success(host, firewall, ["-C", parent, "-i", bridge, "-j", chain]).await
}

async fn cleanup_native(
    host: &dyn Host,
    namespace: &str,
    id: &BoxId,
    network_known_owned: bool,
) -> Result<()> {
    let names = NetworkNames::for_box(namespace, id);
    for firewall in ["iptables", "ip6tables"] {
        for (parent, chain) in [
            ("DOCKER-USER", names.forward_chain.as_str()),
            ("INPUT", names.input_chain.as_str()),
        ] {
            let hook = host
                .run(&ExecRequest::new([
                    "sudo",
                    "-n",
                    firewall,
                    "-w",
                    "5",
                    "-C",
                    parent,
                    "-i",
                    &names.bridge,
                    "-j",
                    chain,
                ]))
                .await?;
            if hook.succeeded() {
                firewall_success(
                    host,
                    firewall,
                    ["-D", parent, "-i", &names.bridge, "-j", chain],
                )
                .await?;
            }
            let rules = firewall_output(host, firewall, ["-S"]).await?;
            if rules.lines().any(|line| line.contains(chain)) {
                firewall_success(host, firewall, ["-F", chain]).await?;
                firewall_success(host, firewall, ["-X", chain]).await?;
            }
            let remaining = firewall_output(host, firewall, ["-S"]).await?;
            if remaining.lines().any(|line| line.contains(chain)) {
                return Err(unsupported(
                    "egress firewall chain cleanup was not verified",
                ));
            }
        }
    }

    let inspect = docker_request(
        host,
        vec![
            "docker".into(),
            "network".into(),
            "inspect".into(),
            "--format".into(),
            format!("{{{{index .Labels \"{OWNER_LABEL}\"}}}}"),
            names.network.clone(),
        ],
    )
    .await?;
    if inspect.succeeded() {
        let owner = inspect.stdout_lossy().trim().to_owned();
        if !network_known_owned && owner != id.as_str() {
            return Err(unsupported(
                "egress network ownership could not be verified",
            ));
        }
        docker_success(
            host,
            vec![
                "docker".into(),
                "network".into(),
                "rm".into(),
                names.network,
            ],
        )
        .await?;
    } else if !inspect.stderr_lossy().contains("No such network")
        && !inspect.stderr_lossy().contains("not found")
    {
        return Err(unsupported("egress network cleanup could not be verified"));
    }
    Ok(())
}

async fn firewall_output<const N: usize>(
    host: &dyn Host,
    firewall: &str,
    arguments: [&str; N],
) -> Result<String> {
    let mut argv = vec!["sudo", "-n", firewall, "-w", "5"];
    argv.extend(arguments);
    let output = host.run(&ExecRequest::new(argv)).await?;
    if !output.succeeded() {
        return Err(unsupported("required firewall command failed"));
    }
    Ok(output.stdout_lossy().into_owned())
}

async fn firewall_success<I, S>(host: &dyn Host, firewall: &str, arguments: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut argv = vec![
        "sudo".to_owned(),
        "-n".to_owned(),
        firewall.to_owned(),
        "-w".to_owned(),
        "5".to_owned(),
    ];
    argv.extend(
        arguments
            .into_iter()
            .map(|argument| argument.as_ref().to_owned()),
    );
    let output = host.run(&ExecRequest::new(argv)).await?;
    if !output.succeeded() {
        return Err(unsupported("required firewall command failed"));
    }
    Ok(())
}

async fn docker_output(host: &dyn Host, argv: Vec<String>) -> Result<String> {
    let output = docker_request(host, force_local_rootful_docker(argv)).await?;
    if !output.succeeded() {
        return Err(unsupported(
            "Docker daemon identity or configuration could not be verified",
        ));
    }
    Ok(output.stdout_lossy().trim().to_owned())
}

async fn docker_success(host: &dyn Host, argv: Vec<String>) -> Result<String> {
    let output = docker_request(host, force_local_rootful_docker(argv)).await?;
    if !output.succeeded() {
        return Err(Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "configure egress filtering",
            message: output.stderr_lossy().trim().to_owned(),
        });
    }
    Ok(output.stdout_lossy().trim().to_owned())
}

async fn docker_request(host: &dyn Host, argv: Vec<String>) -> Result<ExecOutput> {
    host.run(&ExecRequest::new(argv)).await
}

fn force_local_rootful_docker(argv: Vec<String>) -> Vec<String> {
    if argv.first().is_some_and(|program| program == "env") {
        return argv;
    }
    let mut forced = vec![
        "env".into(),
        "-u".into(),
        "DOCKER_HOST".into(),
        "-u".into(),
        "DOCKER_CONTEXT".into(),
        "-u".into(),
        "DOCKER_TLS_VERIFY".into(),
        "-u".into(),
        "DOCKER_CERT_PATH".into(),
        "docker".into(),
        "--host".into(),
        DOCKER_SOCKET.into(),
    ];
    forced.extend(argv.into_iter().skip(1));
    forced
}
