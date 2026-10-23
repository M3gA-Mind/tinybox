//! Tests for native Docker egress filter capability checks.

use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use tinybox_core::{BoxId, Error, ExecOutput, ExecRequest, Host, HostExecutionLocation, Result};

use super::{
    DockerEgressController, NativeLinuxDockerEgressController, NetworkNames,
    verify_created_bridge_link,
};
use crate::EgressResolver;

#[derive(Debug)]
struct FakeNativeHost {
    missing_forward_hook: &'static str,
    commands: Mutex<Vec<Vec<String>>>,
}

impl FakeNativeHost {
    fn new(missing_forward_hook: &'static str) -> Self {
        Self {
            missing_forward_hook,
            commands: Mutex::new(Vec::new()),
        }
    }

    fn commands(&self) -> Vec<Vec<String>> {
        self.commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl Host for FakeNativeHost {
    fn name(&self) -> &'static str {
        "fake-native"
    }

    fn execution_location(&self) -> HostExecutionLocation {
        HostExecutionLocation::Local
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        self.commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.argv.clone());

        let is_missing_hook = request.argv.iter().any(|part| part == "-C")
            && request.argv.iter().any(|part| part == "FORWARD")
            && request.argv.iter().any(|part| part == "DOCKER-USER")
            && request
                .argv
                .iter()
                .any(|part| part == self.missing_forward_hook);
        if request.argv.iter().any(|part| part == "docker") {
            return Ok(ExecOutput::new(
                0,
                b"linux|Ubuntu 26.04|[]".to_vec(),
                Vec::new(),
            ));
        }
        if is_missing_hook {
            return Ok(ExecOutput::new(1, Vec::new(), b"rule not found".to_vec()));
        }
        if request.argv.iter().any(|part| part == "FORWARD")
            && request.argv.iter().any(|part| part == "-S")
        {
            let firewall = if request.argv.iter().any(|part| part == "ip6tables") {
                "ip6tables"
            } else {
                "iptables"
            };
            let rules = if firewall == self.missing_forward_hook {
                "-P FORWARD DROP\n-A FORWARD -j DOCKER-FORWARD\n"
            } else {
                "-P FORWARD DROP\n-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER-FORWARD\n"
            };
            return Ok(ExecOutput::new(0, rules.as_bytes().to_vec(), Vec::new()));
        }
        Ok(ExecOutput::new(0, b"chain exists\n".to_vec(), Vec::new()))
    }
}

#[derive(Debug)]
struct Resolver;

impl EgressResolver for Resolver {
    fn resolve(&self, _hostname: &str) -> std::io::Result<Vec<IpAddr>> {
        Ok(vec![
            IpAddr::from([203, 0, 113, 8]),
            IpAddr::from([203, 0, 113, 9]),
        ])
    }
}

#[derive(Debug)]
struct BridgeLinkHost {
    exists: bool,
}

#[derive(Debug)]
struct PreparedNativeHost {
    commands: Mutex<Vec<Vec<String>>>,
    box_id: String,
    bridge: String,
    forward_chain: String,
    input_chain: String,
}

impl PreparedNativeHost {
    fn new(id: &BoxId, names: &NetworkNames) -> Self {
        Self {
            commands: Mutex::new(Vec::new()),
            box_id: id.to_string(),
            bridge: names.bridge.clone(),
            forward_chain: names.forward_chain.clone(),
            input_chain: names.input_chain.clone(),
        }
    }

    fn commands(&self) -> Vec<Vec<String>> {
        self.commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl Host for PreparedNativeHost {
    fn name(&self) -> &'static str {
        "prepared-native"
    }

    fn execution_location(&self) -> HostExecutionLocation {
        HostExecutionLocation::Local
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        let argv = &request.argv;
        self.commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(argv.clone());

        if let Some(docker_index) = argv.iter().position(|arg| arg == "docker") {
            let docker_args = &argv[docker_index + 1..];
            if docker_args.iter().any(|arg| arg == "info") {
                return Ok(ExecOutput::new(
                    0,
                    b"linux|Ubuntu 26.04|[]".to_vec(),
                    Vec::new(),
                ));
            }
            if docker_args.iter().any(|arg| arg == "network") {
                if docker_args.iter().any(|arg| arg == "create") {
                    return Ok(ExecOutput::new(0, b"network-id".to_vec(), Vec::new()));
                }
                if let Some(inspect_index) = docker_args.iter().position(|arg| arg == "inspect") {
                    let format = docker_args
                        .get(inspect_index + 2)
                        .map_or("", String::as_str);
                    let stdout = if format.contains(".Driver") {
                        format!("bridge|true|{}|{}", self.bridge, self.box_id)
                    } else {
                        self.box_id.clone()
                    };
                    return Ok(ExecOutput::new(0, stdout.into_bytes(), Vec::new()));
                }
            }
        }

        if argv.first().is_some_and(|arg| arg == "ip") {
            return Ok(ExecOutput::new(
                0,
                format!("17: {}: <BROADCAST,MULTICAST,UP>\n", self.bridge).into_bytes(),
                Vec::new(),
            ));
        }

        if argv
            .iter()
            .any(|arg| arg == "iptables" || arg == "ip6tables")
        {
            if argv.iter().any(|arg| arg == "FORWARD") {
                return Ok(ExecOutput::new(
                    0,
                    b"-P FORWARD DROP\n-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER-FORWARD\n"
                        .to_vec(),
                    Vec::new(),
                ));
            }
            if argv.iter().any(|arg| arg == "-S") {
                let chain = argv.last().map_or("", String::as_str);
                let stdout = if chain == self.forward_chain || chain == self.input_chain {
                    format!("-A {chain} -j DROP\n")
                } else {
                    String::new()
                };
                return Ok(ExecOutput::new(0, stdout.into_bytes(), Vec::new()));
            }
            return Ok(ExecOutput::new(0, Vec::new(), Vec::new()));
        }

        Ok(ExecOutput::new(0, Vec::new(), Vec::new()))
    }
}

#[async_trait]
impl Host for BridgeLinkHost {
    fn name(&self) -> &'static str {
        "bridge-link-host"
    }

    fn execution_location(&self) -> HostExecutionLocation {
        HostExecutionLocation::Local
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        let bridge = request.argv.last().map_or("", String::as_str);
        if self.exists {
            Ok(ExecOutput::new(
                0,
                format!("17: {bridge}: <BROADCAST,MULTICAST,UP>\n").into_bytes(),
                Vec::new(),
            ))
        } else {
            Ok(ExecOutput::new(1, Vec::new(), b"Device not found".to_vec()))
        }
    }
}

#[test]
fn allowlist_protocol_set_is_tcp_only() {
    assert_eq!(&super::ALLOWLIST_PROTOCOLS[..], &["tcp"]);
}

#[tokio::test]
async fn missing_local_bridge_link_refuses_enforcement() -> Result<()> {
    let names = NetworkNames::for_box("test", &BoxId::new("box-0")?);
    let host = BridgeLinkHost { exists: false };

    assert!(matches!(
        verify_created_bridge_link(&host, &names).await,
        Err(Error::ConstraintNotEnforced {
            constraint: tinybox_core::Constraint::Network,
            enforcement: tinybox_core::Enforcement::Unsupported,
            ..
        })
    ));
    Ok(())
}

#[tokio::test]
async fn existing_local_bridge_link_is_verified() -> Result<()> {
    let names = NetworkNames::for_box("test", &BoxId::new("box-0")?);
    let host = BridgeLinkHost { exists: true };

    verify_created_bridge_link(&host, &names).await
}

#[tokio::test]
async fn native_controller_prepares_and_cleans_a_pinned_allowlist() -> Result<()> {
    let id = BoxId::new("box-0")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let host = PreparedNativeHost::new(&id, &names);
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));
    let allowlist = tinybox_core::EgressAllowlist::new(["service.test"], [443]);

    let prepared = controller.prepare(&host, namespace, &id, &allowlist).await;
    assert!(
        prepared.is_ok(),
        "{prepared:?}; commands={:?}",
        host.commands()
    );
    let network = prepared?;
    assert_eq!(network.network(), names.network);
    assert_eq!(
        network.host_mappings(),
        [
            ("service.test".to_owned(), IpAddr::from([203, 0, 113, 8])),
            ("service.test".to_owned(), IpAddr::from([203, 0, 113, 9])),
        ]
    );
    controller.cleanup(&host, namespace, &id).await?;

    let commands = host.commands();
    assert!(commands.iter().any(|argv| {
        argv.iter().any(|arg| arg == "-A")
            && argv.iter().any(|arg| arg == "203.0.113.8")
            && argv.iter().any(|arg| arg == "443")
            && argv.iter().any(|arg| arg == "tcp")
            && argv.iter().any(|arg| arg == "ACCEPT")
    }));
    assert!(commands.iter().any(|argv| {
        argv.iter().any(|arg| arg == "DROP") && argv.iter().any(|arg| arg == &names.input_chain)
    }));
    assert!(commands.iter().any(|argv| {
        argv.iter().any(|arg| arg == "-D") && argv.iter().any(|arg| arg == "DOCKER-USER")
    }));
    assert!(commands.iter().any(|argv| {
        argv.iter().any(|arg| arg == "rm") && argv.iter().any(|arg| arg == &names.network)
    }));
    assert!(
        commands
            .iter()
            .filter(|argv| argv.iter().any(|arg| arg == "docker"))
            .all(|argv| {
                argv.first().is_some_and(|arg| arg == "env")
                    && argv.iter().any(|arg| arg == "unix:///var/run/docker.sock")
            })
    );
    Ok(())
}

#[tokio::test]
async fn missing_forward_hook_refuses_native_egress_before_resource_creation() {
    for firewall in ["iptables", "ip6tables"] {
        let host = FakeNativeHost::new(firewall);
        let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));

        assert!(matches!(
            controller.validate_host(&host).await,
            Err(Error::ConstraintNotEnforced {
                constraint: tinybox_core::Constraint::Network,
                enforcement: tinybox_core::Enforcement::Unsupported,
                ..
            })
        ));
        assert!(
            host.commands()
                .iter()
                .all(|argv| !argv.contains(&"create".to_owned()))
        );
    }
}
