//! Tests for native Docker egress filter capability checks.

use std::{
    fmt::Write as _,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use tinybox_core::{BoxId, Error, ExecOutput, ExecRequest, Host, HostExecutionLocation, Result};

use super::{
    DockerEgressController, NativeLinuxDockerEgressController, NetworkNames, deny_rules,
    scope_token, verify_created_bridge_link,
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
struct MappedIpv4Resolver;

impl EgressResolver for MappedIpv4Resolver {
    fn resolve(&self, _hostname: &str) -> std::io::Result<Vec<IpAddr>> {
        Ok(vec!["::ffff:203.0.113.11".parse().map_err(|error| {
            std::io::Error::other(format!("invalid fixture: {error}"))
        })?])
    }
}

#[derive(Debug)]
struct BridgeLinkHost {
    exists: bool,
}

#[derive(Debug)]
struct PreparedNativeHost {
    commands: Mutex<Vec<Vec<String>>>,
    chains: Mutex<std::collections::BTreeSet<(String, String)>>,
    marked_chains: Mutex<std::collections::BTreeSet<(String, String)>>,
    fail_network_create: bool,
    empty_network_create: bool,
    fail_chain_marker: bool,
    network_owner: String,
    network_scope: String,
    chain_owner_token: String,
    bridge: String,
    forward_chain: String,
    input_chain: String,
}

impl PreparedNativeHost {
    fn new(id: &BoxId, names: &NetworkNames) -> Self {
        Self {
            commands: Mutex::new(Vec::new()),
            chains: Mutex::new(std::collections::BTreeSet::new()),
            marked_chains: Mutex::new(std::collections::BTreeSet::new()),
            fail_network_create: false,
            empty_network_create: false,
            fail_chain_marker: false,
            network_owner: id.to_string(),
            network_scope: names.owner_token.clone(),
            chain_owner_token: names.owner_token.clone(),
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
#[allow(clippy::too_many_lines)] // The fake host models the firewall and Docker command surface.
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
                    if self.fail_network_create {
                        return Ok(ExecOutput::new(
                            1,
                            Vec::new(),
                            b"network name already exists".to_vec(),
                        ));
                    }
                    let network_id = if self.empty_network_create {
                        Vec::new()
                    } else {
                        b"network-id".to_vec()
                    };
                    return Ok(ExecOutput::new(0, network_id, Vec::new()));
                }
                if let Some(inspect_index) = docker_args.iter().position(|arg| arg == "inspect") {
                    let format = docker_args
                        .get(inspect_index + 2)
                        .map_or("", String::as_str);
                    let stdout = if format.contains(".Driver") {
                        format!(
                            "bridge|true|{}|{}|{}",
                            self.bridge, self.network_owner, self.network_scope
                        )
                    } else {
                        format!("{}|{}", self.network_owner, self.network_scope)
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
            if let Some(index) = argv.iter().position(|arg| arg == "-N")
                && let Some(chain) = argv.get(index + 1)
            {
                let firewall = argv
                    .iter()
                    .find(|arg| matches!(arg.as_str(), "iptables" | "ip6tables"))
                    .cloned()
                    .unwrap_or_default();
                self.chains
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert((firewall, chain.clone()));
            }
            if let Some(index) = argv.iter().position(|arg| arg == "-X")
                && let Some(chain) = argv.get(index + 1)
            {
                let firewall = argv
                    .iter()
                    .find(|arg| matches!(arg.as_str(), "iptables" | "ip6tables"))
                    .cloned()
                    .unwrap_or_default();
                self.chains
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&(firewall.clone(), chain.clone()));
                self.marked_chains
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&(firewall, chain.clone()));
            }
            if self.fail_chain_marker
                && argv
                    .windows(2)
                    .any(|args| args == ["--comment", &self.chain_owner_token])
            {
                return Ok(ExecOutput::new(
                    1,
                    Vec::new(),
                    b"injected owner marker failure".to_vec(),
                ));
            }
            if argv.iter().any(|arg| arg == "--comment")
                && let Some(index) = argv.iter().position(|arg| arg == "-A")
                && let Some(chain) = argv.get(index + 1)
            {
                let firewall = argv
                    .iter()
                    .find(|arg| matches!(arg.as_str(), "iptables" | "ip6tables"))
                    .cloned()
                    .unwrap_or_default();
                self.marked_chains
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert((firewall, chain.clone()));
            }
            if argv.iter().any(|arg| arg == "FORWARD") {
                return Ok(ExecOutput::new(
                    0,
                    b"-P FORWARD DROP\n-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER-FORWARD\n"
                        .to_vec(),
                    Vec::new(),
                ));
            }
            if argv.iter().any(|arg| arg == "-S") {
                let firewall = argv
                    .iter()
                    .find(|arg| matches!(arg.as_str(), "iptables" | "ip6tables"))
                    .cloned()
                    .unwrap_or_default();
                let chains = self
                    .chains
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let marked_chains = self
                    .marked_chains
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let stdout = [&self.forward_chain, &self.input_chain]
                    .into_iter()
                    .filter(|chain| chains.contains(&(firewall.clone(), (*chain).clone())))
                    .fold(String::new(), |mut stdout, chain| {
                        let _ = writeln!(stdout, "-N {chain}");
                        if marked_chains.contains(&(firewall.clone(), chain.clone())) {
                            let _ = writeln!(
                                stdout,
                                "-A {chain} -s 0.0.0.0/32 -m comment --comment {} -j DROP",
                                self.chain_owner_token
                            );
                        }
                        let _ = writeln!(stdout, "-A {chain} -j DROP");
                        stdout
                    });
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
    let established_position = commands
        .iter()
        .position(|argv| {
            argv.windows(2)
                .any(|args| args == ["--ctstate", "ESTABLISHED,RELATED"])
        })
        .ok_or_else(|| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "find established-flow firewall rule",
            message: "rule was not installed".to_owned(),
        })?;
    let forward_drop_position = commands
        .iter()
        .position(|argv| {
            argv.windows(4)
                .any(|args| args == ["-A", &names.forward_chain, "-j", "DROP"])
        })
        .ok_or_else(|| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "find forward default-drop rule",
            message: "rule was not installed".to_owned(),
        })?;
    assert!(established_position < forward_drop_position);
    assert_input_return_rules(&commands, &names)?;
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

fn assert_input_return_rules(commands: &[Vec<String>], names: &NetworkNames) -> Result<()> {
    let input_established_position = commands
        .iter()
        .position(|argv| {
            argv.iter().any(|arg| arg == "iptables")
                && argv
                    .windows(4)
                    .any(|args| args == ["-A", &names.input_chain, "-m", "conntrack"])
                && argv
                    .windows(2)
                    .any(|args| args == ["--ctstate", "ESTABLISHED,RELATED"])
        })
        .ok_or_else(|| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "find established INPUT return rule",
            message: "rule was not installed".to_owned(),
        })?;
    let ipv4_input_drop_position = commands
        .iter()
        .position(|argv| {
            argv.iter().any(|arg| arg == "iptables")
                && argv
                    .windows(4)
                    .any(|args| args == ["-A", &names.input_chain, "-j", "DROP"])
        })
        .ok_or_else(|| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "find IPv4 INPUT default-drop rule",
            message: "rule was not installed".to_owned(),
        })?;
    assert!(input_established_position < ipv4_input_drop_position);
    let neighbor_solicitation_position = commands
        .iter()
        .position(|argv| {
            argv.iter().any(|arg| arg == "ip6tables")
                && argv.iter().any(|arg| arg == "neighbor-solicitation")
        })
        .ok_or_else(|| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "find IPv6 neighbor-discovery rule",
            message: "rule was not installed".to_owned(),
        })?;
    let input_drop_position = commands
        .iter()
        .position(|argv| {
            argv.iter().any(|arg| arg == "ip6tables")
                && argv
                    .windows(4)
                    .any(|args| args == ["-A", &names.input_chain, "-j", "DROP"])
        })
        .ok_or_else(|| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "find INPUT default-drop rule",
            message: "rule was not installed".to_owned(),
        })?;
    let ipv6_input_established_position = commands
        .iter()
        .position(|argv| {
            argv.iter().any(|arg| arg == "ip6tables")
                && argv
                    .windows(4)
                    .any(|args| args == ["-A", &names.input_chain, "-m", "conntrack"])
                && argv
                    .windows(2)
                    .any(|args| args == ["--ctstate", "ESTABLISHED,RELATED"])
        })
        .ok_or_else(|| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "find IPv6 established INPUT return rule",
            message: "rule was not installed".to_owned(),
        })?;
    assert!(neighbor_solicitation_position < ipv6_input_established_position);
    assert!(ipv6_input_established_position < input_drop_position);
    Ok(())
}

#[tokio::test]
async fn native_controller_maps_ipv4_mapped_answers_as_ipv4() -> Result<()> {
    let id = BoxId::new("box-mapped")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let host = PreparedNativeHost::new(&id, &names);
    let controller = NativeLinuxDockerEgressController::new(Arc::new(MappedIpv4Resolver));
    let allowlist = tinybox_core::EgressAllowlist::new(["service.test"], [443]);

    let prepared = controller
        .prepare(&host, namespace, &id, &allowlist)
        .await?;

    assert_eq!(
        prepared.host_mappings(),
        [("service.test".to_owned(), IpAddr::from([203, 0, 113, 11]))]
    );
    let commands = host.commands();
    assert!(commands.iter().any(|argv| {
        argv.iter().any(|part| part == "iptables")
            && argv.iter().any(|part| part == "203.0.113.11")
            && argv.iter().any(|part| part == "ACCEPT")
    }));
    assert!(!commands.iter().any(|argv| {
        argv.iter().any(|part| part == "ip6tables")
            && argv.iter().any(|part| part.contains("203.0.113.11"))
    }));
    controller.cleanup(&host, namespace, &id).await?;
    Ok(())
}

#[tokio::test]
async fn cleanup_refuses_a_different_network_owner_before_firewall_mutation() -> Result<()> {
    let id = BoxId::new("box-foreign-owner")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.network_owner = "another-box".to_owned();
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));

    assert!(controller.cleanup(&host, namespace, &id).await.is_err());

    assert!(!host.commands().iter().any(|argv| {
        argv.iter()
            .any(|part| part == "iptables" || part == "ip6tables")
            && argv
                .iter()
                .any(|part| part == "-D" || part == "-F" || part == "-X")
    }));
    Ok(())
}

#[tokio::test]
async fn cleanup_refuses_a_network_scope_hash_collision_before_firewall_mutation() -> Result<()> {
    let id = BoxId::new("box-scope-collision")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.network_scope = "different-full-hash".to_owned();
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));

    assert!(controller.cleanup(&host, namespace, &id).await.is_err());

    assert!(!host.commands().iter().any(|argv| {
        argv.iter()
            .any(|part| part == "iptables" || part == "ip6tables")
            && argv
                .iter()
                .any(|part| part == "-D" || part == "-F" || part == "-X")
    }));
    Ok(())
}

#[tokio::test]
async fn cleanup_refuses_firewall_chains_with_another_owner_marker() -> Result<()> {
    let id = BoxId::new("box-chain-collision")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.chain_owner_token = "different-full-hash".to_owned();
    host.chains
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .extend([
            ("iptables".to_owned(), names.forward_chain.clone()),
            ("iptables".to_owned(), names.input_chain.clone()),
        ]);
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));

    assert!(controller.cleanup(&host, namespace, &id).await.is_err());

    assert!(!host.commands().iter().any(|argv| {
        argv.iter()
            .any(|part| part == "iptables" || part == "ip6tables")
            && argv
                .iter()
                .any(|part| part == "-D" || part == "-F" || part == "-X")
    }));
    Ok(())
}

#[test]
fn deny_rules_block_metadata_without_disabling_other_link_local_destinations() {
    let ipv4 = deny_rules(false);
    let ipv6 = deny_rules(true);
    let has_destination = |rules: &[Vec<String>], destination: &str| {
        rules
            .iter()
            .any(|rule| rule.windows(2).any(|pair| pair == ["-d", destination]))
    };

    assert!(has_destination(&ipv4, "169.254.169.254/32"));
    assert!(has_destination(&ipv4, "169.254.170.2/32"));
    assert!(!has_destination(&ipv4, "169.254.0.0/16"));
    assert!(has_destination(&ipv6, "fd00:ec2::254/128"));
    assert!(!has_destination(&ipv6, "fe80::/10"));
}

#[test]
fn firewall_owner_token_uses_unambiguous_sha256_identity() {
    let left = scope_token("ab", "c");
    let right = scope_token("a", "bc");

    assert_eq!(left.len(), 64);
    assert_ne!(left, right);
    assert_eq!(left, scope_token("ab", "c"));
}

#[tokio::test]
async fn network_name_conflict_does_not_clean_an_existing_owners_firewall() -> Result<()> {
    let id = BoxId::new("box-0")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.fail_network_create = true;
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));
    let allowlist = tinybox_core::EgressAllowlist::new(["service.test"], [443]);

    assert!(matches!(
        controller.prepare(&host, namespace, &id, &allowlist).await,
        Err(Error::Backend {
            operation: "configure egress filtering",
            ..
        })
    ));
    assert!(host.commands().iter().all(|argv| {
        !argv
            .iter()
            .any(|arg| matches!(arg.as_str(), "-D" | "-F" | "-X"))
    }));
    Ok(())
}

#[tokio::test]
async fn empty_successful_network_create_rolls_back_the_owned_network() -> Result<()> {
    let id = BoxId::new("box-0")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.empty_network_create = true;
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));
    let allowlist = tinybox_core::EgressAllowlist::new(["service.test"], [443]);

    assert!(matches!(
        controller.prepare(&host, namespace, &id, &allowlist).await,
        Err(Error::ConstraintNotEnforced {
            enforcement: tinybox_core::Enforcement::Unsupported,
            ..
        })
    ));
    assert!(host.commands().iter().any(|argv| {
        argv.iter().any(|arg| arg == "rm") && argv.iter().any(|arg| arg == &names.network)
    }));
    Ok(())
}

#[tokio::test]
async fn marker_install_failure_rolls_back_only_the_created_chain_and_network() -> Result<()> {
    let id = BoxId::new("box-marker-failure")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.fail_chain_marker = true;
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));
    let allowlist = tinybox_core::EgressAllowlist::new(["service.test"], [443]);

    let result = controller.prepare(&host, namespace, &id, &allowlist).await;

    assert!(result.is_err());
    let commands = host.commands();
    assert!(commands.iter().any(|argv| {
        argv.iter().any(|arg| arg == "-X") && argv.iter().any(|arg| arg == &names.forward_chain)
    }));
    assert!(commands.iter().any(|argv| {
        argv.iter().any(|arg| arg == "rm") && argv.iter().any(|arg| arg == &names.network)
    }));
    assert!(host
        .chains
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_empty());
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
