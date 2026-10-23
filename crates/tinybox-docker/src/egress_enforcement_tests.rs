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
        Ok(vec![IpAddr::from([203, 0, 113, 8])])
    }
}

#[derive(Debug)]
struct BridgeLinkHost {
    exists: bool,
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
