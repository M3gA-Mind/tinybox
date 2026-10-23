//! Tests for native Docker egress filter capability checks.

use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use tinybox_core::{Error, ExecOutput, ExecRequest, Host, HostExecutionLocation, Result};

use super::{DockerEgressController, NativeLinuxDockerEgressController};
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
    fn name(&self) -> &str {
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
        Ok(ExecOutput::new(0, b"chain exists\n".to_vec(), Vec::new()))
    }
}

#[derive(Debug)]
struct Resolver;

impl EgressResolver for Resolver {
    fn resolve(&self, _hostname: &str) -> std::io::Result<Vec<IpAddr>> {
        Ok(vec!["203.0.113.8".parse().expect("test IP is valid")])
    }
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
