//! Tests for resolver-backed egress allowlist planning.

use super::*;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Mutex;

use tinybox_core::{EgressAllowlist, Error};

#[derive(Debug)]
struct ChangingResolver {
    calls: Mutex<Vec<String>>,
}

impl EgressResolver for ChangingResolver {
    fn resolve(&self, hostname: &str) -> std::io::Result<Vec<IpAddr>> {
        let mut calls = self
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        calls.push(hostname.to_owned());
        if calls.len() == 1 {
            Ok(vec!["203.0.113.8".parse().map_err(|error| {
                std::io::Error::other(format!("invalid fixture: {error}"))
            })?])
        } else {
            Ok(vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)])
        }
    }
}

#[derive(Debug)]
struct StaticResolver(BTreeMap<String, Vec<IpAddr>>);

impl EgressResolver for StaticResolver {
    fn resolve(&self, hostname: &str) -> std::io::Result<Vec<IpAddr>> {
        self.0.get(hostname).cloned().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no fixture for {hostname}"),
            )
        })
    }
}

fn addresses(
    host: &str,
    answers: &[&str],
) -> std::result::Result<StaticResolver, Box<dyn std::error::Error>> {
    let addresses = answers
        .iter()
        .map(|answer| answer.parse::<IpAddr>())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(StaticResolver(BTreeMap::from([(
        host.to_owned(),
        addresses,
    )])))
}

#[test]
fn resolves_each_distinct_hostname_once_and_retains_the_answer() -> tinybox_core::Result<()> {
    let resolver = ChangingResolver {
        calls: Mutex::new(Vec::new()),
    };
    let allowlist = EgressAllowlist::new(["API.Example.Test.", "api.example.test."], [443, 8443]);

    let plan = plan_egress_allowlist(&allowlist, &resolver)?;

    assert_eq!(
        resolver
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_slice(),
        ["api.example.test."]
    );
    assert_eq!(plan.targets().len(), 2);
    assert!(plan.targets().iter().all(|target| {
        target.host() == "api.example.test."
            && target.address() == IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 8))
    }));
    assert_eq!(
        plan.targets()[0].socket_addr().ip(),
        plan.targets()[0].address()
    );
    Ok(())
}

#[derive(Debug)]
struct AbsoluteAwareResolver {
    calls: Mutex<Vec<String>>,
}

impl EgressResolver for AbsoluteAwareResolver {
    fn resolve(&self, hostname: &str) -> std::io::Result<Vec<IpAddr>> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(hostname.to_owned());
        let answer = match hostname {
            "service." => "203.0.113.17",
            "service" => "203.0.113.23",
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no fixture for {hostname}"),
                ));
            }
        };
        Ok(vec![answer.parse().map_err(|error| {
            std::io::Error::other(format!("invalid fixture: {error}"))
        })?])
    }
}

#[test]
fn resolves_absolute_names_with_the_root_dot_and_keeps_them_distinct() -> tinybox_core::Result<()> {
    let resolver = AbsoluteAwareResolver {
        calls: Mutex::new(Vec::new()),
    };
    let allowlist = EgressAllowlist::new(["Service.", "SERVICE.", "service"], [443]);

    let plan = plan_egress_allowlist(&allowlist, &resolver)?;

    assert_eq!(
        resolver
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_slice(),
        ["service.", "service"]
    );
    assert_eq!(plan.targets().len(), 2);
    assert_eq!(plan.targets()[0].host(), "service");
    assert_eq!(
        plan.targets()[0].address(),
        IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 23))
    );
    assert_eq!(plan.targets()[1].host(), "service.");
    assert_eq!(
        plan.targets()[1].address(),
        IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 17))
    );
    Ok(())
}

#[test]
fn rejects_a_plan_if_any_answer_is_loopback_or_metadata()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for (hostname, answer) in [
        ("loopback-v4.example", "127.0.0.1"),
        ("loopback-v6.example", "::1"),
        ("mapped-loopback.example", "::ffff:127.0.0.1"),
        ("aws-metadata.example", "169.254.169.254"),
        ("alibaba-metadata.example", "100.100.100.200"),
        ("mapped-alibaba-metadata.example", "::ffff:100.100.100.200"),
        ("ec2-metadata.example", "fd00:ec2::254"),
    ] {
        let resolver = addresses(hostname, &[answer])?;
        let allowlist = EgressAllowlist::new([hostname], [443]);
        assert!(
            matches!(
                plan_egress_allowlist(&allowlist, &resolver),
                Err(Error::InvalidNetworkPolicy { .. })
            ),
            "{hostname} resolving to {answer} must reject the entire plan"
        );
    }
    Ok(())
}

#[test]
fn rejects_mixed_safe_and_forbidden_answers_instead_of_dropping_one()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let resolver = addresses("mixed.example", &["203.0.113.8", "127.0.0.1"])?;
    let allowlist = EgressAllowlist::new(["mixed.example"], [443]);

    assert!(matches!(
        plan_egress_allowlist(&allowlist, &resolver),
        Err(Error::InvalidNetworkPolicy { .. })
    ));
    Ok(())
}

#[test]
fn allows_private_addresses_when_the_policy_does_not_forbid_them()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let resolver = addresses("private.example", &["10.2.3.4"])?;
    let allowlist = EgressAllowlist::new(["private.example"], [443]);

    let plan = plan_egress_allowlist(&allowlist, &resolver)?;

    assert_eq!(plan.targets().len(), 1);
    assert_eq!(plan.targets()[0].address(), "10.2.3.4".parse::<IpAddr>()?);
    Ok(())
}

#[test]
fn rejects_a_hostname_with_no_resolver_answers()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let resolver = addresses("empty.example", &[])?;
    let allowlist = EgressAllowlist::new(["empty.example"], [443]);

    assert!(matches!(
        plan_egress_allowlist(&allowlist, &resolver),
        Err(Error::InvalidNetworkPolicy { .. })
    ));
    Ok(())
}
