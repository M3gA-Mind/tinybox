//! Native jail vocabulary is serialized independently of implementation types.
use super::*;

#[test]
fn native_jail_request_keeps_explicit_enforcement_and_grants() -> Result<(), serde_json::Error> {
    let value = serde_json::json!({
        "read_only": ["/usr"], "read_write": [], "allow_net": true,
        "allow_subprocess": false, "enforcement": "enforced",
        "require_process_isolation": true,
    });
    let config: NativeJailConfig = serde_json::from_value(value.clone())?;
    assert_eq!(config.enforcement, JailEnforcement::Enforced);
    assert_eq!(serde_json::to_value(config)?, value);
    assert_eq!(serde_json::to_value(JailEnforcement::Declared)?, "declared");
    assert!(
        serde_json::from_value::<NativeJailConfig>(serde_json::json!({"read_only": []})).is_err()
    );
    Ok(())
}
