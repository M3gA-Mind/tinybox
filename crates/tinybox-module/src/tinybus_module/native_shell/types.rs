//! Retained native collector and scratch ownership.
use tinybox_bus::ShellExecRequest;
pub(in crate::tinybus_module) struct ShellContext {
    pub(super) request: ShellExecRequest,
    pub(super) environment: std::collections::BTreeMap<String, String>,
    pub(super) scratch: std::sync::Mutex<Option<tempfile::TempDir>>,
    pub(super) scratch_cleanup_failed: std::sync::atomic::AtomicBool,
    pub(super) host: ShellHost,
}
pub(super) enum ShellHost {
    Local(tinybox_host::LimitedLocalHost),
    Jailed(tinybox_host::JailLocalHost),
}
