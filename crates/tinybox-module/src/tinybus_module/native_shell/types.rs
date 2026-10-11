//! Retained native collector and scratch ownership.
use tinybox_bus::ShellExecRequest;
pub(in crate::tinybus_module) struct ShellContext {
    pub(super) request: ShellExecRequest,
    pub(super) environment: std::collections::BTreeMap<String, String>,
    pub(super) _scratch: tempfile::TempDir,
    pub(super) host: ShellHost,
}
pub(super) enum ShellHost {
    Local(tinybox_host::LimitedLocalHost),
    Jailed(tinybox_host::JailLocalHost),
}
