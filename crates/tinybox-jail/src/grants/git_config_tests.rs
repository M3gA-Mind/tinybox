//! Git include decoding and malformed-value rejection coverage.
use super::*;

#[test]
fn include_values_decode_git_escapes_and_preserve_quoted_whitespace() {
    assert_eq!(
        include_value(r##"  " a\n\t\b\\\"#; " # comment"##),
        Some(" a\n\t\u{0008}\\\"#; ".into())
    );
    assert_eq!(include_value("  safe  ; comment"), Some("safe".into()));
    assert_eq!(include_value(r#"a""b"#), Some("ab".into()));
}

#[test]
fn malformed_or_empty_include_values_are_not_granted() {
    for value in [
        "",
        " # comment",
        "; comment",
        "\"\"",
        "\"unterminated",
        "\\",
        r"\q",
    ] {
        assert_eq!(include_value(value), None, "{value}");
    }
}

#[test]
fn empty_xdg_config_home_is_unset_in_git_root_selection() {
    assert_eq!(xdg_root(Some(std::ffi::OsStr::new(""))), None);
    assert_eq!(xdg_root(None), None);
    assert_eq!(
        xdg_root(Some(std::ffi::OsStr::new("config-root"))),
        Some(Path::new("config-root"))
    );
}
