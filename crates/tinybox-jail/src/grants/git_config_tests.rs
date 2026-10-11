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
