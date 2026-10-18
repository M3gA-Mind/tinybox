//! Tests for inherited-descriptor handling.

use super::*;

#[test]
fn cloexec_is_read_from_the_octal_flags_line() {
    assert!(has_cloexec("pos:\t0\nflags:\t02100002\nmnt_id:\t1\n"));
    assert!(!has_cloexec("pos:\t0\nflags:\t0100002\nmnt_id:\t1\n"));
    assert!(!has_cloexec("garbage"));
}

#[test]
fn script_closes_each_leaked_descriptor_then_execs() -> io::Result<()> {
    assert_eq!(
        closing_script(&[3, 5])?,
        "exec 3>&- 5>&- ; exec \"$0\" \"$@\""
    );
    Ok(())
}

#[test]
fn a_descriptor_the_shell_cannot_close_fails_closed() {
    let kind = closing_script(&[3, 12]).err().map(|e| e.kind());
    assert_eq!(kind, Some(io::ErrorKind::InvalidInput));
}

#[test]
fn files_opened_by_std_are_close_on_exec_so_never_leaked() -> io::Result<()> {
    let file = std::fs::File::open("/proc/self/status")?;
    let mine = {
        use std::os::fd::AsRawFd;
        file.as_raw_fd()
    };
    assert!(!leaked_fds()?.contains(&mine));
    Ok(())
}
