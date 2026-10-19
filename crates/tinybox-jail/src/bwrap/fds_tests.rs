//! Tests for inherited-descriptor handling.

use super::*;

#[test]
fn cloexec_is_read_from_the_octal_flags_line() {
    assert!(has_cloexec("pos:\t0\nflags:\t02100002\nmnt_id:\t1\n"));
    assert!(!has_cloexec("pos:\t0\nflags:\t0100002\nmnt_id:\t1\n"));
    assert!(!has_cloexec("garbage"));
}

#[test]
fn script_closes_each_leaked_descriptor_then_execs() {
    assert_eq!(
        closing_script(&[3, 142]),
        "exec 3>&- 142>&- ; exec \"$0\" \"$@\""
    );
}

#[test]
fn low_descriptors_use_sh_and_high_ones_need_bash() -> io::Result<()> {
    assert_eq!(shell_for(&[3, 9], |_| false)?, "/bin/sh");
    assert_eq!(shell_for(&[3, 142], |p| p == "/bin/bash")?, "/bin/bash");
    assert_eq!(
        shell_for(&[142], |p| p == "/usr/bin/bash")?,
        "/usr/bin/bash"
    );
    Ok(())
}

#[test]
fn a_high_descriptor_without_bash_fails_closed() {
    let kind = shell_for(&[3, 142], |_| false).err().map(|e| e.kind());
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
