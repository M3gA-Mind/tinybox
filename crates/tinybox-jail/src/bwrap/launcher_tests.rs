//! Tests for the launcher; no `bwrap` needed, a stand-in script plays it.

use super::*;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::PermissionsExt as _;

fn stand_in(dir: &Path, body: &str) -> io::Result<PathBuf> {
    let path = dir.join("fake-bwrap");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    Ok(path)
}

fn run(shell: &str, body: &str, args: &[&str]) -> io::Result<String> {
    let dir = tempfile::tempdir()?;
    let bwrap = stand_in(dir.path(), body)?;
    let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
    let file = ArgsFile::create(&argv)?;
    let out = command(shell, &bwrap, &file).output()?;
    file.discard();
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn shell_prefers_bash_and_falls_back_to_sh() {
    assert_eq!(pick_shell(|p| p == "/bin/bash"), "/bin/bash");
    assert_eq!(pick_shell(|p| p == "/usr/bin/bash"), "/usr/bin/bash");
    assert_eq!(pick_shell(|_| false), "/bin/sh");
}

#[test]
fn the_args_file_is_private_nul_separated_and_never_reused() -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let file = ArgsFile::create(&["--setenv".into(), "TOKEN".into(), "s3cret".into()])?;
    assert_eq!(std::fs::read(file.path())?, b"--setenv\0TOKEN\0s3cret\0");
    assert_eq!(std::fs::metadata(file.path())?.mode() & 0o777, 0o600);
    let dir = file
        .path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    assert_eq!(std::fs::metadata(&dir)?.mode() & 0o777, 0o700);
    let other = ArgsFile::create(&[])?;
    assert_ne!(other.path(), file.path());
    file.discard();
    other.discard();
    assert!(!dir.exists());
    Ok(())
}

#[test]
fn the_launcher_hands_bwrap_the_args_on_fd_9_and_deletes_the_file() -> io::Result<()> {
    let out = run(
        "/bin/sh",
        r#"[ "$1" = "--args" ] && [ "$2" = "9" ] || exit 3
cat <&9 | tr '\0' ','"#,
        &["--a", "value with space", "--b"],
    )?;
    assert_eq!(out, "--a,value with space,--b,");
    Ok(())
}

#[test]
fn the_args_file_is_gone_once_the_launcher_has_started_bwrap() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let bwrap = stand_in(dir.path(), "exit 0")?;
    let file = ArgsFile::create(&["x".into()])?;
    let path = file.path().to_path_buf();
    assert!(command("/bin/sh", &bwrap, &file).status()?.success());
    assert!(!path.exists() && !path.parent().is_some_and(Path::exists));
    Ok(())
}

#[test]
fn the_launcher_runs_with_an_empty_environment() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let bwrap = stand_in(dir.path(), "env")?;
    let file = ArgsFile::create(&[])?;
    let out = command("/bin/sh", &bwrap, &file).output()?;
    file.discard();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("HOME=") && !text.contains("LD_PRELOAD"),
        "{text}"
    );
    Ok(())
}

#[test]
fn inheritable_descriptors_are_closed_by_both_shells_including_high_numbers() -> io::Result<()> {
    let secret = tempfile::NamedTempFile::new()?;
    // Enough open files that some descriptors are above 9.
    let mut files = Vec::new();
    for _ in 0..12 {
        let file = std::fs::File::open(secret.path())?;
        rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::empty())?;
        files.push(file);
    }
    let fds: Vec<i32> = files.iter().map(AsRawFd::as_raw_fd).collect();
    assert!(fds.iter().any(|fd| *fd > 9), "{fds:?}");
    let list = "ls /proc/self/fd | tr '\\n' ' '";
    let shells: Vec<&str> = ["/bin/bash", "/usr/bin/bash"]
        .into_iter()
        .filter(|p| Path::new(p).is_file())
        .collect();
    for shell in shells {
        let out = run(shell, list, &[])?;
        for fd in &fds {
            let token = format!("{fd} ");
            assert!(
                !out.split_whitespace().any(|f| f == token.trim()),
                "{shell}: fd {fd} survived: {out}"
            );
        }
    }
    Ok(())
}

#[test]
fn a_missing_proc_fd_directory_would_fail_closed_by_construction() {
    assert!(SCRIPT.starts_with("[ -d /proc/self/fd ] || exit 126"));
    assert!(SCRIPT.contains(r#"exec "$0" --args 9"#));
}
