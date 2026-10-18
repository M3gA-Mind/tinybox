//! Tests for the `bwrap` argument builder.

use super::*;

fn strings(argv: &[OsString]) -> Vec<String> {
    argv.iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

fn has_triple(argv: &[String], kind: &str, path: &Path) -> bool {
    let p = path.display().to_string();
    argv.windows(3)
        .any(|w| w[0] == kind && w[1] == p && w[2] == p)
}

fn jail(root: &Path) -> Jail {
    Jail::new(root, "bwrap-test")
}

#[test]
fn namespaces_and_lifetime_flags_are_always_present() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let argv = strings(&jail_args(&jail(root.path()), None)?);
    for flag in [
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--new-session",
    ] {
        assert!(argv.iter().any(|a| a == flag), "missing {flag}");
    }
    Ok(())
}

#[test]
fn network_is_unshared_only_when_denied() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let open = strings(&jail_args(&jail(root.path()), None)?);
    assert!(!open.iter().any(|a| a == "--unshare-net"));
    let closed = strings(&jail_args(&jail(root.path()).deny_net(), None)?);
    assert!(closed.iter().any(|a| a == "--unshare-net"));
    Ok(())
}

#[test]
fn grants_become_bind_mounts_at_their_own_paths() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let ro = tempfile::tempdir()?;
    let rw = tempfile::tempdir()?;
    let j = jail(root.path())
        .add_read_only(ro.path())
        .add_read_write(rw.path());
    let argv = strings(&jail_args(&j, None)?);
    assert!(has_triple(&argv, "--bind", root.path()));
    assert!(has_triple(&argv, "--bind", rw.path()));
    assert!(has_triple(&argv, "--ro-bind-try", ro.path()));
    assert!(!has_triple(&argv, "--bind", ro.path()));
    Ok(())
}

#[test]
fn ungranted_paths_and_whole_etc_are_never_mounted() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let other = tempfile::tempdir()?;
    let argv = strings(&jail_args(&jail(root.path()), None)?);
    assert!(
        !argv
            .iter()
            .any(|a| *a == other.path().display().to_string())
    );
    assert!(!has_triple(&argv, "--ro-bind-try", Path::new("/etc")));
    assert!(!has_triple(&argv, "--ro-bind", Path::new("/")));
    Ok(())
}

#[test]
fn deny_read_inside_a_grant_is_masked() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let secret_dir = root.path().join("secrets");
    std::fs::create_dir(&secret_dir)?;
    let secret_file = root.path().join("token");
    std::fs::write(&secret_file, "x")?;
    let mut j = jail(root.path());
    j.deny_read = vec![secret_dir.clone(), secret_file.clone()];
    let argv = strings(&jail_args(&j, None)?);
    let dir = secret_dir.display().to_string();
    let file = secret_file.display().to_string();
    assert!(argv.windows(2).any(|w| w[0] == "--tmpfs" && w[1] == dir));
    assert!(
        argv.windows(3)
            .any(|w| w[0] == "--ro-bind" && w[1] == "/dev/null" && w[2] == file)
    );
    // The masks come after the bind they carve out of.
    let bind_at = argv.iter().position(|a| a == "--bind");
    let mask_at = argv.iter().position(|a| *a == dir);
    assert!(bind_at < mask_at);
    Ok(())
}

#[test]
fn deny_read_over_a_grant_drops_the_grant() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let ro = tempfile::tempdir()?;
    let mut j = jail(root.path()).add_read_only(ro.path());
    j.deny_read = vec![ro.path().to_path_buf()];
    let argv = strings(&jail_args(&j, None)?);
    assert!(!argv.iter().any(|a| *a == ro.path().display().to_string()));
    Ok(())
}

#[test]
fn missing_root_or_read_write_grant_is_not_found() {
    let missing = jail(Path::new("/nonexistent/tinybox-jail-root"));
    let err = jail_args(&missing, None).err().map(|e| e.kind());
    assert_eq!(err, Some(io::ErrorKind::NotFound));
}

#[test]
fn chdir_defaults_to_root_and_honours_the_command_cwd() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let sub = root.path().join("sub");
    let default = strings(&jail_args(&jail(root.path()), None)?);
    let root_s = root.path().display().to_string();
    assert!(
        default
            .windows(2)
            .any(|w| w[0] == "--chdir" && w[1] == root_s)
    );
    let custom = strings(&jail_args(&jail(root.path()), Some(&sub))?);
    let sub_s = sub.display().to_string();
    assert!(
        custom
            .windows(2)
            .any(|w| w[0] == "--chdir" && w[1] == sub_s)
    );
    Ok(())
}
