//! Toolchain grant discovery and protected-path regression coverage.
use super::*;
use std::fs;
use std::path::{Path, PathBuf};

fn fake_home() -> std::io::Result<tempfile::TempDir> {
    let home = tempfile::tempdir()?;
    for d in [
        ".ssh", ".gnupg", ".aws", ".cargo", ".rustup", ".nvm", ".npm",
    ] {
        fs::create_dir_all(home.path().join(d))?;
    }
    Ok(home)
}

fn canon(p: &Path) -> std::io::Result<PathBuf> {
    p.canonicalize()
}

fn has(grants: &[PathBuf], p: &Path) -> bool {
    grants.iter().any(|g| g == p)
}

fn all(g: &JailGrants) -> Vec<PathBuf> {
    g.read_only.iter().chain(&g.read_write).cloned().collect()
}

/// A grant reaches a credential store if it IS one, is inside one, or contains
/// one (Landlock grants are recursive, so a parent grant exposes the child).
fn reaches_credentials(grants: &[PathBuf], home: &Path) -> Option<PathBuf> {
    for cred in [".ssh", ".gnupg", ".aws"] {
        let cred = home.join(cred);
        for g in grants {
            if g.starts_with(&cred) || cred.starts_with(g) {
                return Some(g.clone());
            }
        }
    }
    None
}

#[test]
fn credential_dirs_are_never_granted_by_default() -> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    let g = resolve(Some(home.path()), &LocalGrantConfig::default());
    assert_eq!(reaches_credentials(&all(&g), home.path()), None);
    Ok(())
}

#[test]
fn credential_dirs_are_never_granted_even_when_extras_ask() -> Result<(), Box<dyn std::error::Error>>
{
    let home = fake_home()?;
    let cfg = LocalGrantConfig {
        extra_read_only: vec![
            "~/.ssh".into(),
            "~/.gnupg/".into(),
            format!("{}", home.path().join(".aws").display()),
            "~".into(),
            format!("{}", home.path().display()),
            "/".into(),
        ],
        extra_read_write: vec!["~/.ssh".into(), "~".into()],
        ..LocalGrantConfig::default()
    };
    let g = resolve(Some(home.path()), &cfg);
    assert_eq!(reaches_credentials(&all(&g), home.path()), None);
    assert!(!g.read_only.iter().any(|p| p == Path::new("/")));
    Ok(())
}

#[test]
#[cfg(unix)]
fn credential_floor_holds_for_a_symlink_into_a_credential_dir()
-> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    std::os::unix::fs::symlink(home.path().join(".ssh"), home.path().join("innocent"))?;
    let cfg = LocalGrantConfig {
        extra_read_only: vec!["~/innocent".into()],
        ..LocalGrantConfig::default()
    };
    let g = resolve(Some(home.path()), &cfg);
    assert_eq!(reaches_credentials(&all(&g), home.path()), None);
    Ok(())
}

#[test]
fn toolchain_homes_are_granted_when_they_exist() -> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    let cargo = home.path().join(".cargo");
    for dir in ["bin", "registry", "git"] {
        fs::create_dir_all(cargo.join(dir))?;
    }
    for file in ["config.toml", "config", "env"] {
        fs::write(cargo.join(file), "")?;
    }
    let g = resolve(Some(home.path()), &LocalGrantConfig::default());
    let h = canon(home.path())?;
    let cargo = h.join(".cargo");
    assert!(
        !has(&g.read_write, &cargo),
        "Cargo home must never be writable"
    );
    assert!(has(&g.read_only, &cargo.join("bin")));
    assert!(has(&g.read_only, &cargo.join("registry")));
    assert!(has(&g.read_only, &cargo.join("git")));
    for file in ["config.toml", "config", "env"] {
        assert!(
            has(&g.read_only, &cargo.join(file)),
            "{file} should be read-only"
        );
    }
    for ro in [".rustup", ".nvm", ".npm"] {
        assert!(has(&g.read_only, &h.join(ro)), "{ro} should be read-only");
        assert!(
            !has(&g.read_write, &h.join(ro)),
            "{ro} must not be writable"
        );
    }
    for sys in ["/usr/local", "/opt"] {
        if Path::new(sys).exists() {
            assert!(has(&g.read_only, &canon(Path::new(sys))?), "{sys} missing");
        }
    }
    Ok(())
}

#[test]
fn absent_toolchain_homes_are_not_granted() -> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    fs::create_dir_all(home.path().join(".nvm"))?;
    let g = resolve(Some(home.path()), &LocalGrantConfig::default());
    let h = canon(home.path())?;
    assert!(has(&g.read_only, &h.join(".nvm")));
    assert!(!all(&g).iter().any(|p| p.starts_with(h.join(".cargo"))));
    assert!(!all(&g).iter().any(|p| p.starts_with(h.join(".rustup"))));
    Ok(())
}

#[test]
fn toolchain_homes_can_be_switched_off() -> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    fs::write(home.path().join(".gitconfig"), "[user]\n name = x\n")?;
    let cfg = LocalGrantConfig {
        toolchain_homes: false,
        ..LocalGrantConfig::default()
    };
    let g = resolve(Some(home.path()), &cfg);
    assert!(g.read_only.is_empty() && g.read_write.is_empty(), "{g:?}");
    Ok(())
}

#[test]
fn cargo_home_with_registry_credentials_is_granted_piecewise()
-> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    let cargo = home.path().join(".cargo");
    for d in ["bin", "registry", "git"] {
        fs::create_dir_all(cargo.join(d))?;
    }
    fs::write(
        cargo.join("credentials.toml"),
        "[registry]\ntoken = \"x\"\n",
    )?;
    fs::write(cargo.join("config.toml"), "")?;
    let g = resolve(Some(home.path()), &LocalGrantConfig::default());
    let c = canon(&cargo)?;
    assert!(
        !has(&g.read_write, &c),
        "whole ~/.cargo would expose credentials.toml"
    );
    assert!(!all(&g).iter().any(|p| p.ends_with("credentials.toml")));
    assert!(has(&g.read_only, &c.join("registry")));
    assert!(has(&g.read_only, &c.join("git")));
    assert!(has(&g.read_only, &c.join("bin")));
    assert!(has(&g.read_only, &c.join("config.toml")));
    Ok(())
}

#[test]
fn a_writable_grant_subsumes_the_same_path_read_only() -> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    let cfg = LocalGrantConfig {
        extra_read_only: vec!["~/.npm".into()],
        extra_read_write: vec!["~/.npm".into()],
        ..LocalGrantConfig::default()
    };
    let g = resolve(Some(home.path()), &cfg);
    let npm = canon(&home.path().join(".npm"))?;
    assert!(has(&g.read_write, &npm));
    assert!(!has(&g.read_only, &npm));
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn proc_is_off_by_default_and_only_the_toggle_grants_it() -> Result<(), Box<dyn std::error::Error>>
{
    let home = fake_home()?;
    let g = resolve(Some(home.path()), &LocalGrantConfig::default());
    assert!(!all(&g).iter().any(|p| p.starts_with("/proc")));

    // An `extra_*` entry cannot smuggle it in: only `allow_proc` does.
    let cfg = LocalGrantConfig {
        extra_read_only: vec!["/proc".into()],
        ..LocalGrantConfig::default()
    };
    let g = resolve(Some(home.path()), &cfg);
    assert!(!all(&g).iter().any(|p| p.starts_with("/proc")));

    let cfg = LocalGrantConfig {
        allow_proc: true,
        ..LocalGrantConfig::default()
    };
    let g = resolve(Some(home.path()), &cfg);
    assert!(has(&g.read_only, Path::new("/proc")));
    assert!(!has(&g.read_write, Path::new("/proc")));
    Ok(())
}

#[test]
fn extras_expand_tilde_and_skip_missing_paths() -> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    fs::create_dir_all(home.path().join("dotfiles"))?;
    fs::create_dir_all(home.path().join("data"))?;
    let cfg = LocalGrantConfig {
        extra_read_only: vec!["~/dotfiles".into(), "~/nope".into()],
        extra_read_write: vec!["~/data/../data".into()],
        ..LocalGrantConfig::default()
    };
    let g = resolve(Some(home.path()), &cfg);
    assert!(has(&g.read_only, &canon(&home.path().join("dotfiles"))?));
    assert!(has(&g.read_write, &canon(&home.path().join("data"))?));
    assert!(!all(&g).iter().any(|p| p.ends_with("nope")));
    Ok(())
}

#[test]
#[cfg(unix)]
fn gitconfig_symlink_and_include_targets_are_canonicalized()
-> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    let dots = home.path().join("dotfiles");
    fs::create_dir_all(&dots)?;
    fs::write(dots.join("work.gitconfig"), "[user]\n email = a@b\n")?;
    fs::write(dots.join("local.gitconfig"), "")?;
    fs::write(
        dots.join("gitconfig"),
        "[user]\n name = x\n[include]\n path = dotfiles/work.gitconfig\n\
         [includeIf \"gitdir:~/w/\"]\n\tpath = ~/dotfiles/local.gitconfig\n\
         [include]\n path = ~/.ssh/leaky\n",
    )?;
    std::os::unix::fs::symlink(dots.join("gitconfig"), home.path().join(".gitconfig"))?;
    // The credential include must be dropped even though the file exists.
    fs::write(home.path().join(".ssh/leaky"), "")?;

    let g = resolve(Some(home.path()), &LocalGrantConfig::default());
    let d = canon(&dots)?;
    assert!(has(&g.read_only, &d.join("gitconfig")), "{g:?}");
    assert!(has(&g.read_only, &d.join("work.gitconfig")), "{g:?}");
    assert!(has(&g.read_only, &d.join("local.gitconfig")), "{g:?}");
    assert_eq!(reaches_credentials(&all(&g), home.path()), None);
    Ok(())
}

#[test]
fn gitconfig_include_cycles_terminate() -> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    fs::write(home.path().join(".gitconfig"), "[include]\n path = ~/b\n")?;
    fs::write(home.path().join("b"), "[include]\n path = ~/.gitconfig\n")?;
    let g = resolve(Some(home.path()), &LocalGrantConfig::default());
    assert!(has(&g.read_only, &canon(&home.path().join("b"))?));
    Ok(())
}

#[test]
fn no_home_yields_only_system_toolchain_dirs() {
    let g = resolve(None, &LocalGrantConfig::default());
    assert_eq!(g.read_write, Vec::<PathBuf>::new());
    assert!(
        g.read_only
            .iter()
            .all(|p| p.starts_with("/usr/local") || p.starts_with("/opt"))
    );
}

fn floor(home: Option<&Path>) -> ProtectedPaths {
    ProtectedPaths {
        components: [
            ".ssh",
            ".gnupg",
            ".aws",
            ".azure",
            ".kube",
            "keychains",
            ".netrc",
            ".git-credentials",
            ".pgpass",
            ".npmrc",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        component_pairs: vec![
            [".cargo".into(), "credentials.toml".into()],
            [".docker".into(), "config.json".into()],
        ],
        prefixes: [
            "/etc",
            "/root",
            "/boot",
            "/proc",
            "/sys",
            "/system",
            "c:/windows",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        credential_roots: home
            .map(|home| {
                [".ssh", ".gnupg", ".aws", ".azure", ".kube"]
                    .into_iter()
                    .map(|component| home.join(component).to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default(),
    }
}
fn resolve(home: Option<&Path>, config: &LocalGrantConfig) -> JailGrants {
    resolve_local_jail_grants(home, config, &floor(home))
}

#[test]
fn custom_host_floor_excludes_direct_and_ancestor_grants() -> Result<(), Box<dyn std::error::Error>>
{
    let home = fake_home()?;
    let private = home.path().join("host-secrets");
    fs::create_dir(&private)?;
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_only: vec!["~".into(), "~/host-secrets".into()],
        ..LocalGrantConfig::default()
    };
    let protected = ProtectedPaths {
        credential_roots: vec![private.to_string_lossy().into_owned()],
        ..ProtectedPaths::default()
    };
    let grants = resolve_local_jail_grants(Some(home.path()), &config, &protected);
    assert_eq!(grants.read_only, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
fn host_floor_matches_component_pairs_and_case_insensitive_components()
-> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    fs::create_dir_all(home.path().join(".SSH"))?;
    fs::write(home.path().join(".cargo/credentials.toml"), "secret")?;
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_only: vec!["~/.SSH".into(), "~/.cargo/credentials.toml".into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve(Some(home.path()), &config);
    assert_eq!(grants.read_only, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
fn extras_without_home_and_empty_values_are_skipped() {
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_only: vec![" ".into(), "~".into(), "~/unknown".into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve(None, &config);
    assert_eq!(grants.read_only, Vec::<PathBuf>::new());
}

#[test]
fn include_parser_ignores_non_include_sections_and_empty_paths() {
    assert_eq!(
        include_paths(
            "[user]\npath = wrong\n[INCLUDE]\nignored\n other = wrong\n path = \"\"\n PATH = \"valid\"\n[includeIf \"gitdir:~/project\"]\n path = relative\n"
        ),
        ["valid", "relative"]
    );
}

#[test]
fn host_floor_matches_windows_separators_and_absolute_prefix_boundaries() {
    let protected = ProtectedPaths {
        components: vec![".ssh".into()],
        component_pairs: vec![["Microsoft".into(), "Protect".into()]],
        prefixes: vec!["C:/Windows".into()],
        credential_roots: Vec::new(),
    };
    let builder = Builder::new(None, &protected);
    assert!(builder.is_protected(Path::new(r"C:\Users\x\.SSH\id_rsa")));
    assert!(builder.is_protected(Path::new(r"C:\Users\x\Microsoft\Protect\keys")));
    assert!(builder.is_protected(Path::new(r"C:\WINDOWS\System32")));
    assert!(builder.is_protected(Path::new(r"C:\WINDOWS")));
    assert!(!builder.is_protected(Path::new(r"C:\WINDOWS-tools")));
}

#[test]
fn gitconfig_include_depth_is_bounded_and_non_files_are_skipped()
-> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    fs::write(
        home.path().join(".gitconfig"),
        "[include]\n path = ~/next-0\n path = ~/.cargo\n",
    )?;
    for index in 0..10 {
        fs::write(
            home.path().join(format!("next-{index}")),
            format!("[include]\n path = ~/next-{}\n", index + 1),
        )?;
    }
    let grants = resolve(Some(home.path()), &LocalGrantConfig::default());
    assert!(has(&grants.read_only, &canon(&home.path().join("next-7"))?));
    assert!(!has(
        &grants.read_only,
        &canon(&home.path().join("next-8"))?
    ));
    Ok(())
}

#[test]
fn protected_absolute_root_blocks_every_descendant() {
    let protected = ProtectedPaths {
        prefixes: vec!["/".into()],
        ..ProtectedPaths::default()
    };
    let builder = Builder::new(None, &protected);
    assert!(builder.is_protected(Path::new("/opt")));
    assert!(builder.is_protected(Path::new("/usr/local/toolchain")));
    assert!(!builder.is_protected(Path::new("relative/toolchain")));
}

#[test]
fn protected_prefix_trailing_separators_keep_component_boundaries() {
    let protected = ProtectedPaths {
        prefixes: vec!["/opt/secrets/".into(), r"C:\Windows\".into()],
        ..ProtectedPaths::default()
    };
    let builder = Builder::new(None, &protected);
    assert!(builder.is_protected(Path::new("/opt/secrets/key")));
    assert!(builder.is_protected(Path::new("/opt/secrets")));
    assert!(!builder.is_protected(Path::new("/opt/secrets-tools/key")));
    assert!(builder.is_protected(Path::new(r"C:\WINDOWS\System32")));
    assert!(builder.is_protected(Path::new(r"C:\WINDOWS")));
    assert!(!builder.is_protected(Path::new(r"C:\WINDOWS-tools")));
}

#[test]
fn protected_windows_prefixes_match_canonical_extended_path_names() {
    let protected = ProtectedPaths {
        prefixes: vec!["C:/Windows/".into(), "//server/secrets/".into()],
        ..ProtectedPaths::default()
    };
    let builder = Builder::new(None, &protected);
    assert!(builder.is_protected(Path::new(r"\\?\C:\WINDOWS\System32")));
    assert!(!builder.is_protected(Path::new(r"\\?\C:\WINDOWS-tools")));
    assert!(builder.is_protected(Path::new(r"\\?\UNC\SERVER\secrets\key")));
    assert!(!builder.is_protected(Path::new(r"\\?\UNC\SERVER\secrets-tools")));
}

#[test]
fn credential_root_ancestors_match_case_and_separator_styles() {
    let protected = ProtectedPaths {
        credential_roots: vec!["c:/users/floor-fixture/.ssh".into()],
        ..ProtectedPaths::default()
    };
    let builder = Builder::new(None, &protected);
    assert!(builder.exposes_credentials(Path::new(r"\\?\C:\Users\FLOOR-FIXTURE")));
    assert!(builder.exposes_credentials(Path::new(r"C:\USERS\floor-fixture\.SSH\id_rsa")));
    assert!(!builder.exposes_credentials(Path::new(r"C:\Users\floor-fixture-other")));
}

#[test]
#[cfg(unix)]
fn protected_credential_alias_does_not_grant_its_neutral_target()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    fs::create_dir(home.path().join("dotfiles"))?;
    fs::write(home.path().join("dotfiles/npmrc"), "fixture")?;
    std::os::unix::fs::symlink(
        home.path().join("dotfiles/npmrc"),
        home.path().join(".npmrc"),
    )?;
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_only: vec!["~/.npmrc".into()],
        ..LocalGrantConfig::default()
    };
    let protected = ProtectedPaths {
        components: vec![".npmrc".into()],
        ..ProtectedPaths::default()
    };
    let grants = resolve_local_jail_grants(Some(home.path()), &config, &protected);
    assert_eq!(grants.read_only, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn procfs_extras_cannot_bypass_the_dedicated_toggle_with_an_empty_floor() {
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_only: vec!["/proc".into(), "/proc/self".into()],
        extra_read_write: vec!["/proc".into(), "/proc/self".into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_local_jail_grants(None, &config, &ProtectedPaths::default());
    assert_eq!(grants.read_only, Vec::<PathBuf>::new());
    assert_eq!(grants.read_write, Vec::<PathBuf>::new());
}

#[test]
#[cfg(target_os = "linux")]
fn procfs_toggle_grants_read_only_access_even_when_extras_ask_for_writes() {
    let config = LocalGrantConfig {
        toolchain_homes: false,
        allow_proc: true,
        extra_read_write: vec!["/proc".into(), "/proc/self".into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_local_jail_grants(None, &config, &ProtectedPaths::default());
    assert_eq!(grants.read_only, vec![PathBuf::from("/proc")]);
    assert_eq!(grants.read_write, Vec::<PathBuf>::new());
}

#[test]
fn discovered_cargo_dependency_sources_cannot_be_poisoned_for_later_host_builds()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    for cache in ["git/checkouts/dependency", "registry/src/dependency"] {
        let source = home.path().join(".cargo").join(cache);
        fs::create_dir_all(&source)?;
        fs::write(source.join("build.rs"), "fn main() {}")?;
    }
    let grants = resolve_local_jail_grants(
        Some(home.path()),
        &LocalGrantConfig::default(),
        &ProtectedPaths::default(),
    );
    for cache in ["git", "registry"] {
        let source = home.path().join(".cargo").join(cache).canonicalize()?;
        assert!(has(&grants.read_only, &source), "{grants:?}");
        assert!(!has(&grants.read_write, &source), "{grants:?}");
    }
    Ok(())
}

#[test]
fn rejected_git_config_cannot_grant_its_nested_includes() -> Result<(), Box<dyn std::error::Error>>
{
    let home = tempfile::tempdir()?;
    fs::create_dir(home.path().join(".ssh"))?;
    fs::write(
        home.path().join(".gitconfig"),
        "[include]\n path = ~/.ssh/private-config\n",
    )?;
    fs::write(
        home.path().join(".ssh/private-config"),
        "[include]\n path = ~/neutral-secret\n",
    )?;
    fs::write(home.path().join("neutral-secret"), "fixture")?;
    let protected = ProtectedPaths {
        components: vec![".ssh".into()],
        ..ProtectedPaths::default()
    };
    let grants =
        resolve_local_jail_grants(Some(home.path()), &LocalGrantConfig::default(), &protected);
    assert!(
        !has(
            &grants.read_only,
            &home.path().join("neutral-secret").canonicalize()?
        ),
        "{grants:?}"
    );
    Ok(())
}

#[test]
fn protected_prefixes_also_reject_recursive_ancestor_grants()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    fs::create_dir(home.path().join("private"))?;
    let protected = ProtectedPaths {
        prefixes: vec![
            home.path()
                .join("private")
                .to_str()
                .ok_or("non-UTF8 fixture")?
                .into(),
        ],
        ..ProtectedPaths::default()
    };
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_write: vec![home.path().to_str().ok_or("non-UTF8 fixture")?.into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_local_jail_grants(None, &config, &protected);
    assert_eq!(grants.read_write, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
#[cfg(unix)]
fn protected_prefix_alias_also_blocks_its_canonical_spelling()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    let target = home.path().join("neutral");
    fs::create_dir(&target)?;
    std::os::unix::fs::symlink(&target, home.path().join("protected"))?;
    let protected = ProtectedPaths {
        prefixes: vec![
            home.path()
                .join("protected")
                .to_str()
                .ok_or("non-UTF8 fixture")?
                .into(),
        ],
        ..ProtectedPaths::default()
    };
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_only: vec![target.to_str().ok_or("non-UTF8 fixture")?.into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_local_jail_grants(None, &config, &protected);
    assert_eq!(grants.read_only, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
fn explicit_writable_grants_cannot_promote_shared_cargo_sources()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    for cache in ["git", "registry"] {
        fs::create_dir_all(home.path().join(".cargo").join(cache))?;
    }
    let config = LocalGrantConfig {
        toolchain_homes: true,
        extra_read_write: vec!["~/.cargo/git".into(), "~/.cargo/registry".into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_local_jail_grants(Some(home.path()), &config, &ProtectedPaths::default());
    assert_eq!(grants.read_write, Vec::<PathBuf>::new());
    for cache in ["git", "registry"] {
        assert!(
            has(
                &grants.read_only,
                &home.path().join(".cargo").join(cache).canonicalize()?
            ),
            "{grants:?}"
        );
    }
    Ok(())
}

#[test]
fn git_ignore_patterns_cannot_add_config_include_grants() -> Result<(), Box<dyn std::error::Error>>
{
    let home = tempfile::tempdir()?;
    fs::create_dir_all(home.path().join(".config/git"))?;
    fs::write(
        home.path().join(".config/git/ignore"),
        "[include]\npath = ~/neutral-secret\n",
    )?;
    fs::write(home.path().join("neutral-secret"), "fixture")?;
    let grants = resolve_local_jail_grants(
        Some(home.path()),
        &LocalGrantConfig::default(),
        &ProtectedPaths::default(),
    );
    assert!(
        has(
            &grants.read_only,
            &home.path().join(".config/git/ignore").canonicalize()?
        ),
        "{grants:?}"
    );
    assert!(
        !has(
            &grants.read_only,
            &home.path().join("neutral-secret").canonicalize()?
        ),
        "{grants:?}"
    );
    Ok(())
}

#[test]
#[cfg(unix)]
fn credential_root_alias_keeps_its_requested_ancestor_protected()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    std::os::unix::fs::symlink(outside.path(), home.path().join(".ssh"))?;
    let protected = ProtectedPaths {
        credential_roots: vec![
            home.path()
                .join(".ssh")
                .to_str()
                .ok_or("non-UTF8 fixture")?
                .into(),
        ],
        ..ProtectedPaths::default()
    };
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_only: vec!["~".into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_local_jail_grants(Some(home.path()), &config, &protected);
    assert_eq!(grants.read_only, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
#[cfg(unix)]
fn credential_floor_preserves_alias_locations_under_aliased_parent_directories()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    fs::create_dir(root.path().join("physical"))?;
    std::os::unix::fs::symlink(
        root.path().join("physical"),
        root.path().join("parent-alias"),
    )?;
    let home = root.path().join("parent-alias/home");
    fs::create_dir(&home)?;
    std::os::unix::fs::symlink(outside.path(), home.join(".ssh"))?;
    for credential in [".ssh", "missing/.ssh"] {
        let protected = ProtectedPaths {
            credential_roots: vec![
                home.join(credential)
                    .to_str()
                    .ok_or("non-UTF8 fixture")?
                    .into(),
            ],
            ..ProtectedPaths::default()
        };
        let config = LocalGrantConfig {
            toolchain_homes: false,
            extra_read_only: vec!["~".into()],
            ..LocalGrantConfig::default()
        };
        let grants = resolve_local_jail_grants(Some(&home), &config, &protected);
        assert_eq!(grants.read_only, Vec::<PathBuf>::new(), "{credential}");
    }
    Ok(())
}

#[test]
fn writable_extras_cannot_replace_cargo_executables_or_launch_configuration()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    fs::create_dir_all(home.path().join(".cargo/bin"))?;
    for file in ["config.toml", "config", "env"] {
        fs::write(home.path().join(".cargo").join(file), "fixture")?;
    }
    let config = LocalGrantConfig {
        extra_read_write: ["bin", "config.toml", "config", "env"].into_iter().map(|entry| format!("~/.cargo/{entry}")).collect(),
        ..LocalGrantConfig::default()
    };
    let grants = resolve_local_jail_grants(Some(home.path()), &config, &ProtectedPaths::default());
    assert_eq!(grants.read_write, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
fn automatic_toolchain_roots_cannot_be_promoted_through_writable_descendants()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    for root in [".rustup", ".nvm", ".npm"] { fs::create_dir_all(home.path().join(root).join("nested"))?; }
    let config = LocalGrantConfig {
        extra_read_write: [".rustup", ".nvm", ".npm"].into_iter().map(|root| format!("~/{root}/nested")).collect(),
        ..LocalGrantConfig::default()
    };
    let grants = resolve_local_jail_grants(Some(home.path()), &config, &ProtectedPaths::default());
    assert_eq!(grants.read_write, Vec::<PathBuf>::new());
    Ok(())
}
