//! Bounded Git configuration include discovery.
use super::Builder;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Git config files read at startup, relative to `$HOME`.
const GITCONFIG_FILES: &[&str] = &[".gitconfig", ".config/git/config"];

/// Deepest `include` chain followed when collecting git config files.
const GITCONFIG_MAX_DEPTH: usize = 8;

impl Builder<'_> {
    /// Read-only grants for the user's git config files and everything they
    /// `include`, each canonicalized (a config is often a symlink into a
    /// dotfiles repo, and the jail needs the target).
    pub(super) fn add_gitconfig(&mut self, home: &Path) {
        let mut roots: Vec<PathBuf> = GITCONFIG_FILES.iter().map(|f| home.join(f)).collect();
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            roots.push(Path::new(&xdg).join("git/config"));
        }
        self.fixed_read_only(&home.join(".config/git/ignore"), "gitignore");
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            self.fixed_read_only(&Path::new(&xdg).join("git/ignore"), "gitignore");
        }
        let mut visited = HashSet::new();
        for root in roots {
            self.add_gitconfig_file(&root, home, 0, &mut visited);
        }
    }

    fn add_gitconfig_file(
        &mut self,
        file: &Path,
        home: &Path,
        depth: usize,
        visited: &mut HashSet<PathBuf>,
    ) {
        let Some(canonical) = self.admit(file, "gitconfig") else {
            return;
        };
        if !canonical.is_file() {
            return;
        }
        // Protect each requested link location, even when multiple configs
        // resolve to one target. A writable parent could replace that link.
        self.fixed_read_only(file, "gitconfig");
        if !visited.insert(canonical.clone()) || depth >= GITCONFIG_MAX_DEPTH {
            return;
        }
        let Ok(text) = std::fs::read_to_string(&canonical) else {
            return;
        };
        // Relative includes resolve against the directory of the file *as
        // named*, which for a symlinked config is the link's directory.
        let base = file.parent().unwrap_or(home);
        for target in include_paths(&text) {
            let resolved = if let Some(rest) = target.strip_prefix("~/") {
                home.join(rest)
            } else if Path::new(&target).is_absolute() {
                PathBuf::from(&target)
            } else {
                base.join(&target)
            };
            self.add_gitconfig_file(&resolved, home, depth + 1, visited);
        }
    }
}

/// `path = …` values inside `[include]` / `[includeIf …]` sections.
pub(super) fn include_paths(config: &str) -> Vec<String> {
    let mut in_include = false;
    let mut out = Vec::new();
    for line in config.lines() {
        let line = line.trim();
        if let Some(section) = line.strip_prefix('[') {
            let name = section.split([']', ' ', '"']).next().unwrap_or("");
            in_include =
                name.eq_ignore_ascii_case("include") || name.eq_ignore_ascii_case("includeif");
            continue;
        }
        if !in_include {
            continue;
        }
        if let Some((key, value)) = line.split_once('=')
            && key.trim().eq_ignore_ascii_case("path")
            && let Some(value) = include_value(value)
        {
            out.push(value);
        }
    }
    out
}

// Git comments begin only outside double quotes. Decode Git's supported
// escapes and reject malformed values instead of inventing filesystem paths.
fn include_value(value: &str) -> Option<String> {
    let mut chars = value.trim_start().chars();
    let mut quoted = false;
    let mut out = String::new();
    let mut significant = 0;
    while let Some(ch) = chars.next() {
        match ch {
            '"' => quoted = !quoted,
            '#' | ';' if !quoted => break,
            '\\' => {
                let decoded = match chars.next()? {
                    'n' => '\n',
                    't' => '\t',
                    'b' => '\u{0008}',
                    '\\' => '\\',
                    '"' => '"',
                    _ => return None,
                };
                out.push(decoded);
                significant = out.len();
            }
            _ => {
                out.push(ch);
                if quoted || !ch.is_whitespace() {
                    significant = out.len();
                }
            }
        }
    }
    if quoted {
        return None;
    }
    out.truncate(significant);
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
#[path = "git_config_tests.rs"]
mod tests;
