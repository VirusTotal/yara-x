use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf, Prefix};

/// Paths excluded from a scan.
///
/// Each exclusion is kept in up to two spellings: the path as given, made
/// absolute against the working directory, and the same path with symbolic
/// links in its parent directories resolved. A candidate is excluded when any
/// spelling of an exclusion is a prefix of any spelling of the candidate, so
/// that `/tmp/x` and `/private/tmp/x` on macOS, `$PWD/x` and `./x`, or Windows
/// 8.3 short names and long names, all refer to the same exclusion. Only
/// parent directories are resolved; the excluded entry itself is not opened.
#[derive(Default)]
pub struct Exclusions {
    /// Working directory, read once.
    cwd: Option<PathBuf>,
    /// Every spelling of every exclusion.
    keys: Vec<Key>,
}

/// A normalized absolute path: a prefix (drive or UNC share on Windows, the
/// root elsewhere) followed by normal components. `.` and `..` are resolved
/// lexically.
#[derive(Clone, PartialEq, Debug)]
struct Key(Vec<OsString>);

/// Exclusions expressed relative to the root of a directory walk, computed
/// once per walk so that matching an entry needs no allocation.
pub struct Scope {
    root_excluded: bool,
    relative: Vec<Vec<OsString>>,
}

/// Canonical spellings of parent directories already resolved during a walk
/// of a scan list, so each directory is resolved once.
#[derive(Default)]
pub struct ParentCache(HashMap<PathBuf, Option<Key>>);

impl Exclusions {
    pub fn new() -> Self {
        Self { cwd: std::env::current_dir().ok(), keys: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn add(&mut self, path: &Path) -> anyhow::Result<()> {
        anyhow::ensure!(
            !path.as_os_str().is_empty(),
            "excluded path must not be empty"
        );
        let lexical = self.lexical(path).ok_or_else(|| {
            anyhow::anyhow!(
                "can't resolve `{}` without a working directory",
                path.display()
            )
        })?;
        let resolved = resolve_parent(&lexical);
        self.keys.push(lexical);
        if let Some(resolved) = resolved
            && !self.keys.contains(&resolved)
        {
            self.keys.push(resolved);
        }
        Ok(())
    }

    /// Returns true if `path` is excluded. Empty paths are never excluded, so
    /// that the caller reports them as it would without exclusions.
    pub fn contains(&self, path: &Path) -> bool {
        self.contains_cached(path, &mut ParentCache::default())
    }

    /// Like [`Exclusions::contains`], reusing resolved parent directories.
    pub fn contains_cached(
        &self,
        path: &Path,
        cache: &mut ParentCache,
    ) -> bool {
        if self.is_empty() || path.as_os_str().is_empty() {
            return false;
        }
        let Some(lexical) = self.lexical(path) else {
            return false;
        };
        if self.matches(&lexical) {
            return true;
        }
        let Some((name, parent)) = lexical.0.split_last() else {
            return false;
        };
        let parent: PathBuf = parent.iter().collect();
        let resolved = cache
            .0
            .entry(parent.clone())
            .or_insert_with(|| canonical(&parent))
            .clone();
        match resolved {
            Some(mut key) => {
                key.0.push(name.clone());
                self.matches(&key)
            }
            None => false,
        }
    }

    /// Exclusions relative to `root`, the starting point of a directory walk.
    pub fn scope(&self, root: &Path) -> Scope {
        let mut scope = Scope { root_excluded: false, relative: Vec::new() };
        if self.is_empty() {
            return scope;
        }
        let mut roots = Vec::new();
        if let Some(lexical) = self.lexical(root) {
            roots.push(lexical);
        }
        if let Some(resolved) = canonical(root)
            && !roots.contains(&resolved)
        {
            roots.push(resolved);
        }
        for root in &roots {
            for key in &self.keys {
                if is_prefix(&key.0, &root.0) {
                    scope.root_excluded = true;
                } else if is_prefix(&root.0, &key.0) {
                    let rest = key.0[root.0.len()..].to_vec();
                    if !scope.relative.contains(&rest) {
                        scope.relative.push(rest);
                    }
                }
            }
        }
        scope
    }

    fn lexical(&self, path: &Path) -> Option<Key> {
        if path.is_absolute() {
            Some(key(path))
        } else {
            self.cwd.as_ref().map(|cwd| key(&cwd.join(path)))
        }
    }

    fn matches(&self, candidate: &Key) -> bool {
        self.keys.iter().any(|key| is_prefix(&key.0, &candidate.0))
    }
}

impl Scope {
    pub fn root_excluded(&self) -> bool {
        self.root_excluded
    }

    /// `relative` is the path of a walk entry relative to the walk root.
    pub fn excludes(&self, relative: &Path) -> bool {
        self.relative.iter().any(|excluded| {
            let mut components = relative.components();
            excluded.iter().all(|e| match components.next() {
                Some(Component::Normal(c)) => component_eq(e, c),
                _ => false,
            })
        })
    }
}

/// Resolves symbolic links in the parent directories of `lexical`, without
/// touching the last component. Returns `None` if the parent can't be
/// resolved, for instance because it doesn't exist.
fn resolve_parent(lexical: &Key) -> Option<Key> {
    let (name, parent) = lexical.0.split_last()?;
    if parent.is_empty() {
        return None;
    }
    let mut resolved = canonical(&parent.iter().collect::<PathBuf>())?;
    resolved.0.push(name.clone());
    (resolved != *lexical).then_some(resolved)
}

fn canonical(path: &Path) -> Option<Key> {
    dunce::canonicalize(path).ok().map(|p| key(&p))
}

/// Normalizes an absolute path into a [`Key`]. On Windows, verbatim (`\\?\`)
/// and regular prefixes for the same drive or share produce the same key.
fn key(path: &Path) -> Key {
    let mut parts: Vec<OsString> = Vec::new();
    let mut base = 0;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                parts.push(prefix_key(prefix.kind()));
                base = parts.len();
            }
            Component::RootDir => {
                parts.push(OsString::from(std::path::MAIN_SEPARATOR_STR));
                base = parts.len();
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.len() > base {
                    parts.pop();
                }
            }
            Component::Normal(c) => parts.push(c.to_os_string()),
        }
    }
    Key(parts)
}

fn prefix_key(prefix: Prefix<'_>) -> OsString {
    match prefix {
        Prefix::Disk(d) | Prefix::VerbatimDisk(d) => {
            OsString::from(format!("{}:", (d as char).to_ascii_uppercase()))
        }
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
            let mut s = OsString::from(r"\\");
            s.push(server);
            s.push(r"\");
            s.push(share);
            s
        }
        Prefix::Verbatim(p) => p.to_os_string(),
        Prefix::DeviceNS(p) => {
            let mut s = OsString::from(r"\\.\");
            s.push(p);
            s
        }
    }
}

fn is_prefix(prefix: &[OsString], path: &[OsString]) -> bool {
    prefix.len() <= path.len()
        && prefix.iter().zip(path).all(|(a, b)| component_eq(a, b))
}

/// Path components compare case-insensitively on Windows, where file names
/// are case-insensitive, and byte for byte elsewhere.
fn component_eq(a: &OsStr, b: &OsStr) -> bool {
    if !cfg!(windows) || a == b {
        return a == b;
    }
    if a.eq_ignore_ascii_case(b) {
        return true;
    }
    match (a.to_str(), b.to_str()) {
        (Some(a), Some(b)) => a.to_lowercase() == b.to_lowercase(),
        _ => false,
    }
}
