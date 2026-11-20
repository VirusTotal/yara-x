use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf, Prefix};

/// Literal paths excluded from a scan, together with their descendants.
///
/// Each excluded path is stored as a lexically normalized absolute [`PathBuf`]
/// and, when its ancestor directories resolve to a different spelling (e.g.,
/// symlinked parents like `/tmp` -> `/private/tmp` on macOS, or Windows 8.3
/// short names), that second spelling is stored as well. The excluded entry
/// itself is never opened.
#[derive(Default)]
pub struct Exclusions {
    /// Working directory captured once so relative paths don't call
    /// `std::env::current_dir` repeatedly.
    cwd: Option<PathBuf>,
    /// Normalized absolute paths to exclude.
    paths: Vec<PathBuf>,
}

/// Exclusions scoped to the root of a single directory walk.
///
/// Borrows root-relative path slices directly from [`Exclusions`], allowing
/// `WalkDir::filter_entry` to check each entry with no per-entry allocations.
#[derive(Default)]
pub struct Scope<'a> {
    root_excluded: bool,
    relative: Vec<&'a Path>,
}

/// Cache of canonicalized ancestor directories reused while iterating a
/// `--scan-list` so each directory is resolved at most once.
#[derive(Default)]
pub struct ParentCache {
    entries: HashMap<PathBuf, Option<PathBuf>>,
}

impl ParentCache {
    fn canonicalize(&mut self, dir: &Path) -> Option<&Path> {
        if !self.entries.contains_key(dir) {
            let resolved = dunce::canonicalize(dir).ok();
            self.entries.insert(dir.to_path_buf(), resolved);
        }
        self.entries.get(dir).and_then(|p| p.as_deref())
    }
}

impl Exclusions {
    pub fn new() -> Self {
        Self { cwd: std::env::current_dir().ok(), paths: Vec::new() }
    }

    pub fn add(&mut self, path: &Path) -> anyhow::Result<()> {
        anyhow::ensure!(
            !path.as_os_str().is_empty(),
            "excluded path must not be empty"
        );

        let lexical = self.make_absolute(path).ok_or_else(|| {
            anyhow::anyhow!(
                "can't resolve `{}` without a working directory",
                path.display()
            )
        })?;

        let resolved =
            resolve_parent_cached(&lexical, &mut ParentCache::default());

        self.push_unique(lexical);
        if let Some(resolved) = resolved {
            self.push_unique(resolved);
        }

        Ok(())
    }

    /// Returns `true` if `path` is excluded.
    ///
    /// Empty paths are never excluded so callers report them the same way as
    /// when no exclusions are configured.
    pub fn contains(&self, path: &Path) -> bool {
        self.contains_cached(path, &mut ParentCache::default())
    }

    /// Like [`Exclusions::contains`], reusing previously canonicalized
    /// ancestor directories across calls.
    pub fn contains_cached(
        &self,
        path: &Path,
        cache: &mut ParentCache,
    ) -> bool {
        if self.paths.is_empty() || path.as_os_str().is_empty() {
            return false;
        }

        let Some(lexical) = self.make_absolute(path) else {
            return false;
        };

        if self.matches(&lexical) {
            return true;
        }

        resolve_parent_cached(&lexical, cache)
            .is_some_and(|resolved| self.matches(&resolved))
    }

    /// Precomputes exclusions relative to `root`, the starting directory of a
    /// directory walk.
    pub fn scope(&self, root: &Path) -> Scope<'_> {
        if self.paths.is_empty() {
            return Scope::default();
        }

        let mut roots = Vec::with_capacity(2);
        if let Some(lexical) = self.make_absolute(root) {
            roots.push(lexical);
        }
        if let Ok(resolved) = dunce::canonicalize(root)
            && !roots.iter().any(|r| paths_eq(r, &resolved))
        {
            roots.push(resolved);
        }

        let mut relative: Vec<&Path> = Vec::new();
        for root in &roots {
            for excluded in &self.paths {
                if strip_prefix_components(root, excluded).is_some() {
                    return Scope {
                        root_excluded: true,
                        relative: Vec::new(),
                    };
                }
                if let Some(rel) = strip_prefix_components(excluded, root)
                    && !relative.iter().any(|r| paths_eq(r, rel))
                {
                    relative.push(rel);
                }
            }
        }

        Scope { root_excluded: false, relative }
    }

    fn push_unique(&mut self, path: PathBuf) {
        if !self.paths.iter().any(|existing| paths_eq(existing, &path)) {
            self.paths.push(path);
        }
    }

    fn make_absolute(&self, path: &Path) -> Option<PathBuf> {
        if path.is_absolute() {
            return Some(normalize_lexical(path));
        }

        // On Windows, drive-relative paths like `C:` or `C:foo` carry a prefix
        // without a root directory. `cwd.join(path)` would discard `cwd` and
        // leave the path unrooted, so resolve those via `std::path::absolute`.
        if matches!(path.components().next(), Some(Component::Prefix(_))) {
            return std::path::absolute(path)
                .ok()
                .map(|p| normalize_lexical(&p));
        }

        self.cwd.as_ref().map(|cwd| normalize_lexical(&cwd.join(path)))
    }

    fn matches(&self, candidate: &Path) -> bool {
        self.paths.iter().any(|excluded| {
            strip_prefix_components(candidate, excluded).is_some()
        })
    }
}

impl Scope<'_> {
    pub fn root_excluded(&self) -> bool {
        self.root_excluded
    }

    /// Returns `true` if `relative` (a walk entry path relative to the walk
    /// root) matches an exclusion.
    pub fn excludes(&self, relative: &Path) -> bool {
        self.relative.iter().any(|excluded| {
            strip_prefix_components(relative, excluded).is_some()
        })
    }
}

/// Resolves symbolic links (and Windows 8.3 short names) in the ancestor
/// directories of `path` without touching `path` itself.
///
/// Walks up from `path.parent()` until the deepest resolvable ancestor is
/// found, then re-appends the remaining suffix components. Returns `None` for
/// root paths (`/` or `C:\`), when no ancestor can be resolved, or when the
/// resolved path equals `path`.
fn resolve_parent_cached(
    path: &Path,
    cache: &mut ParentCache,
) -> Option<PathBuf> {
    let parent = path.parent()?;
    let name = path.file_name()?;

    // Fast path: immediate parent exists and is accessible.
    if let Some(canonical) = cache.canonicalize(parent) {
        if paths_eq(canonical, parent) {
            return None;
        }
        return Some(canonical.join(name));
    }

    // Slow path: immediate parent is missing or inaccessible; walk up to the
    // deepest resolvable ancestor and re-append the unresolved tail.
    let mut tail = vec![name];
    let mut current = parent;
    loop {
        tail.push(current.file_name()?);
        current = current.parent()?;
        if let Some(canonical) = cache.canonicalize(current) {
            if paths_eq(canonical, current) {
                return None;
            }
            let mut resolved = canonical.to_path_buf();
            for component in tail.into_iter().rev() {
                resolved.push(component);
            }
            return Some(resolved);
        }
    }
}

/// Lexically normalizes `.` and `..` components of an absolute path while
/// preserving its prefix (including Windows verbatim `\\?\` prefixes) and root.
fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                out.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(c) => out.push(c),
        }
    }
    out
}

/// Strips `prefix` from `path` component-by-component, equating Windows
/// verbatim and regular prefixes and comparing case-insensitively on Windows.
fn strip_prefix_components<'a>(
    path: &'a Path,
    prefix: &Path,
) -> Option<&'a Path> {
    let mut path_components = path.components();
    for expected in prefix.components() {
        let actual = path_components.next()?;
        if !component_eq(actual, expected) {
            return None;
        }
    }
    Some(path_components.as_path())
}

fn paths_eq(a: &Path, b: &Path) -> bool {
    strip_prefix_components(a, b)
        .is_some_and(|rest| rest.as_os_str().is_empty())
}

fn component_eq(a: Component<'_>, b: Component<'_>) -> bool {
    match (a, b) {
        (Component::RootDir, Component::RootDir) => true,
        (Component::CurDir, Component::CurDir) => true,
        (Component::ParentDir, Component::ParentDir) => true,
        (Component::Normal(a), Component::Normal(b)) => os_str_eq(a, b),
        (Component::Prefix(a), Component::Prefix(b)) => {
            prefix_eq(a.kind(), b.kind())
        }
        _ => false,
    }
}

fn prefix_eq(a: Prefix<'_>, b: Prefix<'_>) -> bool {
    match (a, b) {
        (
            Prefix::Disk(a) | Prefix::VerbatimDisk(a),
            Prefix::Disk(b) | Prefix::VerbatimDisk(b),
        ) => a.eq_ignore_ascii_case(&b),
        (
            Prefix::UNC(s1, sh1) | Prefix::VerbatimUNC(s1, sh1),
            Prefix::UNC(s2, sh2) | Prefix::VerbatimUNC(s2, sh2),
        ) => os_str_eq(s1, s2) && os_str_eq(sh1, sh2),
        (Prefix::Verbatim(a), Prefix::Verbatim(b)) => os_str_eq(a, b),
        (Prefix::DeviceNS(a), Prefix::DeviceNS(b)) => os_str_eq(a, b),
        _ => false,
    }
}

/// Path components compare case-insensitively on Windows and byte-for-byte
/// elsewhere.
fn os_str_eq(a: &OsStr, b: &OsStr) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_lexical_collapses_dots_and_clamps_at_root() {
        #[cfg(unix)]
        {
            assert_eq!(
                normalize_lexical(Path::new("/a/./b/../c")),
                Path::new("/a/c")
            );
            assert_eq!(
                normalize_lexical(Path::new("/../../a")),
                Path::new("/a")
            );
            assert_eq!(normalize_lexical(Path::new("/a/..")), Path::new("/"));
        }

        #[cfg(windows)]
        {
            assert_eq!(
                normalize_lexical(Path::new(r"C:\a\.\b\..\c")),
                Path::new(r"C:\a\c")
            );
            assert_eq!(
                normalize_lexical(Path::new(r"C:\..\..\a")),
                Path::new(r"C:\a")
            );
            assert_eq!(
                normalize_lexical(Path::new(r"C:\a\..")),
                Path::new(r"C:\")
            );
        }
    }

    #[test]
    fn strip_prefix_matches_component_boundaries() {
        let base = if cfg!(windows) {
            Path::new(r"C:\work\skip")
        } else {
            Path::new("/work/skip")
        };
        let child = base.join("deep").join("file.bin");
        let sibling = if cfg!(windows) {
            Path::new(r"C:\work\skip.more")
        } else {
            Path::new("/work/skip.more")
        };

        assert_eq!(strip_prefix_components(base, base), Some(Path::new("")));
        assert_eq!(
            strip_prefix_components(&child, base),
            Some(Path::new("deep").join("file.bin").as_path())
        );
        assert_eq!(strip_prefix_components(sibling, base), None);
    }

    #[test]
    fn root_path_is_not_excluded_by_descendant_exclusion() {
        let cwd = std::env::current_dir().unwrap();
        let mut exclusions =
            Exclusions { cwd: Some(cwd.clone()), paths: Vec::new() };
        exclusions.add(Path::new(".")).unwrap();

        let root = cwd.ancestors().last().unwrap();
        assert!(!exclusions.contains(root));
        assert!(exclusions.contains(&cwd));
        assert!(exclusions.contains(&cwd.join("child")));

        let scope = exclusions.scope(root);
        assert!(!scope.root_excluded());
        let rel = cwd.strip_prefix(root).unwrap();
        assert!(scope.excludes(rel));
    }

    #[cfg(windows)]
    #[test]
    fn verbatim_and_case_differences_match_on_windows() {
        let regular = Path::new(r"C:\Users\Alice\OneDrive");
        let verbatim_long =
            Path::new(r"\\?\c:\users\alice\onedrive\sub\file.bin");
        assert_eq!(
            strip_prefix_components(verbatim_long, regular),
            Some(Path::new(r"sub\file.bin"))
        );

        let unc = Path::new(r"\\Server\Share\Folder");
        let verbatim_unc = Path::new(r"\\?\UNC\server\share\folder\file.bin");
        assert_eq!(
            strip_prefix_components(verbatim_unc, unc),
            Some(Path::new("file.bin"))
        );
    }
}
