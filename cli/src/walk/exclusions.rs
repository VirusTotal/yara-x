use std::path::{Component, Path, PathBuf, absolute};

/// Literal, lexical paths. Resolving symlinks or checking existence here would
/// access paths that the caller explicitly asked us not to scan.
#[derive(Default)]
pub(super) struct Exclusions {
    paths: Vec<PathBuf>,
}

impl Exclusions {
    pub(super) fn add(&mut self, path: &Path) -> anyhow::Result<()> {
        anyhow::ensure!(
            !path.as_os_str().is_empty(),
            "excluded path must not be empty"
        );
        self.paths.push(normalize(&absolute(path)?));
        Ok(())
    }

    pub(super) fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    pub(super) fn contains(&self, path: &Path) -> anyhow::Result<bool> {
        if self.is_empty() {
            return Ok(false);
        }
        Ok(self.contains_absolute(&absolute(path)?))
    }

    pub(super) fn contains_absolute(&self, path: &Path) -> bool {
        let path = normalize(path);
        self.paths.iter().any(|excluded| path.starts_with(excluded))
    }
}

fn normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in dunce::simplified(path).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            _ => result.push(component.as_os_str()),
        }
    }
    result
}
