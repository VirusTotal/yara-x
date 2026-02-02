use std::io::{Cursor, Read, Seek};

use strum_macros::Display;
use zip::result::ZipResult;
use zip::ZipArchive;

use crate::modules::protos;

#[derive(Display)]
pub enum Error {
    InvalidVsix,
}

/// A Visual Studio Code Extension (VSIX) parser.
///
/// VSIX files are ZIP archives containing a `package.json` manifest
/// that describes the extension. The manifest is typically located at
/// `extension/package.json` but may also be at the root or in a
/// `publisher.name-version/` directory.
#[derive(Default)]
pub struct Vsix {
    manifest: Option<VsixManifest>,
    files: Vec<String>,
}

/// The package.json manifest structure for VS Code extensions.
#[derive(serde::Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct VsixManifest {
    name: Option<String>,
    display_name: Option<String>,
    publisher: Option<String>,
    version: Option<String>,
    description: Option<String>,
    main: Option<String>,
    browser: Option<String>,
    #[serde(default)]
    activation_events: Vec<String>,
    #[serde(default)]
    engines: Option<VsixEngines>,
    repository: Option<VsixRepository>,
    homepage: Option<String>,
    license: Option<String>,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    keywords: Vec<String>,
}

#[derive(serde::Deserialize, Debug, Default)]
struct VsixEngines {
    vscode: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
#[serde(untagged)]
enum VsixRepository {
    String(String),
    Object { url: Option<String> },
}

impl VsixRepository {
    fn url(&self) -> Option<&str> {
        match self {
            VsixRepository::String(s) => Some(s.as_str()),
            VsixRepository::Object { url } => url.as_deref(),
        }
    }
}

impl Vsix {
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let mut zip = Self::read_zip(data).map_err(|_| Error::InvalidVsix)?;

        // Collect all file names from the archive as in-memory strings for YARA
        // rule matching. Note: While file.name() can contain path traversal
        // sequences like "../", this is only a security concern when extracting
        // files to disk. Here, names are stored as opaque strings for pattern
        // matching, never used as paths.
        let mut files = Vec::with_capacity(zip.len());
        for i in 0..zip.len() {
            if let Ok(file) = zip.by_index(i) {
                files.push(file.name().to_string());
            }
        }

        // Try to find and parse package.json
        let manifest = Self::read_manifest(&mut zip);

        // If no manifest found, this is not a valid VSIX
        if manifest.is_none() {
            return Err(Error::InvalidVsix);
        }

        Ok(Vsix { manifest, files })
    }

    fn read_zip(zip_data: &[u8]) -> ZipResult<ZipArchive<Cursor<&[u8]>>> {
        zip::ZipArchive::new(Cursor::new(zip_data))
    }

    fn read_manifest<R: Read + Seek>(
        zip: &mut ZipArchive<R>,
    ) -> Option<VsixManifest> {
        // Try common locations for package.json
        let paths = ["extension/package.json", "package.json"];

        for path in paths {
            if let Ok(file) = zip.by_name(path) {
                if let Ok(manifest) =
                    serde_json::from_reader::<_, VsixManifest>(file)
                {
                    return Some(manifest);
                }
            }
        }

        // Try to find package.json in any subdirectory (e.g., publisher.name-version/)
        for i in 0..zip.len() {
            if let Ok(file) = zip.by_index(i) {
                let name = file.name();
                if name.ends_with("/package.json")
                    && name.matches('/').count() == 1
                {
                    if let Ok(manifest) =
                        serde_json::from_reader::<_, VsixManifest>(file)
                    {
                        return Some(manifest);
                    }
                }
            }
        }

        None
    }
}

impl From<Vsix> for protos::vsix::Vsix {
    fn from(vsix: Vsix) -> Self {
        let mut result = protos::vsix::Vsix::new();
        result.set_is_vsix(true);
        result.files = vsix.files;

        if let Some(manifest) = vsix.manifest {
            result.name = manifest.name.clone();
            result.display_name = manifest.display_name;
            result.publisher = manifest.publisher.clone();
            result.version = manifest.version;
            result.description = manifest.description;
            result.main = manifest.main;
            result.browser = manifest.browser;
            result.activation_events = manifest.activation_events;
            result.license = manifest.license;
            result.homepage = manifest.homepage;
            result.categories = manifest.categories;
            result.keywords = manifest.keywords;

            // Compute extension ID as publisher.name
            if let (Some(publisher), Some(name)) =
                (&manifest.publisher, &manifest.name)
            {
                result.id = Some(format!("{publisher}.{name}"));
            }

            // Extract vscode version from engines
            if let Some(engines) = manifest.engines {
                result.vscode_version = engines.vscode;
            }

            // Extract repository URL
            if let Some(repo) = manifest.repository {
                result.repository = repo.url().map(|s| s.to_string());
            }
        }

        result
    }
}
