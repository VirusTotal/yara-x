use bstr::ByteSlice;
use strum_macros::Display;

use crate::modules::protos;
use crate::modules::utils::zip::Zip;

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
    pub(crate) fn parse(zip: &mut Zip) -> Result<Self, Error> {
        let manifest = Self::read_manifest(zip).ok_or(Error::InvalidVsix)?;

        let mut files = Vec::new();
        let mut path_buf = vec![0u8; 65536];

        for entry in zip.archive.entries().filter_map(|entry| entry.ok()) {
            if let Ok(path_bytes) = entry.read_path(&mut path_buf) {
                files.push(String::from_utf8_lossy(path_bytes).into_owned());
            }
        }

        Ok(Vsix { manifest: Some(manifest), files })
    }

    fn read_manifest(zip: &Zip) -> Option<VsixManifest> {
        // Try common locations for package.json
        let paths = ["extension/package.json", "package.json"];

        for path in paths {
            if let Some(content) = zip.get_file_content(path)
                && let Ok(manifest) =
                    serde_json::from_slice::<VsixManifest>(&content)
                {
                    return Some(manifest);
                }
        }

        // Try to find package.json in any subdirectory
        // (e.g., publisher.name-version/)
        let mut path_buf = vec![0u8; 65536];

        for entry in zip.archive.entries().filter_map(|e| e.ok()) {
            if let Ok(path_bytes) = entry.read_path(&mut path_buf)
                && path_bytes.ends_with_str("/package.json")
                    && let Some(content) = zip.get_file_content(path_bytes)
                        && let Ok(manifest) =
                            serde_json::from_slice::<VsixManifest>(&content)
                        {
                            return Some(manifest);
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
