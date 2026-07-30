//! Serde model of the androguard JSON report (the external analysis the host
//! feeds as module metadata). Mirrors the keys the original Koodous C module
//! read from the report with jansson: `package_name`, `app_name`,
//! `main_activity`, `activities`, `services`, `urls`, `permissions`,
//! `new_permissions`, `min/max/target_sdk_version` (strings, atoi'd) and the
//! `certificate` object (`subjectDN`, `IssuerDN`, `sha1`).

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct CertificateJson {
    #[serde(rename = "subjectDN")]
    pub subject_dn: Option<String>,
    #[serde(rename = "IssuerDN")]
    pub issuer_dn: Option<String>,
    pub sha1: Option<String>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct MetaDataEntry {
    pub name: Option<String>,
    pub value: Option<String>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct AndroguardJson {
    pub package_name: Option<String>,
    pub app_name: Option<String>,
    pub main_activity: Option<String>,

    pub activities: Option<Vec<String>>,
    pub services: Option<Vec<String>>,
    pub receivers: Option<Vec<String>>,
    pub urls: Option<Vec<String>>,

    pub permissions: Option<Vec<String>>,
    pub new_permissions: Option<Vec<String>>,

    pub certificate: Option<CertificateJson>,

    // The original module stored these as strings and ran atoi() over them, so
    // accept a string (and tolerate a bare number too).
    #[serde(default, deserialize_with = "de_opt_int_str")]
    pub min_sdk_version: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_int_str")]
    pub max_sdk_version: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_int_str")]
    pub target_sdk_version: Option<i64>,

    /// `<meta-data>` entries from AndroidManifest.xml
    pub meta_data: Option<Vec<MetaDataEntry>>,
}

/// Deserialize an optional integer that may be encoded as a JSON string
/// ("19"), a JSON number (19), or be absent/null — matching the C module's
/// lenient `atoi(json_string_value(...))`.
fn de_opt_int_str<'de, D>(d: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum IntOrStr {
        Int(i64),
        Str(String),
        Null,
    }
    Ok(match Option::<IntOrStr>::deserialize(d)? {
        None | Some(IntOrStr::Null) => None,
        Some(IntOrStr::Int(i)) => Some(i),
        // atoi semantics: parse the leading integer, 0 on failure.
        Some(IntOrStr::Str(s)) => Some(s.trim().parse::<i64>().unwrap_or(0)),
    })
}
