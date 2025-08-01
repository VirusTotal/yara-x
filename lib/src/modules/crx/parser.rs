use std::collections::HashMap;
use std::fmt::Write;
use std::io::{Cursor, Read, Seek};

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use const_oid::db::rfc5912;
use const_oid::db::rfc5912::SHA_1_WITH_RSA_ENCRYPTION;
use const_oid::{AssociatedOid, ObjectIdentifier};
use nom::bytes::take;
use nom::multi::length_data;
use nom::number::complete::be_u32;
use nom::number::complete::le_u32;
use nom::Parser;
use protobuf::Message;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use strum_macros::Display;
use zip::result::ZipResult;
use zip::ZipArchive;

use crate::mods::crx::{
    AsymmetricKeyProof, CrxFileHeader, CrxSignature, SignedData,
};
use crate::modules::protos;
use crate::modules::utils::crypto::PublicKey;

type NomError<'a> = nom::error::Error<&'a [u8]>;

#[derive(Display)]
pub enum Error<'a> {
    InvalidCrx,
    Parse(nom::Err<NomError<'a>>),
}

impl<'a> From<nom::Err<NomError<'a>>> for Error<'a> {
    fn from(value: nom::Err<nom::error::Error<&'a [u8]>>) -> Self {
        Self::Parse(value)
    }
}

/// A Chrome extension (CRX) parser.
///
/// Parses both CRX2 and CRX3 files. These are actually ZIP files with a special
/// header that contains one or more signatures for validating the extension.
///
/// The CRX2 format goes as follows:
///
/// [4 bytes] : "Cr24", a magic number.
/// [4 bytes] : Version of the CRX file format used (2).
/// [4 bytes] : N, little-endian, length of the public key.
/// [4 bytes] : M, little-endian, length of the signature.
/// [N bytes] : Public key.
/// [M bytes] : Signature.
/// [rest]    : The ZIP archive.
///
/// The CRX3 format is similar to CRX2, but instead of single public key and
/// signature, it can contain multiple ones. The signatures are stored in a
/// CrxFileHeader protobuf.
///
/// [4 bytes] : "Cr24", a magic number.
/// [4 bytes] : Version of the CRX file format used (3).
/// [4 bytes] : N, little-endian, length of the header.
/// [N bytes] : Header data (the binary encoding of a CrxFileHeader protobuf).
/// [rest]    : The ZIP archive.
#[derive(Default)]
pub struct Crx<'a> {
    crx_id: String,
    crx_version: u32,
    header_size: u32,
    manifest: Option<CrxManifest>,
    signatures: Vec<CrxSignature>,
    locale: Option<CrxLocale>,
    zip_data: &'a [u8],
}

#[derive(serde::Deserialize, Debug)]
struct CrxManifest {
    version: Option<String>,
    name: Option<String>,
    description: Option<String>,
    minimum_chrome_version: Option<String>,
    homepage_url: Option<String>,
    default_locale: Option<String>,
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default)]
    host_permissions: Vec<String>,
    #[serde(default)]
    optional_permissions: Vec<String>,
    #[serde(default)]
    optional_host_permissions: Vec<String>,
}

#[derive(serde::Deserialize, Debug)]
struct CrxLocaleEntry {
    message: String,
}

#[derive(serde::Deserialize, Debug)]
struct CrxLocale(HashMap<String, CrxLocaleEntry>);

impl CrxLocale {
    pub fn resolve(&self, msg: &str) -> Option<&str> {
        let key = msg.strip_prefix("__MSG_")?.strip_suffix("__")?;
        self.0.get(key).map(|entry| entry.message.as_str())
    }
}

impl<'a> Crx<'a> {
    const MAGIC: u32 = 0x43723234; // Cr24
    pub fn parse(data: &'a [u8]) -> Result<Self, Error<'a>> {
        let (remainder, (magic, version)) = (be_u32, le_u32).parse(data)?;

        if magic != Self::MAGIC {
            return Err(Error::InvalidCrx);
        }

        match version {
            2 => Self::parse_v2(remainder),
            3 => Self::parse_v3(remainder),
            _ => Err(Error::InvalidCrx),
        }
    }

    fn parse_v2(data: &'a [u8]) -> Result<Self, Error<'a>> {
        let (remainder, (key_len, signature_len)) =
            (le_u32, le_u32).parse(data)?;

        let (remainder, key) = take(key_len).parse(remainder)?;
        let (zip_data, signature) = take(signature_len).parse(remainder)?;

        let mut zip =
            Self::read_zip(zip_data).map_err(|_| Error::InvalidCrx)?;

        let manifest = Self::read_manifest(&mut zip);

        let verified = PublicKey::from_der(SHA_1_WITH_RSA_ENCRYPTION, key)
            .is_ok_and(|key| {
                Self::verify_v2::<Sha1>(zip_data, &key, signature)
            });

        let signatures = vec![CrxSignature {
            key: Some(BASE64_STANDARD.encode(key)),
            verified: Some(verified),
            ..Default::default()
        }];

        // The extension ID consists on the first 16 bytes of the SHA-256
        // of the public key. These bytes are converted to a printable string
        // by `printable_extension_id`.
        let mut sha256 = Sha256::new();
        sha256.update(key);
        let digest = sha256.finalize();
        let crx_id = Self::printable_extension_id(&digest.as_slice()[0..16]);

        // Read the `default_locale` field from the manifest, or use "en" as
        // the default locale language.
        let locale_lang = manifest
            .as_ref()
            .and_then(|m| m.default_locale.as_deref())
            .unwrap_or("en");

        let locale = Self::read_locale(&mut zip, locale_lang);

        Ok(Crx {
            crx_version: 2,
            header_size: key_len + signature_len,
            crx_id,
            manifest,
            signatures,
            locale,
            zip_data,
        })
    }

    fn parse_v3(data: &'a [u8]) -> Result<Self, Error<'a>> {
        let (zip_data, header_data) = length_data(le_u32).parse(data)?;

        // The header is CrxFileHeader protobuf.
        let header = CrxFileHeader::parse_from_bytes(header_data)
            .map_err(|_| Error::InvalidCrx)?;

        let signed_header_data = match &header.signed_header_data {
            Some(data) => data.as_slice(),
            None => return Err(Error::InvalidCrx),
        };

        let signed_data = SignedData::parse_from_bytes(signed_header_data)
            .map_err(|_| Error::InvalidCrx)?;

        let mut signatures = Vec::new();

        signatures.extend(header.sha256_with_rsa.iter().filter_map(|proof| {
            Self::parse_proof(
                rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
                proof,
                signed_header_data,
                zip_data,
            )
        }));

        signatures.extend(header.sha256_with_ecdsa.iter().filter_map(
            |proof| {
                Self::parse_proof(
                    rfc5912::ECDSA_WITH_SHA_256,
                    proof,
                    signed_header_data,
                    zip_data,
                )
            },
        ));

        let crx_id = Self::printable_extension_id(signed_data.crx_id());

        let mut zip =
            Self::read_zip(zip_data).map_err(|_| Error::InvalidCrx)?;

        let manifest = Self::read_manifest(&mut zip);

        // Read the `default_locale` field from the manifest, or use "en" as
        // the default locale language.
        let locale_lang = manifest
            .as_ref()
            .and_then(|m| m.default_locale.as_deref())
            .unwrap_or("en");

        let locale = Self::read_locale(&mut zip, locale_lang);

        Ok(Crx {
            crx_version: 3,
            header_size: header_data.len() as u32,
            crx_id,
            manifest,
            signatures,
            locale,
            zip_data,
        })
    }

    fn parse_proof(
        algorithm: ObjectIdentifier,
        proof: &AsymmetricKeyProof,
        signed_header_data: &[u8],
        zip_data: &[u8],
    ) -> Option<CrxSignature> {
        let public_key_data = proof.public_key.as_ref()?.as_slice();
        let signature = proof.signature.as_ref()?.as_slice();

        let verified = PublicKey::from_der(algorithm, public_key_data)
            .is_ok_and(|key| {
                Self::verify_v3::<Sha256>(
                    signed_header_data,
                    zip_data,
                    &key,
                    signature,
                )
            });

        let mut signature = CrxSignature::new();

        signature.set_key(BASE64_STANDARD.encode(public_key_data));
        signature.set_verified(verified);

        Some(signature)
    }

    fn read_zip(zip_data: &[u8]) -> ZipResult<ZipArchive<Cursor<&[u8]>>> {
        zip::ZipArchive::new(Cursor::new(zip_data))
    }

    fn read_manifest<R: Read + Seek>(
        zip: &mut ZipArchive<R>,
    ) -> Option<CrxManifest> {
        let manifest = zip.by_name("manifest.json").ok()?;
        serde_json::from_reader::<_, CrxManifest>(manifest).ok()
    }

    fn read_locale<R: Read + Seek>(
        zip: &mut ZipArchive<R>,
        lang: &str,
    ) -> Option<CrxLocale> {
        let index =
            zip.index_for_path(format!("_locales/{lang}/messages.json"))?;
        let locale = zip.by_index(index).ok()?;
        serde_json::from_reader::<_, CrxLocale>(locale).ok()
    }

    fn verify_v2<D: Digest + AssociatedOid>(
        zip_data: &[u8],
        public_key: &PublicKey,
        signature: &[u8],
    ) -> bool {
        let mut digest = D::new();
        digest.update(zip_data);
        public_key.verify_digest::<D>(digest.finalize(), signature)
    }

    fn verify_v3<D: Digest + AssociatedOid>(
        signed_header_data: &[u8],
        zip_data: &[u8],
        public_key: &PublicKey,
        signature: &[u8],
    ) -> bool {
        let signed_header_size = signed_header_data.len() as u32;
        let mut digest = D::new();
        digest.update(b"CRX3 SignedData\x00");
        digest.update(signed_header_size.to_le_bytes());
        digest.update(signed_header_data);
        digest.update(zip_data);
        public_key.verify_digest::<D>(digest.finalize(), signature)
    }

    /// Converts a Chrome extension ID from binary form to a printable string.
    ///
    /// Chrome extension IDs are exactly 16 bytes long, but they are displayed
    /// as 32 lowercase characters in the 'a'-'p' range. These characters are
    /// the result of encoding the 16 bytes as hex, and then transposing the
    /// characters from the '0'-'f' range to the 'a'-'p' range, avoiding
    /// decimal digits.
    pub fn printable_extension_id(raw_id: &[u8]) -> String {
        let mut id = String::with_capacity(raw_id.len() * 2);

        for &b in raw_id {
            write!(id, "{:02x}", b).unwrap();
        }

        id.chars()
            .map(|c| {
                let hex_digit = c.to_digit(16).unwrap_or(0);
                let c = (hex_digit + 10) as u8 + b'a' - 10;
                c as char
            })
            .collect()
    }
}

impl From<Crx<'_>> for protos::crx::Crx {
    fn from(crx: Crx) -> Self {
        let mut result = protos::crx::Crx::new();

        result.set_is_crx(true);
        result.set_crx_version(crx.crx_version);
        result.set_id(crx.crx_id);
        result.signatures = crx.signatures;

        if let Some(manifest) = crx.manifest {
            if let Some(locale) = crx.locale {
                result.name = manifest
                    .name
                    .as_deref()
                    .and_then(|name| locale.resolve(name))
                    .or_else(|| manifest.name.as_deref())
                    .map(|s| s.to_owned());
                result.description = manifest
                    .description
                    .as_deref()
                    .and_then(|name| locale.resolve(name))
                    .or_else(|| manifest.description.as_deref())
                    .map(|s| s.to_owned());
                result.raw_name = manifest.name;
                result.raw_description = manifest.description;
            } else {
                result.name = manifest.name;
                result.description = manifest.description;
            }
            result.version = manifest.version;
            result.minimum_chrome_version = manifest.minimum_chrome_version;
            result.homepage_url = manifest.homepage_url;
            result.permissions = manifest.permissions;
            result.host_permissions = manifest.host_permissions;
            result.optional_permissions = manifest.optional_permissions;
            result.optional_host_permissions =
                manifest.optional_host_permissions;
        };

        result
    }
}
