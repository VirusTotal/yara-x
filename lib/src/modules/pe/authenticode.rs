use std::fmt::Write;

use array_bytes::bytes2hex;
use cms::attr::{Countersignature, SigningTime};
use cms::cert::x509::{spki, Certificate};
use cms::content_info::CmsVersion;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use const_oid::db::{rfc5911, rfc5912, rfc6268};
use const_oid::ObjectIdentifier;
use der::asn1::{OctetString, UtcTime};
use der::{Decode, Encode};
use der::{Sequence, SliceReader};
use protobuf::MessageField;
use sha1::digest::Output;
use sha1::{Digest, Sha1};
use x509_tsp::TstInfo;

use crate::modules::protos;

/// OID for [`SpcIndirectDataContent`].
pub const SPC_INDIRECT_DATA_OBJID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.4");

pub const SPC_MS_NESTED_SIGNATURE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.4.1");

pub const SPC_MS_COUNTERSIGN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.3.1");

/// Authenticode ASN.1 image and digest data.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcIndirectDataContent {
    /// Image data.
    pub data: SpcAttributeTypeAndOptionalValue,

    /// Authenticode digest.
    pub message_digest: DigestInfo,
}

/// Authenticode ASN.1 image data.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcAttributeTypeAndOptionalValue {
    /// Type of data stored in the `value` field.
    pub value_type: ObjectIdentifier,

    /// Image data.
    //TODO(nicholasbishop): implement SpcPeImageData.
    pub value: der::Any,
}

/// Authenticode ASN.1 digest data.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct DigestInfo {
    /// Authenticode digest algorithm.
    pub digest_algorithm: spki::AlgorithmIdentifierOwned,

    /// Authenticode digest.
    pub digest: OctetString,
}

/// Error returned by [`AuthenticodeParser::parse`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// The signature data is empty.
    Empty,

    /// The signature data is not valid [`ContentInfo`].
    InvalidContentInfo(der::Error),

    /// The content type does not match [`rfc6268::ID_SIGNED_DATA`].
    InvalidContentType(ObjectIdentifier),

    /// The content info is not valid [`SignedData`].
    InvalidSignedData(der::Error),

    /// The version of [`SignedData`] is not 1.
    InvalidSignedDataVersion(CmsVersion),

    /// The number of digest algorithms is not 1.
    InvalidNumDigestAlgorithms(usize),

    /// The encapsulated content type does not match [`SPC_INDIRECT_DATA_OBJID`].
    InvalidEncapsulatedContentType(ObjectIdentifier),

    /// The encapsulated content is empty.
    EmptyEncapsulatedContent,

    /// The encapsulated content is not valid [`SpcIndirectDataContent`].
    InvalidSpcIndirectDataContent(der::Error),

    /// The number of signer infos is not 1.
    InvalidNumSignerInfo(usize),

    /// The version of [`SignerInfo`] is not 1.
    InvalidSignerInfoVersion(CmsVersion),

    /// The digest algorithm is not internally consistent.
    AlgorithmMismatch,

    /// No authenticated attributes are present.
    EmptyAuthenticatedAttributes,

    /// The `contentType` authenticated attribute is missing.
    MissingContentTypeAuthenticatedAttribute,

    /// The `messageDigest` authenticated attribute is missing.
    MissingMessageDigestAuthenticatedAttribute,
}

/// Parses Authenticode signatures in a PE file.
///
/// Some resources for understanding Authenticode signatures:
/// https://blog.trailofbits.com/2020/05/27/verifying-windows-binaries-without-windows/
/// https://docs.clamav.net/appendix/Authenticode.html
/// https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticodeParser {}

impl AuthenticodeParser {
    /// Parses Authenticode signatures from DER-encoded bytes.
    pub fn parse(
        bytes: &[u8],
    ) -> Result<Vec<AuthenticodeSignature>, ParseError> {
        // Use a reader rather than using `Decode::from_der`, because there may
        // be unused trailing data in `input`, which causes a `TrailingData`
        // error.
        let mut reader =
            SliceReader::new(bytes).map_err(|_| ParseError::Empty)?;

        let content_info = ContentInfo::decode(&mut reader)
            .map_err(ParseError::InvalidContentInfo)?;

        if content_info.content_type != rfc6268::ID_SIGNED_DATA {
            return Err(ParseError::InvalidContentType(
                content_info.content_type,
            ));
        }

        let signed_data = content_info
            .content
            .decode_as::<SignedData>()
            .map_err(ParseError::InvalidSignedData)?;

        if signed_data.version != CmsVersion::V1 {
            return Err(ParseError::InvalidSignedDataVersion(
                signed_data.version,
            ));
        }

        // According to the specification, SignedData must contain exactly one
        // digest algorithm, and it must match the one specified in SignerInfo.
        if signed_data.digest_algorithms.len() != 1 {
            return Err(ParseError::InvalidNumDigestAlgorithms(
                signed_data.digest_algorithms.len(),
            ));
        }

        // Exactly one SignerInfo, as required by the specification.
        if signed_data.signer_infos.0.len() != 1 {
            return Err(ParseError::InvalidNumSignerInfo(
                signed_data.signer_infos.0.len(),
            ));
        }

        if signed_data.encap_content_info.econtent_type
            != SPC_INDIRECT_DATA_OBJID
        {
            return Err(ParseError::InvalidEncapsulatedContentType(
                signed_data.encap_content_info.econtent_type,
            ));
        }

        let indirect_data = signed_data
            .encap_content_info
            .econtent
            .as_ref()
            .ok_or(ParseError::EmptyEncapsulatedContent)?
            .decode_as::<SpcIndirectDataContent>()
            .map_err(ParseError::InvalidSpcIndirectDataContent)?;

        let signer_info = &signed_data.signer_infos.0.as_slice()[0];

        if signer_info.version != CmsVersion::V1 {
            return Err(ParseError::InvalidSignerInfoVersion(
                signer_info.version,
            ));
        }

        if signer_info.digest_alg
            != signed_data.digest_algorithms.as_slice()[0]
        {
            return Err(ParseError::AlgorithmMismatch);
        }

        let signed_attrs =
            if let Some(signed_attrs) = &signer_info.signed_attrs {
                signed_attrs
            } else {
                return Err(ParseError::EmptyAuthenticatedAttributes);
            };

        // The contentType attribute must be present.
        if !signed_attrs
            .iter()
            .any(|attr| attr.oid == rfc6268::ID_CONTENT_TYPE)
        {
            return Err(ParseError::MissingContentTypeAuthenticatedAttribute);
        }

        // The messageDigest attribute must be present.
        let signer_info_digest = if let Some(digest_attr) = signed_attrs
            .iter()
            .find(|attr| attr.oid == rfc6268::ID_MESSAGE_DIGEST)
        {
            digest_attr.values.as_slice()[0].value()
        } else {
            return Err(
                ParseError::MissingMessageDigestAuthenticatedAttribute,
            );
        };

        let mut nested_signatures = Vec::new();
        let mut countersignatures = Vec::new();

        if let Some(attrs) = &signer_info.unsigned_attrs {
            for attr in attrs.iter() {
                match attr.oid {
                    // An Authenticode signature can contain nested signatures in
                    // an unsigned attribute with OID 1.3.6.1.4.1.311.2.4.1.
                    SPC_MS_NESTED_SIGNATURE => {
                        // TODO: can we do this without having to use encode_to_vec?
                        let mut raw = Vec::new();
                        if attr.values.as_slice()[0]
                            .encode_to_vec(&mut raw)
                            .is_ok()
                        {
                            if let Ok(signatures) =
                                AuthenticodeParser::parse(raw.as_slice())
                            {
                                nested_signatures.extend(signatures);
                            }
                        };
                    }
                    SPC_MS_COUNTERSIGN => {
                        for value in attr.values.iter() {
                            if let Ok(signed_data) = value
                                .decode_as::<ContentInfo>()
                                .and_then(|content_info| {
                                    content_info
                                        .content
                                        .decode_as::<SignedData>()
                                })
                            {
                                countersignatures.push(
                                    Self::pkcs9_countersignature(
                                        signed_data
                                            .signer_infos
                                            .as_ref()
                                            .get(0)
                                            .unwrap(),
                                    ),
                                );
                            }
                        }
                    }
                    rfc5911::ID_COUNTERSIGNATURE => {
                        for value in attr.values.iter() {
                            if let Ok(cs) =
                                value.decode_as::<Countersignature>().as_ref()
                            {
                                countersignatures
                                    .push(Self::pkcs9_countersignature(cs));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut signatures = Vec::with_capacity(nested_signatures.len() + 1);

        signatures.push(AuthenticodeSignature {
            signer_info_digest: bytes2hex("", signer_info_digest),
            signed_data,
            indirect_data,
            countersignatures,
        });

        signatures.append(&mut nested_signatures);

        Ok(signatures)
    }

    fn pkcs9_countersignature(
        cs: &Countersignature,
    ) -> AuthenticodeCountersign {
        let mut digest = None;
        let mut signing_time = None;

        if let Some(signed_attrs) = &cs.signed_attrs {
            for attr in signed_attrs.iter() {
                match attr.oid {
                    rfc6268::ID_MESSAGE_DIGEST => {
                        if let Some(value) = attr.values.get(0) {
                            digest = Some(bytes2hex("", value.value()));
                        }
                    }
                    rfc6268::ID_SIGNING_TIME => {
                        if let Some(value) = attr.values.get(0) {
                            signing_time = value.decode_as::<UtcTime>().ok();
                        }
                    }
                    _ => {}
                }
            }
        }

        AuthenticodeCountersign {
            digest_alg: oid_to_algorithm_name(&cs.digest_alg.oid),
            digest,
            signing_time,
        }
    }
}

pub struct AuthenticodeCountersign {
    digest_alg: &'static str,
    digest: Option<String>,
    signing_time: Option<UtcTime>,
}

pub struct AuthenticodeSignature {
    signer_info_digest: String,
    signed_data: SignedData,
    indirect_data: SpcIndirectDataContent,
    countersignatures: Vec<AuthenticodeCountersign>,
}

impl AuthenticodeSignature {
    /// Get the authenticode digest stored in the signature.
    pub fn digest(&self) -> String {
        bytes2hex("", self.indirect_data.message_digest.digest.as_bytes())
    }

    /// Get the name of the digest algorithm.
    pub fn digest_alg(&self) -> String {
        oid_to_algorithm_name(
            &self.indirect_data.message_digest.digest_algorithm.oid,
        )
        .to_string()
    }

    /// Get [`SignerInfo`].
    pub fn signer_info(&self) -> &SignerInfo {
        // The constructor validates that exactly one signer info is
        // present, so this won't panic.
        &self.signed_data.signer_infos.0.as_slice()[0]
    }

    pub fn signer_info_digest_alg(&self) -> String {
        oid_to_algorithm_name(&self.signer_info().digest_alg.oid).to_string()
    }

    pub fn signer_info_digest(&self) -> String {
        self.signer_info_digest.clone()
    }

    pub fn certificates(&self) -> impl Iterator<Item = &Certificate> {
        self.signed_data.certificates.as_ref().unwrap().0.iter().map(|cert| {
            if let cms::cert::CertificateChoices::Certificate(cert) = cert {
                cert
            } else {
                panic!()
            }
        })
    }

    pub fn countersignatures(
        &self,
    ) -> impl Iterator<Item = &AuthenticodeCountersign> {
        self.countersignatures.iter()
    }

    pub fn chain(&self) -> Vec<&Certificate> {
        if let SignerIdentifier::IssuerAndSerialNumber(signer) =
            &self.signer_info().sid
        {
            self.build_chain(signer)
        } else {
            unreachable!()
        }
    }
}

impl AuthenticodeSignature {
    /// Returns a certificate chain containing the certificate with the given
    /// issuer and serial number, and all the certificates participating in the
    /// chain of trust for that certificate, up to the highest level certificate
    /// found in the Authenticode signature.
    ///
    /// The first item in the vector is the requested certificate, and the
    /// highest level certificate in the chain is the last one.
    fn build_chain(
        &self,
        issuer_and_serial_number: &cms::cert::IssuerAndSerialNumber,
    ) -> Vec<&Certificate> {
        let mut chain = vec![];

        let mut current = match self.certificates().find(|cert| {
            cert.tbs_certificate.serial_number
                == issuer_and_serial_number.serial_number
        }) {
            Some(current) => current,
            None => return vec![],
        };

        chain.push(current);

        while let Some(cert) = self.certificates().find(|cert| {
            cert.tbs_certificate.subject == current.tbs_certificate.issuer
        }) {
            chain.push(cert);
            current = cert;
        }

        chain
    }
}

impl From<&AuthenticodeSignature> for protos::pe::Signature {
    fn from(value: &AuthenticodeSignature) -> Self {
        let mut sig = protos::pe::Signature::new();

        sig.set_digest(value.digest());
        sig.set_digest_alg(value.digest_alg());

        sig.certificates
            .extend(value.certificates().map(protos::pe::Certificate::from));

        sig.countersignatures.extend(
            value.countersignatures().map(protos::pe::CounterSignature::from),
        );

        let mut signer_info = protos::pe::SignerInfo::new();

        signer_info.set_digest_alg(value.signer_info_digest_alg());
        signer_info.set_digest(value.signer_info_digest());

        signer_info.chain.extend(
            value.chain().into_iter().map(protos::pe::Certificate::from),
        );

        sig.signer_info = MessageField::from(Some(signer_info));

        // Some fields from the first certificate in the chain are replicated
        // in the `pe::Signature` structure for backward compatibility. The
        // `chain` field in `SignerInfo` didn't exist in previous versions of
        // YARA.
        if let Some(signer_info) = sig.signer_info.as_ref() {
            if let Some(cert) = signer_info.chain.first() {
                sig.version = cert.version;
                sig.thumbprint = cert.thumbprint.clone();
                sig.issuer = cert.issuer.clone();
                sig.subject = cert.subject.clone();
                sig.serial = cert.serial.clone();
                sig.not_after = cert.not_after;
                sig.not_before = cert.not_before;
                sig.algorithm = cert.algorithm.clone();
                sig.algorithm_oid = cert.algorithm_oid.clone();
            }
        }

        sig
    }
}

impl From<&AuthenticodeCountersign> for protos::pe::CounterSignature {
    fn from(value: &AuthenticodeCountersign) -> Self {
        let mut cs = protos::pe::CounterSignature::new();

        cs.digest = value.digest.clone();
        cs.set_digest_alg(value.digest_alg.to_string());

        /*cs.set_verified(
            value
                .verify_flags()
                .is_some_and(|flags| flags == CounterSignatureVerify::Valid),
        );*/

        cs.sign_time =
            value.signing_time.map(|t| t.to_unix_duration().as_secs() as i64);

        /*cs.chain.extend(
            value
                .certificate_chain()
                .iter()
                .map(protos::pe::Certificate::from),
        );*/

        cs
    }
}

impl From<&Certificate> for protos::pe::Certificate {
    fn from(value: &Certificate) -> Self {
        let mut cert = protos::pe::Certificate::new();
        // Versions are 0-based, add 1 for getting the actual version.
        cert.set_version(value.tbs_certificate.version as i64 + 1);

        cert.set_issuer(format_name(&value.tbs_certificate.issuer));
        cert.set_subject(format_name(&value.tbs_certificate.subject));

        cert.set_serial(format_serial_number(
            &value.tbs_certificate.serial_number,
        ));

        cert.set_algorithm_oid(format!("{}", value.signature_algorithm.oid));
        cert.set_algorithm(
            oid_to_algorithm_name(&value.signature_algorithm.oid).to_string(),
        );

        // The certificate thumbprint is the SHA1 of the DER-encoded certificate.
        let mut hasher = Sha1Hasher::new();
        value.encode(&mut hasher).unwrap();
        cert.set_thumbprint(format!("{:x}", hasher.finalize()));

        if let Ok(time) = value
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs()
            .try_into()
        {
            cert.set_not_before(time);
        }

        if let Ok(time) = value
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs()
            .try_into()
        {
            cert.set_not_after(time);
        }

        cert
    }
}

/// Produces a printable string for a x509 name.
///
/// The [`x509_cert::name::Name`] type implements the [`std::fmt::Display`]
/// trait, but the resulting string follows the [RFC 4514], resulting in
/// something like:
///
/// ```text
/// CN=Thawte Timestamping CA,OU=Thawte Certification,O=Thawte,L=Durbanville,ST=Western Cape,C=ZA
/// ```
///
/// However, the format traditionally used by YARA is inherited from OpenSSL and looks like:
///
/// ```text
/// /C=ZA/ST=Western Cape/L=Durbanville/O=Thawte/OU=Thawte Certification/CN=Thawte Timestamping CA
/// ```
///
/// [RFC 4514]: https://datatracker.ietf.org/doc/html/rfc4514
fn format_name(name: &x509_cert::name::Name) -> String {
    let mut result = String::new();
    for s in &name.0 {
        write!(result, "/{}", s).unwrap();
    }
    result
}

/// Produces a printable string of a serial number.
///
/// The [`x509_cert::serial_number::SerialNumber`] type implements the
/// [`std::fmt::Display`] trait, but the resulting string is in uppercase.
fn format_serial_number(
    sn: &x509_cert::serial_number::SerialNumber,
) -> String {
    let mut iter = sn.as_bytes().iter().peekable();
    let mut result = String::new();
    while let Some(byte) = iter.next() {
        match iter.peek() {
            Some(_) => write!(result, "{:02x}:", byte).unwrap(),
            None => write!(result, "{:02x}", byte).unwrap(),
        }
    }
    result
}

/// Given an OID that represents an algorithm name, returns a string
/// that identifies the algorithm.
///
/// # Panics
///
/// If the OID doesn't correspond to some of the supported algorithm
/// names.
fn oid_to_algorithm_name(oid: &ObjectIdentifier) -> &'static str {
    if oid == &rfc5912::ID_SHA_1 {
        "sha1"
    } else if oid == &rfc5912::ID_SHA_256 {
        "sha256"
    } else if oid == &rfc5912::ID_MD_5 {
        "md5"
    } else if oid == &rfc5912::SHA_1_WITH_RSA_ENCRYPTION {
        "sha1WithRSAEncryption"
    } else if oid == &rfc5912::SHA_256_WITH_RSA_ENCRYPTION {
        "sha256WithRSAEncryption"
    } else {
        unreachable!()
    }
}

struct Sha1Hasher {
    hasher: Sha1,
}

impl Sha1Hasher {
    pub fn new() -> Self {
        Self { hasher: Sha1::new() }
    }
    pub fn finalize(self) -> Output<Sha1> {
        self.hasher.finalize()
    }
}

impl der::Writer for Sha1Hasher {
    fn write(&mut self, slice: &[u8]) -> der::Result<()> {
        self.hasher.update(slice);
        Ok(())
    }
}
