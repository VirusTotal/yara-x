use array_bytes::bytes2hex;
use cms::cert::x509::{spki, Certificate};
use cms::content_info::CmsVersion;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use const_oid::db::{rfc5912, rfc6268};
use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::{Decode, Encode};
use der::{Sequence, SliceReader};
use protobuf::MessageField;
use sha1::digest::Output;
use sha1::{Digest, Sha1};

use crate::modules::protos;

/// OID for [`SpcIndirectDataContent`].
pub const SPC_INDIRECT_DATA_OBJID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.4");

pub const SPC_NESTED_SIGNATURE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.4.1");

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
pub enum AuthenticodeParseError {
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticodeParser {}

impl AuthenticodeParser {
    /// Parses Authenticode signatures from DER-encoded bytes.
    pub fn parse(
        bytes: &[u8],
    ) -> Result<Vec<AuthenticodeSignature>, AuthenticodeParseError> {
        // Use a reader rather than using `Decode::from_der`, because there may
        // be unused trailing data in `input`, which causes a `TrailingData`
        // error.
        let mut reader = SliceReader::new(bytes)
            .map_err(|_| AuthenticodeParseError::Empty)?;

        let content_info = ContentInfo::decode(&mut reader)
            .map_err(AuthenticodeParseError::InvalidContentInfo)?;

        if content_info.content_type != rfc6268::ID_SIGNED_DATA {
            return Err(AuthenticodeParseError::InvalidContentType(
                content_info.content_type,
            ));
        }

        let signed_data = content_info
            .content
            .decode_as::<SignedData>()
            .map_err(AuthenticodeParseError::InvalidSignedData)?;

        if signed_data.version != CmsVersion::V1 {
            return Err(AuthenticodeParseError::InvalidSignedDataVersion(
                signed_data.version,
            ));
        }

        // According to the specification, SignedData must contain exactly one
        // digest algorithm, and it must match the one specified in SignerInfo.
        if signed_data.digest_algorithms.len() != 1 {
            return Err(AuthenticodeParseError::InvalidNumDigestAlgorithms(
                signed_data.digest_algorithms.len(),
            ));
        }

        // Exactly one SignerInfo, as required by the specification.
        if signed_data.signer_infos.0.len() != 1 {
            return Err(AuthenticodeParseError::InvalidNumSignerInfo(
                signed_data.signer_infos.0.len(),
            ));
        }

        if signed_data.encap_content_info.econtent_type
            != SPC_INDIRECT_DATA_OBJID
        {
            return Err(
                AuthenticodeParseError::InvalidEncapsulatedContentType(
                    signed_data.encap_content_info.econtent_type,
                ),
            );
        }

        let indirect_data = signed_data
            .encap_content_info
            .econtent
            .as_ref()
            .ok_or(AuthenticodeParseError::EmptyEncapsulatedContent)?
            .decode_as::<SpcIndirectDataContent>()
            .map_err(AuthenticodeParseError::InvalidSpcIndirectDataContent)?;

        let signer_info = &signed_data.signer_infos.0.as_slice()[0];

        if signer_info.version != CmsVersion::V1 {
            return Err(AuthenticodeParseError::InvalidSignerInfoVersion(
                signer_info.version,
            ));
        }

        if signer_info.digest_alg
            != signed_data.digest_algorithms.as_slice()[0]
        {
            return Err(AuthenticodeParseError::AlgorithmMismatch);
        }

        let signed_attrs = if let Some(signed_attrs) =
            &signer_info.signed_attrs
        {
            signed_attrs
        } else {
            return Err(AuthenticodeParseError::EmptyAuthenticatedAttributes);
        };

        // The contentType attribute must be present.
        if !signed_attrs
            .iter()
            .any(|attr| attr.oid == rfc6268::ID_CONTENT_TYPE)
        {
            return Err(AuthenticodeParseError::MissingContentTypeAuthenticatedAttribute);
        }

        // The messageDigest attribute must be present.
        let signer_info_digest = if let Some(digest_attr) = signed_attrs
            .iter()
            .find(|attr| attr.oid == rfc6268::ID_MESSAGE_DIGEST)
        {
            digest_attr.values.as_slice()[0].value()
        } else {
            return Err(AuthenticodeParseError::MissingMessageDigestAuthenticatedAttribute);
        };

        // An Authenticode signature can contain nested signatures in
        // an unsigned attribute with OID 1.3.6.1.4.1.311.2.4.1.
        let mut nested_signatures = Vec::new();

        if let Some(attrs) = &signer_info.unsigned_attrs {
            for attr in attrs.iter() {
                if attr.oid == SPC_NESTED_SIGNATURE {
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
                    }
                }
            }
        }

        let mut signatures = Vec::with_capacity(nested_signatures.len() + 1);

        signatures.push(AuthenticodeSignature {
            signer_info_digest: bytes2hex("", signer_info_digest),
            signed_data,
            indirect_data,
        });

        signatures.append(&mut nested_signatures);

        Ok(signatures)
    }
}

pub struct AuthenticodeSignature {
    signer_info_digest: String,
    signed_data: SignedData,
    indirect_data: SpcIndirectDataContent,
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

    /// Get the certificate chain.
    pub fn certificates(&self) -> impl Iterator<Item = &Certificate> {
        self.signed_data.certificates.as_ref().unwrap().0.iter().map(|cert| {
            if let cms::cert::CertificateChoices::Certificate(cert) = cert {
                cert
            } else {
                panic!()
            }
        })
    }

    /// Returns the certificate chain for this signature.
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

impl From<&Certificate> for protos::pe::Certificate {
    fn from(value: &Certificate) -> Self {
        let mut cert = protos::pe::Certificate::new();
        // Versions are 0-based, add 1 for getting the actual version.
        cert.set_version(value.tbs_certificate.version as i64 + 1);

        // TODO:
        // /C=ZA/ST=Western Cape/L=Durbanville/O=Thawte/OU=Thawte Certification/CN=Thawte Timestamping CA
        // CN=Thawte Timestamping CA,OU=Thawte Certification,O=Thawte,L=Durbanville,ST=Western Cape,C=ZA
        cert.set_issuer(format!("{}", value.tbs_certificate.issuer));
        cert.set_subject(format!("{}", value.tbs_certificate.subject));

        // TODO: to lower
        cert.set_serial(format!("{}", value.tbs_certificate.serial_number));

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
