use std::borrow::Cow;
use std::fmt::{Display, Write};

use crate::modules::pe::parser::PE;
use array_bytes::bytes2hex;
use cms::attr::Countersignature;
use cms::cert::x509::{spki, Certificate};
use cms::cert::IssuerAndSerialNumber;
use cms::content_info::CmsVersion;
use cms::content_info::ContentInfo;
use cms::signed_data::{
    CertificateSet, SignedData, SignerIdentifier, SignerInfo,
};
use const_oid::db::{rfc4519, rfc5911, rfc5912, rfc6268, DB};
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1;
use der::asn1::OctetString;
use der::referenced::OwnedToRef;
use der::{Choice, Sequence, SliceReader};
use der::{Decode, Encode, Tag, Tagged};
use digest::Digest;
use ecdsa::signature::hazmat::PrehashVerifier;
use itertools::Itertools;
use md5::Md5;
use protobuf::MessageField;
use rsa::traits::SignatureScheme;
use rsa::Pkcs1v15Sign;
use sha1::digest::Output;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoRef};
use x509_tsp::TstInfo;
use x509_verify::{VerifyInfo, VerifyingKey};

use crate::modules::protos;

/// OID for [`SpcIndirectDataContent`].
pub const SPC_INDIRECT_DATA_OBJID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.4");

/// OID for [`SpcSpOpusInfo`].
pub const SPC_SP_OPUS_INFO_OBJID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.12");

pub const SPC_MS_NESTED_SIGNATURE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.4.1");

pub const SPC_MS_COUNTERSIGN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.3.1");

pub const JURISDICTION_L: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.60.2.1.1");

pub const JURISDICTION_ST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.60.2.1.2");

pub const JURISDICTION_C: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.60.2.1.3");

/// Similar to 1.2.840.113549.1.1.5. Obsolete, but still present in some files
/// like: 111aeddc6a6dbf64b28cb565aa12af9ee3cc0a56ce31e4da0068cf6b474c3288
pub const SHA1_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.14.3.2.29");

/// ASN.1 SpcIndirectDataContent
///
/// SpcIndirectDataContent ::= SEQUENCE {
///     data                    SpcAttributeTypeAndOptionalValue,
///     messageDigest           DigestInfo
/// }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcIndirectDataContent {
    /// Image data.
    pub data: SpcAttributeTypeAndOptionalValue,

    /// Authenticode digest.
    pub message_digest: DigestInfo,
}

/// ASN.1 SpcAttributeTypeAndOptionalValue
///
/// SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
///     type                    ObjectID,
///     value                   [0] EXPLICIT ANY OPTIONAL
/// }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcAttributeTypeAndOptionalValue {
    /// Type of data stored in the `value` field.
    pub value_type: ObjectIdentifier,
    pub value: der::Any,
}

/// ASN.1 DigestInfo
///
/// DigestInfo ::= SEQUENCE {
///     digestAlgorithm         AlgorithmIdentifier,
///     digest                  OCTETSTRING
/// }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct DigestInfo {
    /// Authenticode digest algorithm.
    pub digest_algorithm: spki::AlgorithmIdentifierOwned,

    /// Authenticode digest.
    pub digest: OctetString,
}

/// ASN.1 SpcSpOpusInfo
///
/// SpcSpOpusInfo ::= SEQUENCE {
///     programName              [0] EXPLICIT SpcString OPTIONAL,
///     moreInfo                 [1] EXPLICIT SpcLink OPTIONAL,
/// }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcSpOpusInfo {
    #[asn1(context_specific = "0", optional = "true")]
    pub program_name: Option<SpcString>,
    #[asn1(context_specific = "1", optional = "true")]
    pub more_info: Option<SpcLink>,
}

/// ASN.1 SpcString
///
/// SpcString ::= CHOICE {
///     unicode                 [0] IMPLICIT BMPSTRING,
///     ascii                   [1] IMPLICIT IA5STRING
/// }
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum SpcString {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Unicode(asn1::BmpString),
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", type = "IA5String")]
    Ascii(asn1::Ia5String),
}

impl Display for SpcString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            SpcString::Unicode(unicode) => unicode.to_string(),
            SpcString::Ascii(ascii) => ascii.to_string(),
        };
        write!(f, "{}", str)
    }
}

/// ASN.1 SpcLink
///
/// SpcLink ::= CHOICE {
///     url                     [0] IMPLICIT IA5STRING,
///     moniker                 [1] IMPLICIT SpcSerializedObject,
///     file                    [2] EXPLICIT SpcString
/// }
///
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum SpcLink {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", type = "IA5String")]
    Url(asn1::Ia5String),
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
pub struct AuthenticodeParser {}

impl AuthenticodeParser {
    /// Parses Authenticode signatures from DER-encoded bytes.
    pub fn parse(
        input: &[u8],
        pe: &PE,
    ) -> Result<Vec<AuthenticodeSignature>, ParseError> {
        // Use a reader rather than using `Decode::from_der`, because
        // there may be unused trailing data in `input`, which causes a
        // `TrailingData` error.
        let mut reader =
            SliceReader::new(input).map_err(|_| ParseError::Empty)?;

        let content_info = ContentInfo::decode(&mut reader)
            .map_err(ParseError::InvalidContentInfo)?;

        if content_info.content_type == rfc6268::ID_SIGNED_DATA {
            Self::parse_content_info(content_info, pe)
        } else {
            Err(ParseError::InvalidContentType(content_info.content_type))
        }
    }

    fn parse_content_info(
        content_info: ContentInfo,
        pe: &PE,
    ) -> Result<Vec<AuthenticodeSignature>, ParseError> {
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

        // The content type attribute must be present.
        if !signed_attrs
            .iter()
            .any(|attr| attr.oid == rfc6268::ID_CONTENT_TYPE)
        {
            return Err(ParseError::MissingContentTypeAuthenticatedAttribute);
        }

        // Get the message digest attribute stored in `SignerInfo`, this is
        // the digest of `SignedData.EncapsulatedContentInfo.econtent`.
        let signer_info_digest = get_message_digest(signer_info)
            .ok_or(ParseError::MissingMessageDigestAuthenticatedAttribute)?;

        // Get the opus info attribute and decode it.
        let opus_info = signed_attrs
            .iter()
            .find(|attr| attr.oid == SPC_SP_OPUS_INFO_OBJID)
            .and_then(|attr| attr.values.get(0))
            .and_then(|value| value.decode_as::<SpcSpOpusInfo>().ok());

        // Get all the certificates contained in `SignedData`, more
        // certificates from nested signatures and countersignatures will
        // be added later to this vector.
        let mut certificates: Vec<Certificate> = signed_data
            .certificates
            .as_ref()
            .map(Self::certificate_set_to_iter)
            .unwrap()
            .cloned()
            .collect();

        let mut nested_signatures = Vec::new();
        let mut countersignatures = Vec::new();

        if let Some(attrs) = &signer_info.unsigned_attrs {
            for attr in attrs.iter() {
                match attr.oid {
                    // An Authenticode signature can contain nested signatures in
                    // an unsigned attribute with OID 1.3.6.1.4.1.311.2.4.1.
                    SPC_MS_NESTED_SIGNATURE => {
                        if let Some(signatures) = attr
                            .values
                            .get(0)
                            .and_then(|value| {
                                value.decode_as::<ContentInfo>().ok()
                            })
                            .and_then(|content_info| {
                                Self::parse_content_info(content_info, pe).ok()
                            })
                        {
                            nested_signatures.extend(signatures);
                        }
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
                                certificates.extend(
                                    signed_data
                                        .certificates
                                        .as_ref()
                                        .map(Self::certificate_set_to_iter)
                                        .unwrap()
                                        .cloned()
                                        .collect::<Vec<Certificate>>(),
                                );

                                let cs = signed_data
                                    .signer_infos
                                    .as_ref()
                                    .get(0)
                                    .unwrap();

                                let mut countersignature =
                                    Self::pkcs9_countersignature(cs);

                                let tst_info = signed_data
                                    .encap_content_info
                                    .econtent
                                    .and_then(|content| {
                                        content.decode_as::<OctetString>().ok()
                                    })
                                    .and_then(|octet_string| {
                                        TstInfo::from_der(
                                            octet_string.as_bytes(),
                                        )
                                        .ok()
                                    });

                                let tst_info = match tst_info {
                                    Some(tst_info) => tst_info,
                                    None => continue,
                                };

                                countersignature.digest_alg = oid_to_str(
                                    &tst_info
                                        .message_imprint
                                        .hash_algorithm
                                        .oid,
                                );

                                countersignature.digest = Some(bytes2hex(
                                    "",
                                    tst_info
                                        .message_imprint
                                        .hashed_message
                                        .as_bytes(),
                                ));

                                countersignature.verified =
                                    verify_message_digest(
                                        &tst_info
                                            .message_imprint
                                            .hash_algorithm,
                                        signer_info.signature.as_bytes(),
                                        tst_info
                                            .message_imprint
                                            .hashed_message
                                            .as_bytes(),
                                    ) && verify_signer_info(
                                        cs,
                                        certificates.as_slice(),
                                    );

                                countersignatures.push(countersignature);
                            }
                        }
                    }
                    rfc5911::ID_COUNTERSIGNATURE => {
                        for value in attr.values.iter() {
                            if let Ok(cs) =
                                value.decode_as::<Countersignature>().as_ref()
                            {
                                let mut countersignature =
                                    Self::pkcs9_countersignature(cs);

                                let message_digest =
                                    match get_message_digest(cs) {
                                        Some(digest) => digest,
                                        None => continue,
                                    };

                                countersignature.verified =
                                    verify_message_digest(
                                        &cs.digest_alg,
                                        signer_info.signature.as_bytes(),
                                        message_digest.as_bytes(),
                                    ) && verify_signer_info(
                                        cs,
                                        certificates.as_slice(),
                                    );

                                countersignatures.push(countersignature);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut signatures = Vec::with_capacity(nested_signatures.len() + 1);

        // Compute the Authenticode hash by ourselves. This hash will be
        // compared later with the one included in the PE file.
        let file_digest = match signer_info.digest_alg.oid {
            rfc5912::ID_SHA_1 => {
                let mut sha1 = Sha1::default();
                pe.authenticode_hash(&mut sha1);
                sha1.finalize().to_vec()
            }
            rfc5912::ID_SHA_256 => {
                let mut sha256 = Sha256::default();
                pe.authenticode_hash(&mut sha256);
                sha256.finalize().to_vec()
            }
            rfc5912::ID_SHA_384 => {
                let mut sha384 = Sha384::default();
                pe.authenticode_hash(&mut sha384);
                sha384.finalize().to_vec()
            }
            rfc5912::ID_SHA_512 => {
                let mut sha512 = Sha512::default();
                pe.authenticode_hash(&mut sha512);
                sha512.finalize().to_vec()
            }
            rfc5912::ID_MD_5 => {
                let mut md5 = Md5::default();
                pe.authenticode_hash(&mut md5);
                md5.finalize().to_vec()
            }
            oid => unimplemented!("{:?}", oid),
        };

        signatures.push(AuthenticodeSignature {
            program_name: opus_info.and_then(|oi| oi.program_name),
            signer_info_digest,
            signed_data,
            computed_authenticode_hash: file_digest,
            indirect_data,
            countersignatures,
            certificates,
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
                            signing_time =
                                value.decode_as::<asn1::UtcTime>().ok();
                        }
                    }
                    _ => {}
                }
            }
        }

        let signer = match &cs.sid {
            SignerIdentifier::IssuerAndSerialNumber(signer) => signer,
            _ => unreachable!(),
        };

        AuthenticodeCountersign {
            signer: signer.clone(),
            digest_alg: oid_to_str(&cs.digest_alg.oid),
            digest,
            signing_time,
            verified: false,
        }
    }

    fn certificate_set_to_iter(
        cs: &CertificateSet,
    ) -> impl Iterator<Item = &Certificate> {
        cs.0.iter().map(|cert| {
            if let cms::cert::CertificateChoices::Certificate(cert) = cert {
                cert
            } else {
                panic!()
            }
        })
    }
}

pub struct AuthenticodeCountersign {
    signer: IssuerAndSerialNumber,
    digest_alg: Cow<'static, str>,
    digest: Option<String>,
    signing_time: Option<asn1::UtcTime>,
    verified: bool,
}

pub struct AuthenticodeSignature {
    signer_info_digest: OctetString,
    indirect_data: SpcIndirectDataContent,
    signed_data: SignedData,
    certificates: Vec<Certificate>,
    countersignatures: Vec<AuthenticodeCountersign>,
    program_name: Option<SpcString>,
    computed_authenticode_hash: Vec<u8>,
}

impl AuthenticodeSignature {
    /// Get the Authenticode hash stored in the PE file.
    #[inline]
    pub fn stored_authenticode_hash(&self) -> &[u8] {
        self.indirect_data.message_digest.digest.as_bytes()
    }

    /// Get the Authenticode hash computed by ourselves.
    #[inline]
    pub fn computed_authenticode_hash(&self) -> &[u8] {
        self.computed_authenticode_hash.as_slice()
    }

    /// Get the name of the Authenticode hash algorithm.
    pub fn authenticode_hash_algorithm(&self) -> Cow<'static, str> {
        oid_to_str(&self.indirect_data.message_digest.digest_algorithm.oid)
    }

    /// Get the [`SignerInfo`] struct.
    #[inline]
    pub fn signer_info(&self) -> &SignerInfo {
        // The parser validates that exactly one signer info is present, so
        // this won't panic.
        &self.signed_data.signer_infos.0.as_ref()[0]
    }

    #[inline]
    pub fn signer_info_digest_alg(&self) -> Cow<'static, str> {
        oid_to_str(&self.signer_info().digest_alg.oid)
    }

    #[inline]
    pub fn signer_info_digest(&self) -> String {
        bytes2hex("", self.signer_info_digest.as_bytes())
    }

    #[inline]
    pub fn certificates(&self) -> &[Certificate] {
        self.certificates.as_slice()
    }

    #[inline]
    pub fn chain(&self) -> impl Iterator<Item = &Certificate> {
        CertificateChain::new(self.certificates.as_slice(), |cert| {
            cert.tbs_certificate.serial_number == self.signer().serial_number
        })
    }

    #[inline]
    pub fn countersignatures(
        &self,
    ) -> impl Iterator<Item = &AuthenticodeCountersign> {
        self.countersignatures.iter()
    }

    pub fn signer(&self) -> &IssuerAndSerialNumber {
        if let SignerIdentifier::IssuerAndSerialNumber(signer) =
            &self.signer_info().sid
        {
            signer
        } else {
            unreachable!()
        }
    }

    /// Returns `true` if the [`AuthenticodeSignature`] is valid.
    ///
    /// A valid Authenticode signature must comply with the following requisites:
    ///
    /// * The Authenticode hash included in the file (in the `message_digest`
    ///   field of [`SpcIndirectDataContent`]) must match the hash computed by
    ///   ourselves using [`PE::authenticode_hash`]. This ensures that the file
    ///   has not been modified.
    ///
    /// * The message digest stored the signed attribute [`rfc6268::ID_MESSAGE_DIGEST`]
    ///   of [`SignerInfo`], must match the one computed by ourselves by hashing
    ///   the `econtent` field in [`EncapsulatedContentInfo`]. This ensures that
    ///   the Authenticode hash included in the file has not been tampered.
    ///
    /// * The signature in [`SignerInfo`] must be valid. This signature is the
    ///   result of signing the hash of the DER encoding of the signed
    ///   attributes in [`SignerInfo`] with the private key of the signing
    ///   certificate. We compute this hash by ourselves, and then use the
    ///   public key included in the signing certificate to verify that the
    ///   signature is valid. This ensures that the signed attributes in
    ///   [`SignerInfo`], including the message digest has not been tampered.
    ///
    /// * The certificate that signed the [`SignerInfo`] struct must be valid,
    ///   which implies that the chain of trust for that certificate must be
    ///   validated, until we found a self-signed certificate or a certificate
    ///   that is not included in the PE file. This last certificate is always
    ///   considered valid.
    pub fn verify(&self) -> bool {
        if self.computed_authenticode_hash() != self.stored_authenticode_hash()
        {
            return false;
        }

        let message_digest = match get_message_digest(self.signer_info()) {
            Some(digest) => digest,
            None => return false,
        };

        if !verify_message_digest(
            &self.signer_info().digest_alg,
            self.signed_data
                .encap_content_info
                .econtent
                .as_ref()
                .unwrap()
                .value(),
            message_digest.as_ref(),
        ) {
            return false;
        }

        verify_signer_info(self.signer_info(), self.certificates())
    }
}

impl From<&AuthenticodeSignature> for protos::pe::Signature {
    fn from(value: &AuthenticodeSignature) -> Self {
        let mut sig = protos::pe::Signature::new();

        sig.set_digest(bytes2hex("", value.stored_authenticode_hash()));
        sig.set_digest_alg(value.authenticode_hash_algorithm().into_owned());
        sig.set_file_digest(bytes2hex("", value.computed_authenticode_hash()));
        sig.set_verified(value.verify());

        sig.certificates.extend(
            value.certificates().iter().map(protos::pe::Certificate::from),
        );

        for cs in value.countersignatures() {
            let mut pbcs = protos::pe::CounterSignature::from(cs);
            pbcs.chain =
                CertificateChain::new(value.certificates.as_slice(), |cert| {
                    cert.tbs_certificate.serial_number
                        == cs.signer.serial_number
                })
                .map(protos::pe::Certificate::from)
                .collect();
            sig.countersignatures.push(pbcs);
        }

        sig.set_number_of_certificates(
            sig.certificates.len().try_into().unwrap(),
        );

        sig.set_number_of_countersignatures(
            sig.countersignatures.len().try_into().unwrap(),
        );

        let mut signer_info = protos::pe::SignerInfo::new();

        signer_info
            .set_digest_alg(value.signer_info_digest_alg().into_owned());

        signer_info.set_digest(value.signer_info_digest());

        if let Some(program_name) = &value.program_name {
            signer_info.set_program_name(program_name.to_string())
        }

        signer_info
            .chain
            .extend(value.chain().map(protos::pe::Certificate::from));

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
        cs.set_verified(value.verified);

        cs.sign_time =
            value.signing_time.map(|t| t.to_unix_duration().as_secs() as i64);

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
            oid_to_str(&value.signature_algorithm.oid).into_owned(),
        );

        // The certificate thumbprint is the SHA1 of the DER-encoded certificate.
        let mut hasher = DerDigest::<Sha1>::default();
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
    let mut n = String::new();
    for rdn in &name.0 {
        write!(n, "/").unwrap();
        for atv in rdn.0.iter() {
            let val = match atv.value.tag() {
                Tag::PrintableString => {
                    asn1::PrintableStringRef::try_from(&atv.value)
                        .ok()
                        .map(|s| s.as_str())
                }
                Tag::Utf8String => asn1::Utf8StringRef::try_from(&atv.value)
                    .ok()
                    .map(|s| s.as_str()),
                Tag::Ia5String => asn1::Ia5StringRef::try_from(&atv.value)
                    .ok()
                    .map(|s| s.as_str()),
                Tag::TeletexString => {
                    asn1::TeletexStringRef::try_from(&atv.value)
                        .ok()
                        .map(|s| s.as_str())
                }
                _ => None,
            };

            if let (key, Some(val)) = (oid_to_str(&atv.oid), val) {
                write!(n, "{}=", key).unwrap();
                for char in val.chars() {
                    n.write_char(char).unwrap();
                }
            } else {
                let value = atv.value.to_der().unwrap();
                write!(n, "{}=#", atv.oid).unwrap();
                for c in value {
                    write!(n, "{:02x}", c).unwrap();
                }
            }
        }
    }

    n
}

/// Given a [`SignerInfo`] returns the value of the message digest attribute.
fn get_message_digest(si: &SignerInfo) -> Option<OctetString> {
    si.signed_attrs
        .as_ref()
        .unwrap()
        .iter()
        .find(|attr| attr.oid == rfc6268::ID_MESSAGE_DIGEST)
        .and_then(|attr| attr.values.get(0))
        .and_then(|value| value.decode_as::<OctetString>().ok())
}

/// Given a hashing algorithm and a message, compute the message's hash
/// and compare it with `digest`. The function returns `true` if they match.
fn verify_message_digest(
    algorithm: &AlgorithmIdentifierOwned,
    message: &[u8],
    digest: &[u8],
) -> bool {
    match algorithm.oid {
        rfc5912::ID_SHA_1 => Sha1::digest(message).as_slice() == digest,
        rfc5912::ID_SHA_256 => Sha256::digest(message).as_slice() == digest,
        rfc5912::ID_SHA_384 => Sha384::digest(message).as_slice() == digest,
        rfc5912::ID_SHA_512 => Sha512::digest(message).as_slice() == digest,
        rfc5912::ID_MD_5 => Md5::digest(message).as_slice() == digest,
        oid => unimplemented!("{:?}", oid),
    }
}

fn verify_signer_info(si: &SignerInfo, certs: &[Certificate]) -> bool {
    match si.digest_alg.oid {
        rfc5912::ID_SHA_1 => verify_signed_data_impl::<Sha1>(si, certs),
        rfc5912::ID_SHA_256 => verify_signed_data_impl::<Sha256>(si, certs),
        rfc5912::ID_SHA_384 => verify_signed_data_impl::<Sha384>(si, certs),
        rfc5912::ID_SHA_512 => verify_signed_data_impl::<Sha512>(si, certs),
        rfc5912::ID_MD_5 => verify_signed_data_impl::<Md5>(si, certs),
        oid => unimplemented!("{:?}", oid),
    }
}

fn verify_signed_data_impl<D: Digest + AssociatedOid + Default>(
    si: &SignerInfo,
    certs: &[Certificate],
) -> bool {
    // Find the certificate that signed the data in `content`.
    let signing_cert_sn =
        if let SignerIdentifier::IssuerAndSerialNumber(signer) = &si.sid {
            &signer.serial_number
        } else {
            unreachable!()
        };

    // Get a certificate chain that starts with the certificate that signed
    // data and contains all the certificates in the chain of truth.
    let cert_chain = CertificateChain::new(certs, |cert| {
        cert.tbs_certificate.serial_number.eq(signing_cert_sn)
    });

    // Make sure that whole certificate chain is valid.
    if !cert_chain.verify() {
        return false;
    }

    // Compute the digest for the DER encoding of the signed attributes, this
    // digest is signed, and its signature is in SignerInfo.signature.
    let mut attrs_digest = DerDigest::<D>::default();

    si.signed_attrs.encode(&mut attrs_digest).unwrap();
    let attrs_digest = attrs_digest.finalize();

    // Search for the certificate that signed the digest.
    let signing_cert = match certs
        .iter()
        .find(|cert| cert.tbs_certificate.serial_number.eq(signing_cert_sn))
    {
        Some(cert) => cert,
        None => return false,
    };

    // Obtain the public key included in the certificate.
    let key = match PublicKey::try_from(
        signing_cert.tbs_certificate.subject_public_key_info.owned_to_ref(),
    ) {
        Ok(key) => key,
        Err(_) => return false,
    };

    // Verify that the signature in SignerInfo.signature is correct.
    key.verify::<D>(attrs_digest.as_slice(), si.signature.as_bytes())
}

/// Produces a printable string of a serial number.
///
/// The [`x509_cert::serial_number::SerialNumber`] type implements the
/// [`Display`] trait, but the resulting string is in uppercase.
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

/// Returns a string that describes an OID.
///
/// When the OID is unknown, returns the numeric representation for
/// the OID (i.e: "1.3.14.3.2.29").
fn oid_to_str(oid: &ObjectIdentifier) -> Cow<'static, str> {
    let oid_str = match oid {
        &rfc5912::ID_SHA_1 => Some("sha1"),
        &rfc5912::ID_SHA_256 => Some("sha256"),
        &rfc5912::ID_SHA_384 => Some("sha384"),
        &rfc5912::ID_SHA_512 => Some("sha512"),
        &rfc5912::ID_MD_5 => Some("md5"),
        &rfc4519::C => Some("C"),
        &rfc4519::COMMON_NAME => Some("CN"),
        &rfc4519::O => Some("O"),
        &rfc4519::OU => Some("OU"),
        &rfc4519::ST => Some("ST"),
        // OIDs not included in const_oid.
        &JURISDICTION_C => Some("jurisdictionC"),
        &JURISDICTION_L => Some("jurisdictionL"),
        &JURISDICTION_ST => Some("jurisdictionST"),
        &SHA1_WITH_RSA_ENCRYPTION => Some("sha1WithRSAEncryption"),
        // In the default case try to use the string representation provided by
        // the `const-oid` crate. Panics if this fails.
        oid => DB.by_oid(oid),
    };

    if let Some(oid) = oid_str {
        Cow::Borrowed(oid)
    } else {
        Cow::Owned(oid.to_string())
    }
}

/// A wrapper that implements the [`der::Writer`] trait for a [`Digest`].
#[derive(Default)]
struct DerDigest<T: Digest + Default>(T);

impl<T: Digest + Default> DerDigest<T> {
    pub fn finalize(self) -> Output<T> {
        self.0.finalize()
    }
}

impl<T: Digest + Default> der::Writer for DerDigest<T> {
    fn write(&mut self, slice: &[u8]) -> der::Result<()> {
        self.0.update(slice);
        Ok(())
    }
}

/// Represents a certificate chain.
///
/// A certificate chain starts with an initial certificate, and contains the
/// certificate that signed the initial certificate, the certificate that
/// signed the signer, and so on, until finding a self-signed certificate, or
/// a certificate that is signed by some external certificate that is not
/// contained in the PE file.
struct CertificateChain<'a> {
    certs: &'a [Certificate],
    next: Option<&'a Certificate>,
}

impl<'a> CertificateChain<'a> {
    /// Creates a new certificate chain.
    ///
    /// This function receives a pool of certificates in the `certs` arguments,
    /// and a `predicate` that identifies the initial certificate in the chain.
    /// The initial certificate will be the first certificate in the pool that
    /// matches the predicate.
    pub fn new<P>(certs: &'a [Certificate], predicate: P) -> Self
    where
        P: Fn(&Certificate) -> bool,
    {
        let next = certs.iter().find(|cert| predicate(cert));
        Self { certs, next }
    }

    /// Returns `true` if the certificate chain is valid.
    ///
    /// A certificate is considered valid if it is correctly signed by a parent
    /// certificate that is included in the PE file, and the parent certificate
    /// is also valid. The validation process goes up the chain of trust until
    /// finding a self-signed certificate or a certificate that is signed by
    /// some other certificate that is not included in the PE.
    ///
    /// When the last certificate in the chain is one that is signed by an
    /// external certificate (not included in the PE) no attempt is made to
    /// continue the validation by retrieving the external certificate from the
    /// operating system certificate store.
    pub fn verify(self) -> bool {
        // Iterate over the chain taking a certificate and its signer on each
        // iteration.
        for (signed, signer) in self.tuple_windows() {
            // The `signed` certificate is the one that will be verified.
            let verify_info = VerifyInfo::new(
                signed.tbs_certificate.to_der().unwrap().into(),
                x509_verify::Signature::new(
                    &signed.signature_algorithm,
                    signed.signature.as_bytes().unwrap(),
                ),
            );

            // The public key in the `signer` certificate is used for
            // verifying the signature in the `signed` certificate.
            let key: VerifyingKey = match signer
                .tbs_certificate
                .subject_public_key_info
                .owned_to_ref()
                .try_into()
            {
                Ok(key) => key,
                Err(_) => return false,
            };

            if key.verify(verify_info).is_err() {
                return false;
            }
        }

        true
    }
}

impl<'a> Iterator for CertificateChain<'a> {
    type Item = &'a Certificate;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.next;
        if let Some(next) = self.next {
            // When the certificate is self-signed issuer == subject, in that
            // case we can't keep going up the chain.
            if next.tbs_certificate.subject == next.tbs_certificate.issuer {
                self.next = None
            } else {
                self.next = self.certs.iter().find(|c| {
                    c.tbs_certificate.subject == next.tbs_certificate.issuer
                });
            }
        }
        next
    }
}

/// Represents public key found in certificate.
enum PublicKey {
    Rsa(rsa::RsaPublicKey),
    Dsa(dsa::VerifyingKey),
    EcdsaP256(p256::ecdsa::VerifyingKey),
    EcdsaP384(p384::ecdsa::VerifyingKey),
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for PublicKey {
    type Error = spki::Error;

    fn try_from(value: SubjectPublicKeyInfoRef) -> Result<Self, Self::Error> {
        match value.algorithm.oid {
            rfc5912::RSA_ENCRYPTION => {
                Ok(Self::Rsa(rsa::RsaPublicKey::try_from(value)?))
            }
            rfc5912::ID_DSA => {
                Ok(Self::Dsa(dsa::VerifyingKey::try_from(value)?))
            }
            rfc5912::ID_EC_PUBLIC_KEY => {
                match value
                    .algorithm
                    .parameters
                    .ok_or(Self::Error::AlgorithmParametersMissing)?
                    .decode_as::<ObjectIdentifier>()
                    .map_err(Self::Error::Asn1)?
                {
                    rfc5912::SECP_256_R_1 => Ok(Self::EcdsaP256(
                        p256::ecdsa::VerifyingKey::try_from(value)?,
                    )),
                    rfc5912::SECP_384_R_1 => Ok(Self::EcdsaP384(
                        p384::ecdsa::VerifyingKey::try_from(value)?,
                    )),
                    oid => Err(Self::Error::OidUnknown { oid }),
                }
            }
            oid => Err(Self::Error::OidUnknown { oid }),
        }
    }
}

impl PublicKey {
    fn verify<D: Digest + AssociatedOid>(
        &self,
        hashed: &[u8],
        signature: &[u8],
    ) -> bool {
        match self {
            Self::Rsa(key) => {
                if Pkcs1v15Sign::new::<D>()
                    .verify(key, hashed, signature)
                    .is_ok()
                {
                    return true;
                }
                Pkcs1v15Sign::new_unprefixed()
                    .verify(key, hashed, signature)
                    .is_ok()
            }
            Self::Dsa(key) => dsa::Signature::from_der(signature)
                .is_ok_and(|s| key.verify_prehash(hashed, &s).is_ok()),
            Self::EcdsaP256(key) => ecdsa::Signature::from_der(signature)
                .is_ok_and(|s| key.verify_prehash(hashed, &s).is_ok()),
            Self::EcdsaP384(key) => ecdsa::Signature::from_der(signature)
                .is_ok_and(|s| key.verify_prehash(hashed, &s).is_ok()),
        }
    }
}
