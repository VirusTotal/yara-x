use std::borrow::Cow;
use std::fmt::Write;

use array_bytes::bytes2hex;
use const_oid::db::{rfc5911, rfc5912, rfc6268};
use const_oid::{AssociatedOid, ObjectIdentifier};
use der_parser::asn1_rs::{Set, Tag, ToDer, UtcTime};
use digest::{Digest, Output};
use dsa::Components;
use ecdsa::signature::hazmat::PrehashVerifier;
use itertools::Itertools;
use md2::Md2;
use md5::Md5;
use nom::AsBytes;
use protobuf::MessageField;
use rsa::traits::SignatureScheme;
use rsa::Pkcs1v15Sign;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use thiserror::Error;
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::num_bigint::BigUint;
use x509_parser::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo, X509Name};

#[cfg(feature = "logging")]
use log::error;

use crate::modules::pe::asn1::{
    oid, oid_to_object_identifier, oid_to_str, Attribute, Certificate,
    ContentInfo, DigestInfo, SignedData, SignerInfo, SpcIndirectDataContent,
    SpcSpOpusInfo, TstInfo,
};
use crate::modules::pe::authenticode::PublicKeyError::InvalidAlgorithm;
use crate::modules::protos;

/// Error returned by [`AuthenticodeParser::parse`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// The signature data is not valid [`ContentInfo`].
    InvalidContentInfo,

    /// The content type is not signed data (1.2.840.113549.1.7.2)
    InvalidContentType(String),

    /// The content info is not valid [`SignedData`].
    InvalidSignedData,

    /// The version of [`SignedData`] is not 1.
    InvalidSignedDataVersion(i32),

    /// The number of digest algorithms is not 1.
    InvalidNumDigestAlgorithms(usize),

    /// The encapsulated content type does not match [`SPC_INDIRECT_DATA_OBJID`].
    InvalidEncapsulatedContentType(String),

    /// The encapsulated content is not valid [`SpcIndirectDataContent`].
    InvalidSpcIndirectDataContent,

    /// The number of signer infos is not 1.
    InvalidNumSignerInfo,

    /// The `contentType` authenticated attribute is missing.
    MissingContentTypeAuthenticatedAttribute,

    /// The attribute containing the Authenticode digest is
    /// missing.
    MissingAuthenticodeDigest,

    /// The Authenticode digest algorithm is invalid.
    InvalidDigestAlgorithm,
}

/// Trait implemented by any type that is able to compute the Authenticode
/// hash for a PE file.
pub trait AuthenticodeHasher {
    /// Computes the Authenticode digest.
    ///
    /// The `digest` argument is any type implementing the [`digest::Update`]
    /// trait, like [`Md5`], [`Sha1`] and [`Sha256`]. It should be newly created
    /// digest that hasn't being updated with any data yet. When this function
    /// returns the digest's output is the Authenticode hash.
    fn hash(&self, digest: &mut dyn digest::Update) -> Option<()>;
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
    pub fn parse<'a>(
        input: &'a [u8],
        authenticode_hasher: &impl AuthenticodeHasher,
    ) -> Result<Vec<AuthenticodeSignature<'a>>, ParseError> {
        let content_info = ContentInfo::from_ber(input)
            .map_err(|_| ParseError::InvalidContentInfo)?;

        Self::parse_content_info(content_info, authenticode_hasher)
    }

    fn parse_content_info<'a>(
        content_info: ContentInfo<'a>,
        authenticode_hasher: &impl AuthenticodeHasher,
    ) -> Result<Vec<AuthenticodeSignature<'a>>, ParseError> {
        if content_info.content_type != rfc5911::ID_SIGNED_DATA {
            return Err(ParseError::InvalidContentType(
                content_info.content_type.to_string(),
            ));
        }

        let mut signed_data: SignedData = content_info
            .content
            .try_into()
            .map_err(|_| ParseError::InvalidSignedData)?;

        if signed_data.version != 1 {
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

        // The content in `SignedData` must be a `SpcIndirectDataContent`
        // structure.
        if signed_data.content_info.content_type
            != oid::MS_SPC_INDIRECT_DATA_OBJID
        {
            return Err(ParseError::InvalidEncapsulatedContentType(
                signed_data.content_info.content_type.to_string(),
            ));
        }

        // According to the Authenticode specification there's exactly one
        // signer info, take it.
        let signer_info = match signed_data.signer_infos.pop() {
            Some(si) => si,
            None => return Err(ParseError::InvalidNumSignerInfo),
        };

        let digest_algorithm =
            match oid_to_object_identifier(signer_info.digest_algorithm.oid())
            {
                Ok(oid) => oid,
                Err(_) => return Err(ParseError::InvalidDigestAlgorithm),
            };

        // No signer infos after taking the only one.
        if !signed_data.signer_infos.is_empty() {
            return Err(ParseError::InvalidNumSignerInfo);
        }

        // `SignerInfo` must have a signed attribute that contains the
        // Authenticode digest. This attribute is identified by OID
        // 1.2.840.113549.1.9.4.
        let signer_info_digest = match signer_info
            .get_signed_attr(&rfc5911::ID_MESSAGE_DIGEST)
            .map(|value| value.data.as_bytes())
        {
            Some(md) => md,
            None => return Err(ParseError::MissingAuthenticodeDigest),
        };

        if signer_info.get_signed_attr(&rfc5911::ID_CONTENT_TYPE).is_none() {
            return Err(ParseError::MissingContentTypeAuthenticatedAttribute);
        }

        // `SignerInfo` can have a signed attribute that contains information
        // about the signed program in a `SpcSpOpusInfo` struct.
        let opus_info: Option<SpcSpOpusInfo> = signer_info
            .get_signed_attr(&oid::MS_SPC_OPUS_INFO)
            .and_then(|value| value.try_into().ok());

        let signed_data_raw = signed_data.content_info.content.data;

        // Extract the `SpcIndirectDataContent` structure from `SignedData`.
        let indirect_data: SpcIndirectDataContent =
            match signed_data.content_info.content.try_into() {
                Ok(idc) => idc,
                Err(_) => {
                    return Err(ParseError::InvalidSpcIndirectDataContent)
                }
            };

        // Extract all the certificates contained in `SignedData`, more
        // certificates from nested signatures and countersignatures will
        // be added later to this vector.
        let mut certificates: Vec<Certificate> = signed_data.certificates;

        let mut nested_signatures = Vec::new();
        let mut countersignatures = Vec::new();

        for attr in signer_info.unsigned_attrs.iter() {
            match attr.attr_type {
                // SignerInfo can have an unsigned attribute containing nested
                // Authenticode signatures. This attribute is identified by
                // OID 1.3.6.1.4.1.311.2.4.1 and its values are `ContentInfo`
                // structures. Usually, this attribute has a single value, but
                // some files, like 6234f03abab2800e7c04aab51ac2dc33 have more
                // than one. Windows doesn't seem to recognize the signature
                // stored in the second value, but we extract it and expose it
                // anyway.
                oid::MS_SPC_NESTED_SIGNATURE => {
                    for value in &attr.attr_values {
                        if let Ok(content_info) = value.try_into() {
                            if let Ok(nested) = Self::parse_content_info(
                                content_info,
                                authenticode_hasher,
                            ) {
                                nested_signatures.extend(nested);
                            }
                        };
                    }
                }
                oid::MS_COUNTERSIGN => {
                    Self::parse_ms_countersignature_attr(
                        &signer_info,
                        attr,
                        &mut certificates,
                        &mut countersignatures,
                    )?;
                }
                rfc5911::ID_COUNTERSIGNATURE => {
                    Self::parse_pkcs9_countersignature_attr(
                        &signer_info,
                        attr,
                        &mut certificates,
                        &mut countersignatures,
                    )?;
                }
                _ => {}
            }
        }

        // Compute the Authenticode hash by ourselves. This hash will be
        // compared later with the one included in the PE file.
        let computed_authenticode_hash = match digest_algorithm {
            rfc5912::ID_MD_2 | rfc5912::MD_2_WITH_RSA_ENCRYPTION => {
                let mut md2 = Md2::default();
                authenticode_hasher.hash(&mut md2);
                md2.finalize().to_vec()
            }
            rfc5912::ID_MD_5 | rfc5912::MD_5_WITH_RSA_ENCRYPTION => {
                let mut md5 = Md5::default();
                authenticode_hasher.hash(&mut md5);
                md5.finalize().to_vec()
            }
            rfc5912::ID_SHA_1
            | rfc5912::SHA_1_WITH_RSA_ENCRYPTION
            | oid::SHA1_WITH_RSA_ENCRYPTION_OBSOLETE => {
                let mut sha1 = Sha1::default();
                authenticode_hasher.hash(&mut sha1);
                sha1.finalize().to_vec()
            }
            rfc5912::ID_SHA_256 | rfc5912::SHA_256_WITH_RSA_ENCRYPTION => {
                let mut sha256 = Sha256::default();
                authenticode_hasher.hash(&mut sha256);
                sha256.finalize().to_vec()
            }
            rfc5912::ID_SHA_384 | rfc5912::SHA_384_WITH_RSA_ENCRYPTION => {
                let mut sha384 = Sha384::default();
                authenticode_hasher.hash(&mut sha384);
                sha384.finalize().to_vec()
            }
            rfc5912::ID_SHA_512 | rfc5912::SHA_512_WITH_RSA_ENCRYPTION => {
                let mut sha512 = Sha512::default();
                authenticode_hasher.hash(&mut sha512);
                sha512.finalize().to_vec()
            }
            _ => {
                #[cfg(feature = "logging")]
                error!("unknown digest algorithm: {:?}", digest_algorithm);
                return Err(ParseError::InvalidDigestAlgorithm);
            }
        };

        let authenticode_digest = indirect_data.message_digest;

        // The Authenticode signature is verified if:
        //
        // * The hash stored in the Authenticode signature matches the actual
        //   hash that we computed by ourselves.
        // * The content of the `SignedData` structure (which contains the
        //   authenticode hash) has not been tampered. This is verified by
        //   comparing the hash of the content with the one stored in the
        //   signed attribute MESSAGE_DIGEST stored in `SignerInfo`.
        // * The `SignerInfo` struct has not been tampered, which is verified
        //   by `verify_signer_info`.
        //
        let verified = authenticode_digest.digest
            == computed_authenticode_hash.as_slice()
            && verify_message_digest(
                &signer_info.digest_algorithm,
                signed_data_raw,
                signer_info_digest,
            )
            && verify_signer_info(&signer_info, certificates.as_slice());

        let mut signatures = Vec::with_capacity(nested_signatures.len() + 1);

        signatures.push(AuthenticodeSignature {
            computed_authenticode_hash,
            program_name: opus_info.and_then(|oi| oi.program_name),
            authenticode_digest,
            signer_info,
            signer_info_digest,
            countersignatures,
            certificates,
            verified,
        });

        signatures.append(&mut nested_signatures);

        Ok(signatures)
    }

    fn parse_ms_countersignature_attr<'a>(
        si: &SignerInfo<'a>,
        attr: &Attribute<'a>,
        certificates: &mut Vec<Certificate<'a>>,
        countersignatures: &mut Vec<AuthenticodeCountersign<'a>>,
    ) -> Result<(), ParseError> {
        for value in &attr.attr_values {
            let ci: ContentInfo = match value.try_into() {
                Ok(ci) => ci,
                Err(_) => continue,
            };

            let sd: SignedData = match ci.content.try_into() {
                Ok(sd) => sd,
                Err(_) => continue,
            };

            certificates.extend(sd.certificates);

            let cs_si = match sd.signer_infos.first() {
                Some(cs_si) => cs_si,
                None => continue,
            };

            let mut countersignature = Self::pkcs9_countersignature(cs_si)?;

            let tst =
                match TstInfo::from_ber(sd.content_info.content.as_bytes()) {
                    Ok(tst_info) => tst_info,
                    Err(_) => continue,
                };

            countersignature.digest_alg = oid_to_str(tst.hash_algorithm.oid());
            countersignature.digest = tst.hashed_message;

            let cs_si_digest = match cs_si
                .get_signed_attr(&rfc5911::ID_MESSAGE_DIGEST)
                .map(|value| value.data.as_bytes())
            {
                Some(md) => md,
                None => return Err(ParseError::MissingAuthenticodeDigest),
            };

            countersignature.verified =
                verify_message_digest(
                    &tst.hash_algorithm,
                    si.signature,
                    tst.hashed_message,
                ) && verify_message_digest(
                    &cs_si.digest_algorithm,
                    sd.content_info.content.as_bytes(),
                    cs_si_digest,
                ) && verify_signer_info(cs_si, certificates.as_slice());

            countersignatures.push(countersignature);
        }

        Ok(())
    }

    fn parse_pkcs9_countersignature_attr<'a>(
        si: &SignerInfo<'a>,
        attr: &Attribute<'a>,
        certificates: &mut Vec<Certificate<'a>>,
        countersignatures: &mut Vec<AuthenticodeCountersign<'a>>,
    ) -> Result<(), ParseError> {
        for value in &attr.attr_values {
            if let Ok(cs_si) = value.try_into() {
                let mut countersignature =
                    Self::pkcs9_countersignature(&cs_si)?;

                countersignature.verified =
                    verify_message_digest(
                        &cs_si.digest_algorithm,
                        si.signature,
                        countersignature.digest,
                    ) && verify_signer_info(&cs_si, certificates.as_slice());

                countersignatures.push(countersignature);
            }
        }

        Ok(())
    }

    fn pkcs9_countersignature<'a>(
        si: &SignerInfo<'a>,
    ) -> Result<AuthenticodeCountersign<'a>, ParseError> {
        let mut digest = None;
        let mut signing_time = None;

        for attr in &si.signed_attrs {
            match attr.attr_type {
                rfc6268::ID_MESSAGE_DIGEST => {
                    digest = attr.attr_values.first().map(|v| v.data);
                }
                rfc6268::ID_SIGNING_TIME => {
                    signing_time = attr
                        .attr_values
                        .first()
                        .and_then(|v| v.try_into().ok())
                        .and_then(|t: UtcTime| t.utc_adjusted_datetime().ok())
                        .map(|t| t.unix_timestamp());
                }
                _ => {}
            }
        }

        let digest = match digest {
            Some(digest) => digest,
            None => return Err(ParseError::MissingAuthenticodeDigest),
        };

        Ok(AuthenticodeCountersign {
            signer: si.serial_number.clone(),
            digest_alg: oid_to_str(si.digest_algorithm.oid()),
            digest,
            signing_time,
            verified: false,
        })
    }
}

pub struct AuthenticodeCountersign<'a> {
    signer: BigUint,
    digest_alg: Cow<'static, str>,
    digest: &'a [u8],
    signing_time: Option<i64>,
    verified: bool,
}

pub struct AuthenticodeSignature<'a> {
    signer_info: SignerInfo<'a>,
    signer_info_digest: &'a [u8],
    authenticode_digest: DigestInfo<'a>,
    certificates: Vec<Certificate<'a>>,
    countersignatures: Vec<AuthenticodeCountersign<'a>>,
    program_name: Option<String>,
    computed_authenticode_hash: Vec<u8>,
    verified: bool,
}

impl<'a> AuthenticodeSignature<'a> {
    /// Get the Authenticode hash stored in the PE file.
    #[inline]
    pub fn stored_authenticode_hash(&self) -> &[u8] {
        self.authenticode_digest.digest
    }

    /// Get the Authenticode hash computed by ourselves.
    #[inline]
    pub fn computed_authenticode_hash(&self) -> &[u8] {
        self.computed_authenticode_hash.as_slice()
    }

    /// Get the name of the Authenticode hash algorithm.
    pub fn authenticode_hash_algorithm(&self) -> Cow<'static, str> {
        oid_to_str(self.authenticode_digest.algorithm.oid())
    }

    #[inline]
    pub fn signer_info_digest_alg(&self) -> Cow<'static, str> {
        oid_to_str(self.signer_info.digest_algorithm.oid())
    }

    #[inline]
    pub fn signer_info_digest(&self) -> String {
        bytes2hex("", self.signer_info_digest.as_bytes())
    }

    #[inline]
    pub fn certificates(&self) -> &[Certificate<'a>] {
        self.certificates.as_slice()
    }

    #[inline]
    pub fn chain(&self) -> impl Iterator<Item = &Certificate<'a>> {
        CertificateChain::new(self.certificates(), |cert| {
            cert.tbs_certificate.issuer.eq(self.issuer())
        })
    }

    #[inline]
    pub fn countersignatures(
        &self,
    ) -> impl Iterator<Item = &AuthenticodeCountersign<'a>> {
        self.countersignatures.iter()
    }

    pub fn issuer(&self) -> &X509Name<'a> {
        &self.signer_info.issuer
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
    pub fn verified(&self) -> bool {
        self.verified
    }
}

impl From<&AuthenticodeSignature<'_>> for protos::pe::Signature {
    fn from(value: &AuthenticodeSignature) -> Self {
        let mut sig = protos::pe::Signature::new();

        sig.set_digest(bytes2hex("", value.stored_authenticode_hash()));
        sig.set_digest_alg(value.authenticode_hash_algorithm().into_owned());
        sig.set_file_digest(bytes2hex("", value.computed_authenticode_hash()));
        sig.set_verified(value.verified());

        sig.certificates.extend(
            value.certificates().iter().map(protos::pe::Certificate::from),
        );

        for cs in value.countersignatures() {
            let mut pbcs = protos::pe::CounterSignature::from(cs);
            pbcs.chain = CertificateChain::new(value.certificates(), |cert| {
                cert.tbs_certificate.serial == cs.signer
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
            signer_info.set_program_name(program_name.clone())
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
                sig.thumbprint.clone_from(&cert.thumbprint);
                sig.issuer.clone_from(&cert.issuer);
                sig.subject.clone_from(&cert.subject);
                sig.serial.clone_from(&cert.serial);
                sig.not_after = cert.not_after;
                sig.not_before = cert.not_before;
                sig.algorithm.clone_from(&cert.algorithm);
                sig.algorithm_oid.clone_from(&cert.algorithm_oid);
            }
        }

        sig
    }
}

impl From<&AuthenticodeCountersign<'_>> for protos::pe::CounterSignature {
    fn from(value: &AuthenticodeCountersign<'_>) -> Self {
        let mut cs = protos::pe::CounterSignature::new();

        cs.set_digest(bytes2hex("", value.digest));
        cs.set_digest_alg(value.digest_alg.to_string());
        cs.set_verified(value.verified);
        cs.sign_time = value.signing_time;

        cs
    }
}

impl From<&Certificate<'_>> for protos::pe::Certificate {
    fn from(value: &Certificate) -> Self {
        let mut cert = protos::pe::Certificate::new();

        // Versions are 0-based, add 1 for getting the actual version.
        cert.set_version(value.x509.tbs_certificate.version.0 as i64 + 1);
        cert.set_issuer(format_name(&value.x509.tbs_certificate.issuer));
        cert.set_subject(format_name(&value.x509.tbs_certificate.subject));
        cert.set_serial(value.x509.raw_serial_as_string());

        cert.set_algorithm_oid(format!(
            "{}",
            value.x509.signature_algorithm.algorithm
        ));

        cert.set_algorithm(
            oid_to_str(&value.x509.signature_algorithm.algorithm).into_owned(),
        );

        cert.set_thumbprint(value.thumbprint.clone());

        cert.set_not_before(
            value.x509.tbs_certificate.validity.not_before.timestamp(),
        );

        cert.set_not_after(
            value.x509.tbs_certificate.validity.not_after.timestamp(),
        );

        cert
    }
}

/// Produces a printable string for a x509 name.
///
/// The [`X509Name`] type implements the [`std::fmt::Display`] trait, but the
/// resulting string follows the [RFC 4514], resulting in something like:
///
/// ```text
/// CN=Thawte Timestamping CA,OU=Thawte Certification,O=Thawte,L=Durbanville,ST=Western Cape,C=ZA
/// ```
///
/// However, the format traditionally used by YARA is inherited from OpenSSL
/// and looks like:
///
/// ```text
/// /C=ZA/ST=Western Cape/L=Durbanville/O=Thawte/OU=Thawte Certification/CN=Thawte Timestamping CA
/// ```
///
/// [RFC 4514]: https://datatracker.ietf.org/doc/html/rfc4514
fn format_name(name: &X509Name) -> String {
    let mut n = String::new();
    for rdn in name.iter_rdn() {
        write!(n, "/").unwrap();
        for atv in rdn.iter() {
            let key = oid_to_str(atv.attr_type());
            let attr_val = atv.attr_value();
            // Not using `atv.as_str()` because it doesn't take into account
            // the `Tag::TeletexString` case.
            let val = match attr_val.tag() {
                Tag::PrintableString => {
                    attr_val.as_printablestring().ok().map(|s| s.string())
                }
                Tag::Utf8String => {
                    attr_val.as_utf8string().ok().map(|s| s.string())
                }
                Tag::Ia5String => {
                    attr_val.as_ia5string().ok().map(|s| s.string())
                }
                Tag::TeletexString => {
                    attr_val.as_teletexstring().ok().map(|s| s.string())
                }
                _ => None,
            };
            match (key, val) {
                (key, Some(val)) => {
                    write!(n, "{}=", key).unwrap();
                    for char in val.chars() {
                        n.write_char(char).unwrap();
                    }
                }
                (key, None) => {
                    write!(n, "{}=#", key).unwrap();
                    for c in attr_val.data {
                        write!(n, "{:02x}", c).unwrap();
                    }
                }
            }
        }
    }

    n
}

/// Given a hashing algorithm and a message, compute the message's hash
/// and compare it with `digest`. The function returns `true` if they match.
fn verify_message_digest(
    algorithm: &AlgorithmIdentifier,
    message: &[u8],
    digest: &[u8],
) -> bool {
    let oid = match oid_to_object_identifier(algorithm.oid()) {
        Ok(oid) => oid,
        Err(_) => return false,
    };
    match oid {
        rfc5912::ID_SHA_1
        | rfc5912::SHA_1_WITH_RSA_ENCRYPTION
        | oid::SHA1_WITH_RSA_ENCRYPTION_OBSOLETE => {
            Sha1::digest(message).as_slice() == digest
        }
        rfc5912::ID_SHA_256 | rfc5912::SHA_256_WITH_RSA_ENCRYPTION => {
            Sha256::digest(message).as_slice() == digest
        }
        rfc5912::ID_SHA_384 | rfc5912::SHA_384_WITH_RSA_ENCRYPTION => {
            Sha384::digest(message).as_slice() == digest
        }
        rfc5912::ID_SHA_512 | rfc5912::SHA_512_WITH_RSA_ENCRYPTION => {
            Sha512::digest(message).as_slice() == digest
        }
        rfc5912::ID_MD_2 | rfc5912::MD_2_WITH_RSA_ENCRYPTION => {
            Md2::digest(message).as_slice() == digest
        }
        rfc5912::ID_MD_5 | rfc5912::MD_5_WITH_RSA_ENCRYPTION => {
            Md5::digest(message).as_slice() == digest
        }
        _ => {
            #[cfg(feature = "logging")]
            error!("unknown digest algorithm: {:?}", algorithm.oid());
            false
        }
    }
}

/// Verifies that the [`SignerInfo`] struct is valid.
///
/// `SignerInfo` contains information about the signer of some data stored in
/// the content field of a [`SignedData`] structure. This information is stored
/// in signed and unsigned attributes of `SignerInfo`. Signed attributes are
/// protected from tampering by a digital signature, which is computed by
/// hashing the attributes first, and then signing the hash. The resulting
/// signature is added `SignerInfo` itself. This signature can be verified by
/// using the public key included in the certificate identified by
/// [`SignerInfo::serial_number`].
///
/// This function makes sure that:
///
/// * The signature of `SignerInfo` is correct.
/// * The certificate that produced the signature for `SignerInfo` is also
///   correct.
///
/// The verification of the certificate includes the verification of the whole
/// certificate chain, until reaching a self-signed certificate or some
/// certificate that was signed by an "external" one (a certificate that is not
/// included in the PE).
fn verify_signer_info(si: &SignerInfo, certs: &[Certificate<'_>]) -> bool {
    let digest_algorithm =
        match oid_to_object_identifier(si.digest_algorithm.oid()) {
            Ok(oid) => oid,
            Err(_) => return false,
        };

    // Get a certificate chain that starts with the certificate that signed
    // the data that this SignerInfo refers to. This chain goes from the
    // signing certificate up in the chain of truth until a self-signed
    // certificate or some "external" certificate.
    let cert_chain = CertificateChain::new(certs, |cert| {
        cert.tbs_certificate.serial.eq(&si.serial_number)
    });

    // Make sure that whole certificate chain is valid.
    if !cert_chain.verify() {
        return false;
    }

    // Search for the certificate that signed the digest.
    let signing_cert = match certs
        .iter()
        .map(|cert| &cert.x509)
        .find(|cert| cert.tbs_certificate.serial.eq(&si.serial_number))
    {
        Some(cert) => cert,
        None => return false,
    };

    // Obtain the public key included in the certificate.
    let spki = &signing_cert.tbs_certificate.subject_pki;
    let key = match PublicKey::try_from(spki) {
        Ok(key) => key,
        Err(_) => return false,
    };

    // We need to compute the hash for the signed attributes. This is a hash of
    // the DER encoding of the attributes, however, the computation of the hash
    // is not straightforward. One may think that the hash can be computed over
    // the bytes in the PE file that correspond to the DER encoding of the
    // attributes, but that's not the case. In fact, the PE file doesn't
    // contain the exact byte sequence that must be hashed.
    //
    // This is the ASN.1 definition for the signed attributes:
    //
    //   SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
    //
    // Normally, the raw bytes of an ASN.1 `SET` start with 0x31 (the tag
    // associated to sets), followed by the set size, and the set contents.
    // The raw bytes would be `0x31 [size] [content]`. But ASN.1 encoding is
    // context-sensitive, which means that the 0x31 tag can be missing if
    // SignedAttributes is used in a parent structure using implicit
    // tagging, for instance:
    //
    //  signedAttrs `[0]` IMPLICIT SignedAttributes OPTIONAL,
    //
    // Within the SignerInfo structure, the tag 0 identifies the signedAttrs
    // field, when this tag is found, the ASN.1 parser already knows that
    // a SignedAttributes follows, and it already knows that it's a SET,
    // therefore the 0x31 is not necessary. The raw bytes are:
    //
    // 0xA0 [size] [content]
    //
    // `0xA0` is the raw encoding for `[0]`.
    //
    // In resume, the PE file has:
    //
    // 0xA0 [size] [content]
    //
    // But the hash is computed for:
    //
    // 0x31 [size] [content]
    //
    let attrs_set = Set::new(Cow::Borrowed(si.raw_signed_attrs));

    // Verify that the signature in `SignerInfo` is correct.
    match digest_algorithm {
        rfc5912::ID_MD_2 | rfc5912::MD_2_WITH_RSA_ENCRYPTION => {
            let mut md2 = Md2::default();
            attrs_set.write_der(&mut md2).unwrap();
            key.verify_digest::<Md2>(md2.finalize(), si.signature)
        }
        rfc5912::ID_MD_5 | rfc5912::MD_5_WITH_RSA_ENCRYPTION => {
            let mut md5 = Md5::default();
            attrs_set.write_der(&mut md5).unwrap();
            key.verify_digest::<Md5>(md5.finalize(), si.signature)
        }
        rfc5912::ID_SHA_1
        | rfc5912::SHA_1_WITH_RSA_ENCRYPTION
        | oid::SHA1_WITH_RSA_ENCRYPTION_OBSOLETE => {
            let mut sha1 = Sha1::default();
            attrs_set.write_der(&mut sha1).unwrap();
            key.verify_digest::<Sha1>(sha1.finalize(), si.signature)
        }
        rfc5912::ID_SHA_256 | rfc5912::SHA_256_WITH_RSA_ENCRYPTION => {
            let mut sha256 = Sha256::default();
            attrs_set.write_der(&mut sha256).unwrap();
            key.verify_digest::<Sha256>(sha256.finalize(), si.signature)
        }
        rfc5912::ID_SHA_384 | rfc5912::SHA_384_WITH_RSA_ENCRYPTION => {
            let mut sha384 = Sha384::default();
            attrs_set.write_der(&mut sha384).unwrap();
            key.verify_digest::<Sha384>(sha384.finalize(), si.signature)
        }
        rfc5912::ID_SHA_512 | rfc5912::SHA_512_WITH_RSA_ENCRYPTION => {
            let mut sha512 = Sha512::default();
            attrs_set.write_der(&mut sha512).unwrap();
            key.verify_digest::<Sha512>(sha512.finalize(), si.signature)
        }
        _ => {
            #[cfg(feature = "logging")]
            error!("unknown digest algorithm: {:?}", digest_algorithm);
            false
        }
    }
}

/// Represents a certificate chain.
///
/// A certificate chain starts with an initial certificate, and contains the
/// certificate that signed the initial certificate, the certificate that
/// signed the signer, and so on, until finding a self-signed certificate, or
/// a certificate that is signed by some external certificate that is not
/// contained in the PE file.
struct CertificateChain<'a, 'b> {
    certs: &'b [Certificate<'a>],
    next: Option<&'b Certificate<'a>>,
}

impl<'a, 'b> CertificateChain<'a, 'b> {
    /// Creates a new certificate chain.
    ///
    /// This function receives a pool of certificates in the `certs` arguments,
    /// and a `predicate` that identifies the initial certificate in the chain.
    /// The initial certificate will be the first certificate in the pool that
    /// matches the predicate.
    pub fn new<P>(certs: &'b [Certificate<'a>], predicate: P) -> Self
    where
        P: Fn(&X509Certificate<'_>) -> bool,
    {
        let next = certs.iter().find(|cert| predicate(&cert.x509));
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
            // When `x509-parser-verify` feature verify certificate signatures
            // using the `x509_parser` crate.
            #[cfg(feature = "x509-parser-verify")]
            {
                if x509_parser::verify::verify_signature(
                    &signer.x509.subject_pki,
                    &signed.x509.signature_algorithm,
                    &signed.x509.signature_value,
                    signed.x509.tbs_certificate.as_ref(),
                )
                .is_err()
                {
                    return false;
                }
            }

            // When `x509-parser-verify` feature is not enabled, use our
            // own logic.
            #[cfg(not(feature = "x509-parser-verify"))]
            {
                let key = match PublicKey::try_from(
                    &signer.x509.tbs_certificate.subject_pki,
                ) {
                    Ok(key) => key,
                    Err(_) => return false,
                };

                if !key.verify(
                    &signed.x509.signature_algorithm,
                    signed.x509.tbs_certificate.as_ref(),
                    signed.x509.signature_value.as_ref(),
                ) {
                    return false;
                }
            }
        }

        true
    }
}

impl<'a, 'b> Iterator for CertificateChain<'a, 'b> {
    type Item = &'b Certificate<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.next;
        if let Some(next) = self.next {
            // When the certificate is self-signed issuer == subject, in that
            // case we can't keep going up the chain.
            if next.x509.tbs_certificate.subject
                == next.x509.tbs_certificate.issuer
            {
                self.next = None
            } else {
                self.next = self.certs.iter().find(|c| {
                    c.x509.tbs_certificate.subject
                        == next.x509.tbs_certificate.issuer
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

#[derive(Error, Debug)]
enum PublicKeyError {
    #[error("PKCS1 error")]
    Pkcs1(#[from] rsa::pkcs1::Error),

    #[error("PKCS8 error")]
    Pkcs8(#[from] rsa::pkcs8::spki::Error),

    #[error("DER parsing error")]
    Der(#[from] der_parser::error::Error),

    #[error("ECDSA error")]
    Ecdsa(#[from] ecdsa::Error),

    #[error("DER parsing error")]
    Nom(#[from] nom::Err<der_parser::error::Error>),

    #[error("Missing algorithm parameters")]
    MissingAlgorithmParameters,

    #[error("Unknown ECDSA curve")]
    UnknownEcdsaCurve(ObjectIdentifier),

    #[error("Unknown encryption algorithm")]
    UnknownAlgorithm(ObjectIdentifier),

    #[error("Invalid object identifier")]
    InvalidAlgorithm,
}

impl TryFrom<&SubjectPublicKeyInfo<'_>> for PublicKey {
    type Error = PublicKeyError;

    fn try_from(spki: &SubjectPublicKeyInfo<'_>) -> Result<Self, Self::Error> {
        match oid_to_object_identifier(spki.algorithm.oid())
            .map_err(|_| InvalidAlgorithm)?
        {
            rfc5912::RSA_ENCRYPTION => {
                use rsa::pkcs1::DecodeRsaPublicKey;
                Ok(Self::Rsa(rsa::RsaPublicKey::from_pkcs1_der(
                    spki.subject_public_key.as_ref(),
                )?))
            }
            rfc5912::ID_DSA => {
                let parameters = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .ok_or(Self::Error::MissingAlgorithmParameters)?;

                let key_bytes = spki.subject_public_key.as_ref();

                use der_parser::ber::parse_ber_integer;
                let (_, y) = parse_ber_integer(key_bytes)?;
                let (rem, p) = parse_ber_integer(parameters.data)?;
                let (rem, q) = parse_ber_integer(rem)?;
                let (_, g) = parse_ber_integer(rem)?;

                let p = dsa::BigUint::from_bytes_be(p.content.as_slice()?);
                let q = dsa::BigUint::from_bytes_be(q.content.as_slice()?);
                let g = dsa::BigUint::from_bytes_be(g.content.as_slice()?);
                let y = dsa::BigUint::from_bytes_be(y.content.as_slice()?);

                let components = Components::from_components(p, q, g)?;
                let key = dsa::VerifyingKey::from_components(components, y)?;

                Ok(Self::Dsa(key))
            }
            rfc5912::ID_EC_PUBLIC_KEY => {
                let curve: der_parser::asn1_rs::Oid = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .ok_or(Self::Error::MissingAlgorithmParameters)?
                    .try_into()?;

                let oid = oid_to_object_identifier(&curve)
                    .map_err(|_| InvalidAlgorithm)?;

                match oid {
                    rfc5912::SECP_256_R_1 => Ok(Self::EcdsaP256(
                        p256::ecdsa::VerifyingKey::try_from(
                            spki.subject_public_key.as_ref(),
                        )?,
                    )),
                    rfc5912::SECP_384_R_1 => Ok(Self::EcdsaP384(
                        p384::ecdsa::VerifyingKey::try_from(
                            spki.subject_public_key.as_ref(),
                        )?,
                    )),
                    oid => Err(Self::Error::UnknownEcdsaCurve(oid)),
                }
            }
            oid => Err(Self::Error::UnknownAlgorithm(oid)),
        }
    }
}

impl PublicKey {
    #[cfg(not(feature = "x509-parser-verify"))]
    fn verify(
        &self,
        digest_algorithm: &AlgorithmIdentifier,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        let oid = match oid_to_object_identifier(digest_algorithm.oid()) {
            Ok(oid) => oid,
            Err(_) => return false,
        };
        match oid {
            rfc5912::ID_MD_2 | rfc5912::MD_2_WITH_RSA_ENCRYPTION => {
                self.verify_impl::<Md2>(message, signature)
            }
            rfc5912::ID_MD_5 | rfc5912::MD_5_WITH_RSA_ENCRYPTION => {
                self.verify_impl::<Md5>(message, signature)
            }
            rfc5912::ID_SHA_1
            | rfc5912::DSA_WITH_SHA_1
            | rfc5912::SHA_1_WITH_RSA_ENCRYPTION
            | oid::SHA1_WITH_RSA_ENCRYPTION_OBSOLETE => {
                self.verify_impl::<Sha1>(message, signature)
            }
            rfc5912::ID_SHA_256
            | rfc5912::SHA_256_WITH_RSA_ENCRYPTION
            | rfc5912::DSA_WITH_SHA_256
            | rfc5912::ECDSA_WITH_SHA_256 => {
                self.verify_impl::<Sha256>(message, signature)
            }
            rfc5912::ID_SHA_384
            | rfc5912::SHA_384_WITH_RSA_ENCRYPTION
            | rfc5912::ECDSA_WITH_SHA_384 => {
                self.verify_impl::<Sha384>(message, signature)
            }
            rfc5912::ID_SHA_512
            | rfc5912::SHA_512_WITH_RSA_ENCRYPTION
            | rfc5912::ECDSA_WITH_SHA_512 => {
                self.verify_impl::<Sha512>(message, signature)
            }
            _ => {
                #[cfg(feature = "logging")]
                error!(
                    "unknown digest algorithm: {:?}",
                    digest_algorithm.oid()
                );
                false
            }
        }
    }

    #[cfg(not(feature = "x509-parser-verify"))]
    fn verify_impl<D: Digest + AssociatedOid>(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        let digest = D::digest(message);
        self.verify_digest::<D>(digest, signature)
    }

    fn verify_digest<D: Digest + AssociatedOid>(
        &self,
        hash: Output<D>,
        signature: &[u8],
    ) -> bool {
        match self {
            Self::Rsa(key) => {
                if Pkcs1v15Sign::new::<D>()
                    .verify(key, hash.as_slice(), signature)
                    .is_ok()
                {
                    return true;
                }
                Pkcs1v15Sign::new_unprefixed()
                    .verify(key, hash.as_slice(), signature)
                    .is_ok()
            }
            Self::Dsa(key) => {
                use dsa::pkcs8::der::Decode;
                dsa::Signature::from_der(signature).is_ok_and(|s| {
                    key.verify_prehash(hash.as_slice(), &s).is_ok()
                })
            }
            Self::EcdsaP256(key) => ecdsa::Signature::from_der(signature)
                .is_ok_and(|s| {
                    key.verify_prehash(hash.as_slice(), &s).is_ok()
                }),
            Self::EcdsaP384(key) => ecdsa::Signature::from_der(signature)
                .is_ok_and(|s| {
                    key.verify_prehash(hash.as_slice(), &s).is_ok()
                }),
        }
    }
}
