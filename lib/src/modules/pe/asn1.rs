use array_bytes::bytes2hex;
use const_oid::db::{rfc4519, rfc5912};
use const_oid::ObjectIdentifier;
use der_parser::der::{
    parse_der_content, parse_der_integer, parse_der_octetstring,
    parse_der_oid, parse_der_sequence_defined_g, parse_der_set_of_v,
    parse_der_tagged_explicit_g, parse_der_tagged_implicit, DerObject,
};
use std::borrow::Cow;

use der_parser::asn1_rs::{Any, FromDer, OptTaggedParser};
use der_parser::ber::parse_ber_any;
use der_parser::error::{BerError, BerResult};
use der_parser::nom::Err::Incomplete;
use der_parser::nom::{IResult, Parser};
use der_parser::num_bigint::BigUint;
use der_parser::{asn1_rs, parse_der, Oid};
use digest::Digest;
use nom::branch::alt;
use nom::combinator::{consumed, map_res};
use sha1::Sha1;
use x509_parser::certificate::X509Certificate;
use x509_parser::error::X509Error;
use x509_parser::prelude::{AlgorithmIdentifier, X509CertificateParser};
use x509_parser::x509::X509Name;

#[rustfmt::skip]
#[allow(dead_code)]
pub mod oid {
    use const_oid::ObjectIdentifier;
    use der_parser::{oid, Oid};

    pub const MD5: Oid = oid!(1.2.840.113549.2.5);
    pub const MD5_B: &[u8] = &oid!(raw 1.2.840.113549.2.5);

    pub const SHA_1: Oid = oid!(1.3.14.3.2.26);
    pub const SHA_1_B: &[u8] = &oid!(raw 1.3.14.3.2.26);

    pub const SHA_256: Oid = oid!(2.16.840.1.101.3.4.2.1);
    pub const SHA_256_B: &[u8] = &oid!(raw 2.16.840.1.101.3.4.2.1);

    pub const SHA_384: Oid = oid!(2.16.840.1.101.3.4.2.2);
    pub const SHA_384_B: &[u8] = &oid!(raw 2.16.840.1.101.3.4.2.2);

    pub const SHA_512: Oid = oid!(2.16.840.1.101.3.4.2.3);
    pub const SHA_512_B: &[u8] = &oid!(raw 2.16.840.1.101.3.4.2.3);

    pub const MD5_WITH_RSA_ENCRYPTION: Oid = oid!(1.2.840.113549.1.1.4);
    pub const MD5_WITH_RSA_ENCRYPTION_B: &[u8] = &oid!(raw 1.2.840.113549.1.1.4);
    
    pub const SHA_1_WITH_RSA_ENCRYPTION: Oid = oid!(1.2.840.113549.1.1.5);
    pub const SHA_1_WITH_RSA_ENCRYPTION_B: &[u8] = &oid!(raw 1.2.840.113549.1.1.5);

    pub const SHA_256_WITH_RSA_ENCRYPTION: Oid = oid!(1.2.840.113549.1.1.11);
    pub const SHA_256_WITH_RSA_ENCRYPTION_B: &[u8] = &oid!(raw 1.2.840.113549.1.1.11);

    pub const SHA_384_WITH_RSA_ENCRYPTION: Oid = oid!(1.2.840.113549.1.1.12);
    pub const SHA_384_WITH_RSA_ENCRYPTION_B: &[u8] = &oid!(raw 1.2.840.113549.1.1.12);

    pub const SHA_512_WITH_RSA_ENCRYPTION: Oid = oid!(1.2.840.113549.1.1.13);
    pub const SHA_512_WITH_RSA_ENCRYPTION_B: &[u8] = &oid!(raw 1.2.840.113549.1.1.13);

    pub const RSA_ENCRYPTION: Oid = oid!(1.2.840.113549.1.1.1);
    pub const RSA_ENCRYPTION_B: &[u8] = &oid!(raw 1.2.840.113549.1.1.1);
    
    pub const SIGNED_DATA: Oid = oid!(1.2.840.113549.1.7.2);
    pub const SIGNED_DATA_B: &[u8] = &oid!(raw 1.2.840.113549.1.7.2);

    pub const MESSAGE_DIGEST: Oid = oid!(1.2.840.113549.1.9.4);
    pub const MESSAGE_DIGEST_B: &[u8] = &oid!(raw 1.2.840.113549.1.9.4);

    pub const INDIRECT_DATA_OBJID: Oid = oid!(1.3.6.1.4.1.311.2.1.4);
    pub const INDIRECT_DATA_OBJID_B: &[u8] = &oid!(raw 1.3.6.1.4.1.311.2.1.4);

    pub const CONTENT_TYPE: Oid = oid!(1.2.840.113549.1.9.3);
    pub const CONTENT_TYPE_B: &[u8] = &oid!(raw 1.2.840.113549.1.9.3);

    pub const OPUS_INFO_OBJID: Oid = oid!(1.3.6.1.4.1.311.2.1.12);
    pub const OPUS_INFO_OBJID_B: &[u8] = &oid!(raw 1.3.6.1.4.1.311.2.1.12);

    pub const MS_NESTED_SIGNATURE: Oid = oid!(1.3.6.1.4.1.311.2.4.1);
    pub const MS_NESTED_SIGNATURE_B: &[u8] = &oid!(raw 1.3.6.1.4.1.311.2.4.1);

    pub const MS_COUNTERSIGN: Oid = oid!(1.3.6.1.4.1.311.3.3.1);
    pub const MS_COUNTERSIGN_B: &[u8] = &oid!(raw 1.3.6.1.4.1.311.3.3.1);

    pub const PKCS9_COUNTERSIGN: Oid = oid!(1.2.840.113549.1.9.6);
    pub const PKCS9_COUNTERSIGN_B: &[u8] = &oid!(raw 1.2.840.113549.1.9.6);

    pub const COUNTRY: Oid = oid!(2.5.4.6);
    pub const COUNTRY_B: &[u8] = &oid!(raw 2.5.4.6);

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
    
}

#[inline]
pub fn oid_to_object_identifier(oid: &Oid) -> ObjectIdentifier {
    ObjectIdentifier::from_bytes(oid.as_bytes()).unwrap()
}

pub fn oid_to_str(oid: &Oid) -> Cow<'static, str> {
    match oid_to_object_identifier(oid) {
        rfc5912::ID_MD_5 => Cow::Borrowed("md5"),
        rfc5912::ID_SHA_1 => Cow::Borrowed("sha1"),
        rfc5912::ID_SHA_256 => Cow::Borrowed("sha256"),
        rfc5912::ID_SHA_384 => Cow::Borrowed("sha384"),
        rfc5912::ID_SHA_512 => Cow::Borrowed("sha512"),
        rfc5912::MD_5_WITH_RSA_ENCRYPTION => {
            Cow::Borrowed("md5WithRSAEncryption")
        }
        oid::SHA1_WITH_RSA_ENCRYPTION | rfc5912::SHA_1_WITH_RSA_ENCRYPTION => {
            Cow::Borrowed("sha1WithRSAEncryption")
        }
        rfc5912::SHA_256_WITH_RSA_ENCRYPTION => {
            Cow::Borrowed("sha256WithRSAEncryption")
        }
        rfc5912::SHA_384_WITH_RSA_ENCRYPTION => {
            Cow::Borrowed("sha384WithRSAEncryption")
        }
        rfc5912::SHA_512_WITH_RSA_ENCRYPTION => {
            Cow::Borrowed("sha512WithRSAEncryption")
        }
        rfc4519::C => Cow::Borrowed("C"),
        rfc4519::COMMON_NAME => Cow::Borrowed("CN"),
        rfc4519::O => Cow::Borrowed("O"),
        rfc4519::OU => Cow::Borrowed("OU"),
        rfc4519::ST => Cow::Borrowed("ST"),
        // OIDs not included in const_oid.
        oid::JURISDICTION_C => Cow::Borrowed("jurisdictionC"),
        oid::JURISDICTION_L => Cow::Borrowed("jurisdictionL"),
        oid::JURISDICTION_ST => Cow::Borrowed("jurisdictionST"),
        // In the default case try to use the string representation provided by
        // the `const-oid` crate. Panics if this fails.
        oid => {
            if let Some(name) = const_oid::db::DB.by_oid(&oid) {
                Cow::Borrowed(name)
            } else {
                Cow::Owned(oid.to_string())
            }
        }
    }
}

pub struct ContentInfo<'a> {
    pub content_type: Oid<'a>,
    pub content: Any<'a>,
}

impl<'a> ContentInfo<'a> {
    pub fn parse(data: &'a [u8]) -> BerResult<Self> {
        parse_der_sequence_defined_g(|i, _| Self::parse_inner(i))(data)
    }

    pub fn from_der(
        data: &'a [u8],
    ) -> Result<Self, nom::Err<der_parser::error::Error>> {
        Self::parse(data).map(|(_, content_info)| content_info)
    }

    fn parse_inner(data: &'a [u8]) -> BerResult<Self> {
        let (remainder, content_type) = parse_der_oid(data)?;
        let (remainder, content) =
            parse_der_tagged_explicit_g(0, |content, _| {
                parse_ber_any(content)
            })(remainder)?;

        Ok((
            remainder,
            Self { content_type: content_type.as_oid_val()?, content },
        ))
    }
}

impl<'a> TryFrom<&Any<'a>> for ContentInfo<'a> {
    type Error = asn1_rs::Error;

    fn try_from(any: &Any<'a>) -> Result<Self, Self::Error> {
        any.tag().assert_eq(asn1_rs::Tag::Sequence)?;
        Ok(Self::parse_inner(any.data).map(|(_, ci)| ci)?)
    }
}

pub struct Certificate<'a> {
    pub x509: X509Certificate<'a>,
    pub thumbprint: String,
}

/// ```text
/// SignedData ::= SEQUENCE {
///         version CMSVersion,
///         digestAlgorithms DigestAlgorithmIdentifiers,
///         encapContentInfo EncapsulatedContentInfo,
///         certificates [0] IMPLICIT CertificateSet OPTIONAL,
///         crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///         signerInfos SignerInfos }
/// ```
///
/// https://datatracker.ietf.org/doc/html/rfc5652#section-5.1
pub struct SignedData<'a> {
    pub version: i32,
    pub digest_algorithms: Vec<AlgorithmIdentifier<'a>>,
    pub content_info: ContentInfo<'a>,
    pub certificates: Vec<Certificate<'a>>,
    /// In general `SignedData` can be signed by multiple signers and therefore
    /// can contain multiple `SignerInfo` structures. However, in the case of
    /// Authenticode there's only one signer.
    pub signer_infos: Vec<SignerInfo<'a>>,
}

impl<'a> SignedData<'a> {
    pub fn parse(input: &'a [u8]) -> BerResult<Self> {
        parse_der_sequence_defined_g(|input: &[u8], _| {
            Self::parse_inner(input)
        })(input)
    }

    fn parse_inner(input: &'a [u8]) -> BerResult<Self> {
        let (remainder, version) = parse_der_integer(input)?;

        let (remainder, digest_algorithms) =
            parse_der_set_of_v(AlgorithmIdentifier::from_der)(remainder)
                .unwrap(); // TODO: handle error

        let (remainder, content_info) = ContentInfo::parse(remainder)?;

        let (remainder, certificates) = OptTaggedParser::from(0)
            .parse_der(remainder, |_, raw_certs| {
                Self::parse_certificates(raw_certs)
            })
            .unwrap(); // TODO:: handle error

        let (remainder, _revocation_info) = OptTaggedParser::from(1)
            .parse_der(remainder, |_, data| parse_der(data))?;

        let (remainder, signer_infos) =
            parse_der_set_of_v(SignerInfo::parse)(remainder)?;

        Ok((
            remainder,
            Self {
                version: version.as_i32()?,
                certificates: certificates.unwrap_or_default(),
                signer_infos,
                digest_algorithms,
                content_info,
            },
        ))
    }

    fn parse_certificates(
        input: &[u8],
    ) -> IResult<&[u8], Vec<Certificate>, X509Error> {
        let mut remainder = input;
        let mut certificates = Vec::new();

        // A parser that returns both the parsed certificate, and the
        // raw bytes consumed by the certificate parser.
        let mut cert_parser =
            consumed(|input| X509CertificateParser::new().parse(input));

        loop {
            remainder = match cert_parser(remainder) {
                Ok((remainder, (cert_bytes, cert))) => {
                    certificates.push(Certificate {
                        x509: cert,
                        thumbprint: bytes2hex("", Sha1::digest(cert_bytes)),
                    });
                    remainder
                }
                Err(Incomplete(_)) => {
                    return Ok((remainder, certificates));
                }
                Err(err) => return Err(err),
            }
        }
    }
}

impl<'a> TryFrom<Any<'a>> for SignedData<'a> {
    type Error = asn1_rs::Error;

    fn try_from(any: Any<'a>) -> Result<Self, Self::Error> {
        any.tag().assert_eq(asn1_rs::Tag::Sequence)?;
        Ok(Self::parse_inner(any.data).map(|(_, ci)| ci)?)
    }
}

/// ```text
/// SignerInfo ::= SEQUENCE {
///         version CMSVersion,
///         sid SignerIdentifier,
///         digestAlgorithm DigestAlgorithmIdentifier,
///         signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
///         signatureAlgorithm SignatureAlgorithmIdentifier,
///         signature SignatureValue,
///         unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
/// ```
///
/// https://datatracker.ietf.org/doc/html/rfc5652#section-5.3
pub struct SignerInfo<'a> {
    pub version: i32,
    pub issuer: X509Name<'a>,
    pub serial_number: BigUint,
    pub digest_algorithm: AlgorithmIdentifier<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature_value: &'a [u8],
    pub raw_signed_attrs: &'a [u8],
    pub signed_attrs: Vec<Attribute<'a>>,
    pub unsigned_attrs: Vec<Attribute<'a>>,
}

impl<'a> SignerInfo<'a> {
    pub fn parse(input: &'a [u8]) -> BerResult<Self> {
        parse_der_sequence_defined_g(|input: &[u8], _| {
            Self::parse_inner(input)
        })(input)
    }

    pub fn parse_inner(input: &'a [u8]) -> BerResult<Self> {
        let (remainder, version) = parse_der_integer(input)?;

        let (remainder, (issuer, serial_number)) =
            Self::parse_issuer_and_serial_number(remainder)?;

        let (remainder, digest_algorithm) =
            AlgorithmIdentifier::from_der(remainder).unwrap(); // TODO: handle error

        let (remainder, signed_attrs) = OptTaggedParser::from(0).parse_der(
            remainder,
            |_, raw_attrs| {
                let (remainder, parsed_attrs) =
                    Self::parse_attributes(raw_attrs)?;

                Ok((remainder, (raw_attrs, parsed_attrs)))
            },
        )?;

        let (remainder, signature_algorithm) =
            AlgorithmIdentifier::from_der(remainder).unwrap(); // TODO: handle error

        let (remainder, signature) = parse_der_octetstring(remainder)?;

        let (remainder, unsigned_attrs) = OptTaggedParser::from(1)
            .parse_der(remainder, |_, raw_attrs| {
                Self::parse_attributes(raw_attrs)
            })?;

        let (raw_signed_attrs, signed_attrs) =
            signed_attrs.unwrap_or_default();

        Ok((
            remainder,
            Self {
                version: version.as_i32()?,
                signed_attrs,
                raw_signed_attrs,
                unsigned_attrs: unsigned_attrs.unwrap_or_default(),
                signature_value: signature.content.as_slice()?,
                issuer,
                serial_number,
                digest_algorithm,
                signature_algorithm,
            },
        ))
    }

    /// Returns the value of the signed attribute with a given OID.
    ///
    /// An attribute can have multiple values, but in Authenticode
    /// signatures all the attributes we need to work with have a
    /// single value. This function retrieves the attribute and its
    /// first value in a single step.
    pub fn get_signed_attr(&self, oid: &Oid) -> Option<&Any<'a>> {
        self.signed_attrs
            .iter()
            .find(|attr| attr.attr_type.eq(oid))
            .and_then(|attr| attr.attr_values.first())
    }

    fn parse_issuer_and_serial_number(
        input: &[u8],
    ) -> BerResult<(X509Name, BigUint)> {
        parse_der_sequence_defined_g(|input: &[u8], _| {
            let (remainder, issuer) = X509Name::from_der(input).unwrap(); // TODO: handle error
            let (remainder, serial) = parse_der_integer(remainder)?;
            // RFC 5280 4.1.2.2: "The serial number MUST be a positive integer"
            // however, many CAs do not respect this and send integers with MSB set,
            // so we do not use `as_biguint()`.
            let serial = BigUint::from_bytes_be(serial.content.as_slice()?);
            Ok((remainder, (issuer, serial)))
        })(input)
    }

    fn parse_attributes(input: &[u8]) -> BerResult<Vec<Attribute>> {
        let mut remainder = input;
        let mut attributes = Vec::new();
        loop {
            remainder = match Attribute::parse(remainder) {
                Ok((remainder, attr)) => {
                    attributes.push(attr);
                    remainder
                }
                Err(Incomplete(_)) => return Ok((remainder, attributes)),
                Err(err) => return Err(err),
            }
        }
    }
}

impl<'a> TryFrom<&Any<'a>> for SignerInfo<'a> {
    type Error = asn1_rs::Error;

    fn try_from(any: &Any<'a>) -> Result<Self, Self::Error> {
        any.tag().assert_eq(asn1_rs::Tag::Sequence)?;
        Ok(Self::parse_inner(any.data).map(|(_, si)| si)?)
    }
}

/// ```text
/// AlgorithmIdentifier  ::=  SEQUENCE  {
///         algorithm               OBJECT IDENTIFIER,
///         parameters              ANY DEFINED BY algorithm OPTIONAL  }
/// ```
///
/// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2
#[derive(Debug)]
pub struct MyAlgorithmIdentifier<'a> {
    pub oid: Oid<'a>,
    pub parameters: DerObject<'a>,
}

impl<'a> MyAlgorithmIdentifier<'a> {
    pub fn parse(input: &'a [u8]) -> BerResult<Self> {
        parse_der_sequence_defined_g(|input: &[u8], _| {
            let (remainder, algorithm) = parse_der_oid(input)?;
            let (remainder, parameters) = parse_der(remainder)?;
            Ok((remainder, Self { oid: algorithm.as_oid_val()?, parameters }))
        })(input)
    }
}

/// ```text
/// Attribute ::= SEQUENCE {
///    attrType OBJECT IDENTIFIER,
///    attrValues SET OF AttributeValue }
///
///  AttributeValue ::= ANY
/// ```
///
/// https://datatracker.ietf.org/doc/html/rfc5652#section-5.3
pub struct Attribute<'a> {
    pub attr_type: Oid<'a>,
    pub attr_values: Vec<Any<'a>>,
}

impl<'a> Attribute<'a> {
    pub fn parse(input: &'a [u8]) -> BerResult<Self> {
        parse_der_sequence_defined_g(|data: &[u8], _| {
            let (remainder, attr_type) = parse_der_oid(data)?;
            let (remainder, attr_values) =
                parse_der_set_of_v(parse_ber_any)(remainder)?;

            Ok((
                remainder,
                Self { attr_type: attr_type.as_oid_val()?, attr_values },
            ))
        })(input)
    }
}

/// ASN.1 SpcIndirectDataContent
///
/// SpcIndirectDataContent ::= SEQUENCE {
///     data                    SpcAttributeTypeAndOptionalValue,
///     messageDigest           DigestInfo
/// }
///
pub struct IndirectDataContent<'a> {
    pub message_digest: DigestInfo<'a>,
}

impl<'a> IndirectDataContent<'a> {
    pub fn parse(input: &'a [u8]) -> BerResult<Self> {
        parse_der_sequence_defined_g(|input: &[u8], _| {
            Self::parse_inner(input)
        })(input)
    }

    pub fn parse_inner(input: &'a [u8]) -> BerResult<Self> {
        let (remainder, _data) = parse_der(input)?;
        let (remainder, message_digest) = DigestInfo::parse(remainder)?;

        Ok((remainder, Self { message_digest }))
    }
}

impl<'a> TryFrom<Any<'a>> for IndirectDataContent<'a> {
    type Error = asn1_rs::Error;

    fn try_from(any: Any<'a>) -> Result<Self, Self::Error> {
        any.tag().assert_eq(asn1_rs::Tag::Sequence)?;
        Ok(Self::parse_inner(any.data).map(|(_, ci)| ci)?)
    }
}

/// ASN.1 DigestInfo
///
/// DigestInfo ::= SEQUENCE {
///     digestAlgorithm         AlgorithmIdentifier,
///     digest                  OCTETSTRING
/// }
pub struct DigestInfo<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub digest: &'a [u8],
}

impl<'a> DigestInfo<'a> {
    pub fn parse(input: &'a [u8]) -> BerResult<Self> {
        parse_der_sequence_defined_g(|input: &[u8], _| {
            let (remainder, algorithm) =
                AlgorithmIdentifier::from_der(input).unwrap(); // TODO: handler error
            let (remainder, digest) = parse_der_octetstring(remainder)?;
            Ok((remainder, Self { algorithm, digest: digest.as_slice()? }))
        })(input)
    }
}

/// ASN.1 TSTInfo
///
/// ```text
/// TSTInfo ::= SEQUENCE  {
///    version                      INTEGER  { v1(1) },
///    policy                       TSAPolicyId,
///    messageImprint               MessageImprint,
///      -- MUST have the same value as the similar field in
///      -- TimeStampReq
///    serialNumber                 INTEGER,
///     -- Time-Stamping users MUST be ready to accommodate integers
///     -- up to 160 bits.
///    genTime                      GeneralizedTime,
///    accuracy                     Accuracy                 OPTIONAL,
///    ordering                     BOOLEAN             DEFAULT FALSE,
///    nonce                        INTEGER                  OPTIONAL,
///      -- MUST be present if the similar field was present
///      -- in TimeStampReq.  In that case it MUST have the same value.
///    tsa                          [0] GeneralName          OPTIONAL,
///    extensions                   [1] IMPLICIT Extensions   OPTIONAL  }
///
///
/// MessageImprint ::= SEQUENCE  {
///     hashAlgorithm                AlgorithmIdentifier,
///     hashedMessage                OCTET STRING  }
/// ```
///
/// https://datatracker.ietf.org/doc/html/rfc3161

pub struct TstInfo<'a> {
    pub hash_algorithm: AlgorithmIdentifier<'a>,
    pub hashed_message: &'a [u8],
}

impl<'a> TstInfo<'a> {
    pub fn from_der(
        data: &'a [u8],
    ) -> Result<Self, nom::Err<der_parser::error::Error>> {
        Self::parse(data).map(|(_, tst_info)| tst_info)
    }

    pub fn parse(input: &'a [u8]) -> BerResult<Self> {
        parse_der_sequence_defined_g(|input: &[u8], _| {
            let (remainder, _version) = parse_der_integer(input)?;
            let (remainder, _policy) = parse_der(remainder)?;

            let (remainder, (hash_algorithm, hashed_message)) =
                Self::parse_message_imprint(remainder)?;

            // Ignore the remaining fields, we don't need them.

            Ok((remainder, Self { hash_algorithm, hashed_message }))
        })(input)
    }

    fn parse_message_imprint(
        input: &'a [u8],
    ) -> BerResult<(AlgorithmIdentifier, &'a [u8])> {
        parse_der_sequence_defined_g(|input: &[u8], _| {
            let (remainder, hash_algorithm) =
                AlgorithmIdentifier::from_der(input).unwrap(); // TODO: handle error
            let (remainder, hashed_message) = parse_der(remainder)?;

            Ok((remainder, (hash_algorithm, hashed_message.as_slice()?)))
        })(input)
    }
}

/// ASN.1 SpcSpOpusInfo
///
/// SpcSpOpusInfo ::= SEQUENCE {
///     programName              [0] EXPLICIT SpcString OPTIONAL,
///     moreInfo                 [1] EXPLICIT SpcLink OPTIONAL,
/// }
pub struct SpcSpOpusInfo {
    pub program_name: Option<String>,
}

impl SpcSpOpusInfo {
    pub fn parse(input: &[u8]) -> BerResult<Self> {
        parse_der_sequence_defined_g(|input: &[u8], _| {
            Self::parse_inner(input)
        })(input)
    }

    fn parse_inner(input: &[u8]) -> BerResult<Self> {
        let (remainder, program_name) = OptTaggedParser::from(0)
            .parse_der(input, |_, content| Self::parse_spc_string(content))?;

        let (remainder, more_info) =
            OptTaggedParser::from(1).parse_der(remainder, |_, content| {
                let (rem, value) = parse_der(content)?;
                Ok((rem, value))
            })?;

        Ok((remainder, Self { program_name }))
    }

    fn parse_spc_string(input: &[u8]) -> BerResult<String> {
        alt((
            map_res(
                parse_der_tagged_implicit(
                    0,
                    parse_der_content(der_parser::der::Tag::BmpString),
                ),
                |s| {
                    string_from_utf16be(s.as_slice()?)
                        .ok_or(BerError::BerValueError)
                },
            ),
            map_res(
                parse_der_tagged_implicit(
                    1,
                    parse_der_content(der_parser::der::Tag::Ia5String),
                ),
                |s| Ok::<String, BerError>(String::from(s.as_str()?)),
            ),
        ))(input)
    }
}

impl TryFrom<&Any<'_>> for SpcSpOpusInfo {
    type Error = asn1_rs::Error;

    fn try_from(any: &Any) -> Result<Self, Self::Error> {
        Ok(Self::parse_inner(any.data).map(|(_, ci)| ci)?)
    }
}

/// Tries to create a string from a byte slice that contains the UTF-16BE
/// representation of the string.
///
/// There's a `String::from_utf16be` function that is currently unstable. If
/// it becomes stable we can use it and remove this function.
///
/// https://doc.rust-lang.org/alloc/string/struct.String.html#method.from_utf16be
fn string_from_utf16be(v: &[u8]) -> Option<String> {
    if v.len() % 2 != 0 {
        return None;
    }

    let codepoints = v
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]));

    let x: String =
        char::decode_utf16(codepoints).collect::<Result<_, _>>().ok()?;

    Some(x)
}
