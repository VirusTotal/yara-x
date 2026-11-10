use std::convert::TryFrom;

use const_oid::db::rfc5912;
use const_oid::{AssociatedOid, ObjectIdentifier};
use digest::{Digest, Output};
use dsa::Components;
use ecdsa::signature::hazmat::PrehashVerifier;
use md2::Md2;
use md5::Md5;
use rsa::Pkcs1v15Sign;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::SignatureScheme;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use thiserror::Error;
use x509_parser::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};

#[cfg(feature = "logging")]
use log::error;

use super::asn1::{oid, oid_to_object_identifier};

/// Represents a public key.
pub enum PublicKey {
    Rsa(rsa::PublicKey),
    Dsa(dsa::VerifyingKey),
    EcdsaP256(p256::ecdsa::VerifyingKey),
    EcdsaP384(p384::ecdsa::VerifyingKey),
}

#[derive(Error, Debug)]
pub enum PublicKeyError {
    #[error("PKCS1 error")]
    Pkcs1(#[from] rsa::pkcs1::Error),

    #[error("PKCS8 error")]
    Pkcs8(#[from] rsa::pkcs8::spki::Error),

    #[error("RSA error")]
    Rsa(#[from] rsa::Error),

    #[error("DER parsing error")]
    Der(#[from] der_parser::error::BerError),

    #[error("ECDSA error")]
    Ecdsa(#[from] ecdsa::Error),

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
            .map_err(|_| PublicKeyError::InvalidAlgorithm)?
        {
            rfc5912::RSA_ENCRYPTION => Ok(Self::Rsa(rsa_key_from_pkcs1_der(
                spki.subject_public_key.as_ref(),
            )?)),
            rfc5912::ID_DSA => {
                let parameters = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .ok_or(Self::Error::MissingAlgorithmParameters)?;

                let key_bytes = spki.subject_public_key.as_ref();

                use der_parser::ber::parse_ber_integer;

                let (_, y) = parse_ber_integer(key_bytes)
                    .map_err(|err| PublicKeyError::Der(err.into()))?;

                let (rem, p) = parse_ber_integer(parameters.data)
                    .map_err(|err| PublicKeyError::Der(err.into()))?;

                let (rem, q) = parse_ber_integer(rem)
                    .map_err(|err| PublicKeyError::Der(err.into()))?;

                let (_, g) = parse_ber_integer(rem)
                    .map_err(|err| PublicKeyError::Der(err.into()))?;

                let mut p_bytes = p.content.as_slice()?;
                let mut q_bytes = q.content.as_slice()?;
                let mut g_bytes = g.content.as_slice()?;
                let mut y_bytes = y.content.as_slice()?;

                while let Some((&0, rest)) = p_bytes.split_first() {
                    p_bytes = rest;
                }
                while let Some((&0, rest)) = q_bytes.split_first() {
                    q_bytes = rest;
                }
                while let Some((&0, rest)) = g_bytes.split_first() {
                    g_bytes = rest;
                }
                while let Some((&0, rest)) = y_bytes.split_first() {
                    y_bytes = rest;
                }

                let p = dsa::BoxedUint::from_be_slice(
                    p_bytes,
                    (p_bytes.len() * 8) as u32,
                )
                .map_err(|_| PublicKeyError::InvalidAlgorithm)?;

                let q = dsa::BoxedUint::from_be_slice(
                    q_bytes,
                    (q_bytes.len() * 8) as u32,
                )
                .map_err(|_| PublicKeyError::InvalidAlgorithm)?;

                let g = dsa::BoxedUint::from_be_slice(
                    g_bytes,
                    (g_bytes.len() * 8) as u32,
                )
                .map_err(|_| PublicKeyError::InvalidAlgorithm)?;

                let y = dsa::BoxedUint::from_be_slice(
                    y_bytes,
                    (y_bytes.len() * 8) as u32,
                )
                .map_err(|_| PublicKeyError::InvalidAlgorithm)?;

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
                    .map_err(|_| PublicKeyError::InvalidAlgorithm)?;

                match oid {
                    rfc5912::SECP_256_R_1 => Ok(Self::EcdsaP256(
                        ecdsa::VerifyingKey::from_sec1_bytes(
                            spki.subject_public_key.as_ref(),
                        )?,
                    )),
                    rfc5912::SECP_384_R_1 => Ok(Self::EcdsaP384(
                        ecdsa::VerifyingKey::from_sec1_bytes(
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

/// Minimum RSA modulus size, in bits, accepted when decoding public keys.
///
/// `rsa` rejects moduli shorter than `rsa::PublicKey::MIN_SIZE` (1024 bits)
/// by default, but signatures in older files use shorter keys. Like rsa
/// 0.10.0-rc.19, which only applied that minimum to key generation, we
/// don't impose any minimum here.
const RSA_MIN_KEY_BITS: usize = 1;

/// Object identifier for `id-RSASSA-PSS` (RFC 4055).
const ID_RSASSA_PSS: rsa::pkcs8::ObjectIdentifier =
    rsa::pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

/// Decodes a PKCS#1 `RSAPublicKey` from DER.
///
/// This is equivalent to `rsa::pkcs1::DecodeRsaPublicKey::from_pkcs1_der`,
/// except that it accepts moduli shorter than 1024 bits. See
/// [`RSA_MIN_KEY_BITS`].
fn rsa_key_from_pkcs1_der(
    der: &[u8],
) -> Result<rsa::PublicKey, PublicKeyError> {
    use rsa::pkcs1::der::Decode;

    let key = rsa::pkcs1::RsaPublicKeyRef::from_der(der)
        .map_err(rsa::pkcs1::Error::from)?;

    let to_uint = |bytes: &[u8]| {
        let bits = u32::try_from(bytes.len())
            .ok()
            .and_then(|len| len.checked_mul(8))
            .ok_or(rsa::pkcs1::Error::KeyMalformed)?;
        rsa::BoxedUint::from_be_slice(bytes, bits)
            .map_err(|_| rsa::pkcs1::Error::KeyMalformed)
    };

    Ok(rsa::PublicKey::new_with_size_limits(
        to_uint(key.modulus.as_bytes())?,
        to_uint(key.public_exponent.as_bytes())?,
        RSA_MIN_KEY_BITS..=rsa::PublicKey::MAX_SIZE,
    )?)
}

/// Decodes an RSA `SubjectPublicKeyInfo` from DER.
///
/// This is equivalent to `rsa::pkcs8::DecodePublicKey::from_public_key_der`,
/// including its validation of the algorithm identifier, except that it
/// accepts moduli shorter than 1024 bits. See [`RSA_MIN_KEY_BITS`].
fn rsa_key_from_spki_der(
    der: &[u8],
) -> Result<rsa::PublicKey, PublicKeyError> {
    use rsa::pkcs8::der::Decode;
    use rsa::pkcs8::spki::Error;

    let spki = rsa::pkcs8::SubjectPublicKeyInfoRef::from_der(der)
        .map_err(Error::from)?;

    match spki.algorithm.oid {
        rsa::pkcs1::ALGORITHM_OID => {
            if spki.algorithm.parameters_any()?
                != rsa::pkcs8::der::asn1::Null.into()
            {
                return Err(Error::KeyMalformed.into());
            }
        }
        ID_RSASSA_PSS => {
            if spki.algorithm.parameters.is_some() {
                return Err(Error::KeyMalformed.into());
            }
        }
        oid => return Err(Error::OidUnknown { oid }.into()),
    }

    rsa_key_from_pkcs1_der(
        spki.subject_public_key.as_bytes().ok_or(Error::KeyMalformed)?,
    )
}

impl PublicKey {
    pub fn from_der(
        algorithm: ObjectIdentifier,
        der: &[u8],
    ) -> Result<Self, PublicKeyError> {
        match algorithm {
            rfc5912::SHA_1_WITH_RSA_ENCRYPTION
            | rfc5912::SHA_256_WITH_RSA_ENCRYPTION => {
                Ok(PublicKey::Rsa(rsa_key_from_spki_der(der)?))
            }
            rfc5912::ECDSA_WITH_SHA_256 => Ok(PublicKey::EcdsaP256(
                ecdsa::VerifyingKey::from_public_key_der(der)?,
            )),
            _ => Err(PublicKeyError::UnknownAlgorithm(algorithm)),
        }
    }

    pub fn verify(
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

    fn verify_impl<D: Digest + AssociatedOid>(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        let digest = D::digest(message);
        self.verify_digest::<D>(digest, signature)
    }

    pub fn verify_digest<D: Digest + AssociatedOid>(
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
                use dsa::signature::hazmat::PrehashVerifier;
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

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::FromDer;

    // Keys and signatures below were generated with OpenSSL. Each signature
    // is a PKCS#1 v1.5 signature of SHA-256("yara-x").

    // 512-bit modulus.
    const RSA_512_N: &str = "bc105b6c2b1df59226754717564eee86388a8593eb089d2e\
        e69ec2dfd98fef93f72f759103b287253dbeeeb6e1f0d9912fb4d64f004940b1eda875\
        55a6bc796d";

    const RSA_512_SPKI: &str = "305c300d06092a864886f70d0101010500034b00304802\
        4100bc105b6c2b1df59226754717564eee86388a8593eb089d2ee69ec2dfd98fef93f7\
        2f759103b287253dbeeeb6e1f0d9912fb4d64f004940b1eda87555a6bc796d02030100\
        01";

    const RSA_512_SIG: &str = "7a02b771937d159883bbbbdd4bdd9abdf5c64719445299\
        311d126f30161924c9da8fcc7090372ede54811852f031b9afd471ad1704797f06915d\
        dac375aabbd7";

    // 520-bit modulus, which isn't a multiple of the 64-bit limb size.
    const RSA_520_SPKI: &str = "305d300d06092a864886f70d0101010500034c00304902\
        4200ba54b8e7c013161f78e9dfed5ccc9222629726f65b9f3165da6531fbebb1acb062\
        c90671d22efc435fd61d732cd61c564181c3e32775f7e9602711c276af72e09b020301\
        0001";

    const RSA_520_SIG: &str = "52bed10da0486862e86bbd4b0fe26a1b583314944cf4ae\
        87b722ef3856f90ac33cc307e48a38fe1764e973359fbe513ff490027f07c5d991911c\
        5c9984adbe4660";

    // Contents of the OBJECT IDENTIFIERs used below.
    const OID_RSA_ENCRYPTION: &[u8] =
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    const OID_RSASSA_PSS: &[u8] =
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
    const OID_EC_PUBLIC_KEY: &[u8] =
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

    const NULL: &[u8] = &[0x05, 0x00];
    const E_65537: &[u8] = &[0x01, 0x00, 0x01];

    /// Encodes a DER tag-length-value.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if content.len() < 0x80 {
            out.push(content.len() as u8);
        } else {
            let len = content.len().to_be_bytes();
            let len = &len[len.iter().position(|&b| b != 0).unwrap()..];
            out.push(0x80 | len.len() as u8);
            out.extend_from_slice(len);
        }
        out.extend_from_slice(content);
        out
    }

    /// Encodes a positive DER INTEGER from its big-endian bytes.
    fn integer(be: &[u8]) -> Vec<u8> {
        let mut content = Vec::new();
        if be[0] & 0x80 != 0 {
            content.push(0);
        }
        content.extend_from_slice(be);
        tlv(0x02, &content)
    }

    /// Encodes a PKCS#1 `RSAPublicKey`.
    fn pkcs1(n: &[u8], e: &[u8]) -> Vec<u8> {
        tlv(0x30, &[integer(n), integer(e)].concat())
    }

    /// Encodes a `SubjectPublicKeyInfo` wrapping `key`.
    fn spki(oid: &[u8], params: Option<&[u8]>, key: &[u8]) -> Vec<u8> {
        let mut algorithm = tlv(0x06, oid);
        if let Some(params) = params {
            algorithm.extend_from_slice(params);
        }
        let bit_string = [&[0x00], key].concat();
        tlv(0x30, &[tlv(0x30, &algorithm), tlv(0x03, &bit_string)].concat())
    }

    fn n_512() -> Vec<u8> {
        hex::decode(RSA_512_N).unwrap()
    }

    fn from_der(der: &[u8]) -> Result<PublicKey, PublicKeyError> {
        PublicKey::from_der(rfc5912::SHA_256_WITH_RSA_ENCRYPTION, der)
    }

    fn from_spki(der: &[u8]) -> Result<PublicKey, PublicKeyError> {
        let (_, spki) = SubjectPublicKeyInfo::from_der(der).unwrap();
        PublicKey::try_from(&spki)
    }

    fn assert_verifies(key: &PublicKey, sig: &str) {
        let sig = hex::decode(sig).unwrap();
        assert!(key.verify_digest::<Sha256>(Sha256::digest(b"yara-x"), &sig));
        assert!(!key.verify_digest::<Sha256>(Sha256::digest(b"yara"), &sig));
    }

    #[test]
    fn rsa_keys_shorter_than_1024_bits_verify() {
        for (spki, sig) in
            [(RSA_512_SPKI, RSA_512_SIG), (RSA_520_SPKI, RSA_520_SIG)]
        {
            let der = hex::decode(spki).unwrap();
            assert_verifies(&from_der(&der).unwrap(), sig);
            assert_verifies(&from_spki(&der).unwrap(), sig);
        }
    }

    #[test]
    fn der_builder_matches_openssl() {
        assert_eq!(
            spki(OID_RSA_ENCRYPTION, Some(NULL), &pkcs1(&n_512(), E_65537)),
            hex::decode(RSA_512_SPKI).unwrap()
        );
    }

    #[test]
    fn rsa_spki_algorithm_parameters() {
        let key = pkcs1(&n_512(), E_65537);

        // `rsaEncryption` requires NULL parameters.
        assert!(from_der(&spki(OID_RSA_ENCRYPTION, Some(NULL), &key)).is_ok());
        assert!(matches!(
            from_der(&spki(OID_RSA_ENCRYPTION, None, &key)),
            Err(PublicKeyError::Pkcs8(_))
        ));
        assert!(matches!(
            from_der(&spki(OID_RSA_ENCRYPTION, Some(&[0x04, 0x00]), &key)),
            Err(PublicKeyError::Pkcs8(_))
        ));

        // `id-RSASSA-PSS` requires absent parameters.
        assert!(from_der(&spki(OID_RSASSA_PSS, None, &key)).is_ok());
        assert!(matches!(
            from_der(&spki(OID_RSASSA_PSS, Some(NULL), &key)),
            Err(PublicKeyError::Pkcs8(_))
        ));

        // Other algorithms are rejected.
        assert!(matches!(
            from_der(&spki(OID_EC_PUBLIC_KEY, Some(NULL), &key)),
            Err(PublicKeyError::Pkcs8(_))
        ));
    }

    #[test]
    fn rsa_spki_trailing_data() {
        let mut der = hex::decode(RSA_512_SPKI).unwrap();
        der.push(0x00);
        assert!(matches!(from_der(&der), Err(PublicKeyError::Pkcs8(_))));
    }

    #[test]
    fn invalid_rsa_keys() {
        // Even modulus.
        let mut n = n_512();
        *n.last_mut().unwrap() &= 0xfe;
        let key = pkcs1(&n, E_65537);
        assert!(matches!(
            from_der(&spki(OID_RSA_ENCRYPTION, Some(NULL), &key)),
            Err(PublicKeyError::Rsa(rsa::Error::InvalidModulus))
        ));
        assert!(matches!(
            from_spki(&spki(OID_RSA_ENCRYPTION, Some(NULL), &key)),
            Err(PublicKeyError::Rsa(rsa::Error::InvalidModulus))
        ));

        // Modulus longer than `rsa::PublicKey::MAX_SIZE` (8192 bits).
        let mut n = vec![0xff; rsa::PublicKey::MAX_SIZE / 8 + 1];
        n[0] = 0x01;
        assert!(matches!(
            rsa_key_from_pkcs1_der(&pkcs1(&n, E_65537)),
            Err(PublicKeyError::Rsa(rsa::Error::ModulusTooLarge))
        ));

        // Public exponent too small.
        assert!(matches!(
            rsa_key_from_pkcs1_der(&pkcs1(&n_512(), &[0x01])),
            Err(PublicKeyError::Rsa(rsa::Error::PublicExponentTooSmall))
        ));

        // Malformed PKCS#1 structure.
        assert!(matches!(
            rsa_key_from_pkcs1_der(&tlv(0x30, &integer(&n_512()))),
            Err(PublicKeyError::Pkcs1(_))
        ));
    }
}
