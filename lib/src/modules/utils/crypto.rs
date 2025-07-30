use std::convert::TryFrom;

use super::asn1::{oid, oid_to_object_identifier};
use const_oid::db::rfc5912;
use const_oid::{AssociatedOid, ObjectIdentifier};
use digest::{Digest, Output};
use dsa::Components;
use ecdsa::signature::hazmat::PrehashVerifier;
use md2::Md2;
use md5::Md5;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::SignatureScheme;
use rsa::Pkcs1v15Sign;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use thiserror::Error;
use x509_parser::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};

/// Represents a public key.
pub enum PublicKey {
    Rsa(rsa::RsaPublicKey),
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

                let (_, y) = parse_ber_integer(key_bytes)
                    .map_err(|err| PublicKeyError::Der(err.into()))?;

                let (rem, p) = parse_ber_integer(parameters.data)
                    .map_err(|err| PublicKeyError::Der(err.into()))?;

                let (rem, q) = parse_ber_integer(rem)
                    .map_err(|err| PublicKeyError::Der(err.into()))?;

                let (_, g) = parse_ber_integer(rem)
                    .map_err(|err| PublicKeyError::Der(err.into()))?;

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

impl PublicKey {
    pub fn from_der(
        algorithm: ObjectIdentifier,
        der: &[u8],
    ) -> Result<Self, PublicKeyError> {
        match algorithm {
            rfc5912::SHA_1_WITH_RSA_ENCRYPTION => Ok(PublicKey::Rsa(
                rsa::RsaPublicKey::from_public_key_der(der)?,
            )),
            rfc5912::SHA_256_WITH_RSA_ENCRYPTION => Ok(PublicKey::Rsa(
                rsa::RsaPublicKey::from_public_key_der(der)?,
            )),
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
