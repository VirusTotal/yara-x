use crate::modules::olecf::parser::Olecf;
use crate::modules::protos;
use crate::modules::protos::msi::Msi as MsiProto;
use crate::modules::utils::authenticode::{
    AuthenticodeHasher, AuthenticodeParser,
};

pub struct Msi;

struct MsiHasher<'a> {
    olecf: &'a Olecf<'a>,
}

impl AuthenticodeHasher for MsiHasher<'_> {
    fn hash(&self, digest: &mut dyn digest::Update) -> Option<()> {
        let data = self.olecf.data();
        let sector_size = self.olecf.sector_size();
        if data.len() < sector_size {
            return None;
        }

        // 1. CFB Header:
        // First sector_size bytes, with CLSID (bytes 8..24)
        // and State Bits (bytes 24..28) zeroed out.
        let header_bytes = &data[..sector_size];
        if header_bytes.len() >= 28 {
            digest.update(&header_bytes[..8]);
            digest.update(&[0u8; 20]);
            digest.update(&header_bytes[28..]);
        } else {
            digest.update(header_bytes);
        }

        // 2. Stream contents:
        // Hash stream data for all streams except DigitalSignature and MsiDigitalSignatureEx.
        for (name, _) in self.olecf.streams() {
            let clean_name = name.trim_start_matches(|c: char| c < '\u{20}');
            if clean_name.eq_ignore_ascii_case("DigitalSignature")
                || clean_name.eq_ignore_ascii_case("MsiDigitalSignatureEx")
            {
                continue;
            }
            if let Ok(stream_data) = self.olecf.get_stream_data(name) {
                digest.update(&stream_data);
            }
        }

        Some(())
    }
}

impl Msi {
    pub fn parse<'a>(olecf: &Olecf<'a>) -> Result<MsiProto, &'static str> {
        // Find the digital signature stream
        let sig_stream = olecf.streams().find(|(name, _)| {
            let clean = name.trim_start_matches(|c: char| c < '\u{20}');
            clean.eq_ignore_ascii_case("DigitalSignature")
        });

        let (sig_name, _) =
            sig_stream.ok_or("No digital signature stream found")?;
        let sig_data = olecf
            .get_stream_data(sig_name)
            .map_err(|_| "Failed to read digital signature stream")?;

        let hasher = MsiHasher { olecf };
        let signatures = AuthenticodeParser::parse(&sig_data, &hasher)
            .map_err(|_| "Failed to parse signature")?;

        let mut msi_proto = MsiProto::new();
        let pb_signatures: Vec<_> =
            signatures.iter().map(protos::pe::Signature::from).collect();

        msi_proto.set_is_signed(!pb_signatures.is_empty());
        msi_proto.signatures = pb_signatures;

        Ok(msi_proto)
    }
}
