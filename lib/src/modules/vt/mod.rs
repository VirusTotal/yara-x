/*! Implementation of the `vt` module.

This a VirusTotal-specific module that provides additional context and metadata
about files, URLs, IP addresses and domains scanned in VirusTotal.
*/

use std::net::IpAddr;
use std::ops::BitAnd;
use std::rc::Rc;
use std::sync::LazyLock;

use ipnet::IpNet;
use protobuf::EnumFull;
use twistrs::permutate::Domain;

use crate::modules::prelude::*;
use crate::modules::protos::titan::*;
use crate::modules::protos::vtnet::enriched_domain::Permutation;
use crate::types::Struct;

static BITSQUATTING: LazyLock<i64> = LazyLock::new(|| {
    Struct::enum_value_i64(&Permutation::BITSQUATTING.descriptor()).unwrap()
});

static TYPO: LazyLock<i64> = LazyLock::new(|| {
    Struct::enum_value_i64(&Permutation::TYPO.descriptor()).unwrap()
});

static HYPHENATION: LazyLock<i64> = LazyLock::new(|| {
    Struct::enum_value_i64(&Permutation::HYPHENATION.descriptor()).unwrap()
});

static HOMOGLYPH: LazyLock<i64> = LazyLock::new(|| {
    Struct::enum_value_i64(&Permutation::HOMOGLYPH.descriptor()).unwrap()
});

static SUBDOMAIN: LazyLock<i64> = LazyLock::new(|| {
    Struct::enum_value_i64(&Permutation::SUBDOMAIN.descriptor()).unwrap()
});

static TLD: LazyLock<i64> = LazyLock::new(|| {
    Struct::enum_value_i64(&Permutation::TLD.descriptor()).unwrap()
});

#[module_main]
fn main(_data: &[u8], _meta: Option<&[u8]>) -> LiveHuntData {
    LiveHuntData::new()
}

#[module_export(method_of = "vt.net.EnrichedIP")]
fn in_range(
    ctx: &mut ScanContext,
    ip: Rc<Struct>,
    cidr: RuntimeString,
) -> bool {
    let cidr =
        match cidr.to_str(ctx).ok().and_then(|s| s.parse::<IpNet>().ok()) {
            Some(cidr) => cidr,
            None => return false,
        };

    let ip = ip.field_by_name("raw").unwrap().type_value.as_string();

    let ip = match ip.to_str().ok().and_then(|s| s.parse::<IpAddr>().ok()) {
        Some(ip) => ip,
        None => return false,
    };

    cidr.contains(&ip)
}

#[module_export(name = "permutation_of", method_of = "vt.net.EnrichedDomain")]
fn all_permutations(
    ctx: &mut ScanContext,
    domain: Rc<Struct>,
    s: RuntimeString,
) -> bool {
    permutations(ctx, domain, s, 0xffffff)
}

#[module_export(name = "permutation_of", method_of = "vt.net.EnrichedDomain")]
fn permutations(
    ctx: &mut ScanContext,
    domain: Rc<Struct>,
    s: RuntimeString,
    permutation_kinds: i64,
) -> bool {
    let domain = domain.field_by_name("raw").unwrap().type_value.as_string();

    let s = match s.to_str(ctx).ok().and_then(|s| Domain::new(s).ok()) {
        Some(s) => s,
        None => return false,
    };

    // The domain is not a permutation of itself.
    if s.fqdn.as_bytes() == domain.as_bytes() {
        return false;
    }

    if TYPO.bitand(&permutation_kinds) != 0 {
        for permutation in s
            .addition()
            .chain(s.insertion())
            .chain(s.omission())
            .chain(s.repetition())
            .chain(s.replacement())
            .chain(s.vowel_swap())
        {
            if permutation.domain.fqdn.as_bytes() == domain.as_bytes() {
                return true;
            }
        }
    }

    if HOMOGLYPH.bitand(&permutation_kinds) != 0 {
        if let Ok(permutations) = s.homoglyph() {
            for permutation in permutations {
                if permutation.domain.fqdn.as_bytes() == domain.as_bytes() {
                    return true;
                }
            }
        }
    }

    if HYPHENATION.bitand(&permutation_kinds) != 0 {
        for permutation in s.hyphentation() {
            if permutation.domain.fqdn.as_bytes() == domain.as_bytes() {
                return true;
            }
        }
    }

    if SUBDOMAIN.bitand(&permutation_kinds) != 0 {
        for permutation in s.subdomain() {
            if permutation.domain.fqdn.as_bytes() == domain.as_bytes() {
                return true;
            }
        }
    }

    if TLD.bitand(&permutation_kinds) != 0 {
        for permutation in s.tld() {
            if permutation.domain.fqdn.as_bytes() == domain.as_bytes() {
                return true;
            }
        }
    }

    if BITSQUATTING.bitand(&permutation_kinds) != 0 {
        for permutation in s.bitsquatting() {
            if permutation.domain.fqdn.as_bytes() == domain.as_bytes() {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use crate::modules::protos::titan::LiveHuntData;
    use crate::{Compiler, Scanner};
    use protobuf::text_format::parse_from_str;

    #[test]
    fn in_range_ipv4() {
        let vt_meta = Box::new(
            parse_from_str::<LiveHuntData>(
                r#"
                meta {
                    itw {
                        ip {
                            raw: "142.250.184.164"
                        }
                    }
                }
                net {
                    ip {
                        raw: "192.168.1.100"
                    }
                }"#,
            )
            .unwrap(),
        );

        let rule = r#"
           import "vt"
           rule test {
             condition:
               vt.net.ip.raw == "192.168.1.100"
               and vt.metadata.itw.ip.raw == "142.250.184.164"
               and vt.net.ip.in_range("192.168.1.100/32")
               and vt.net.ip.in_range("192.168.1.1/17")
               and vt.net.ip.in_range("192.168.1.0/24")
               and not vt.net.ip.in_range("192.168.1.0/32")
               and not vt.net.ip.in_range("192.168.1.0/31")
               and vt.metadata.itw.ip.in_range("142.250.184.164/20")
               and vt.metadata.itw.ip.in_range("142.250.176.0/20")
           }"#;

        let mut compiler = Compiler::new();

        compiler
            .enable_feature("ip_address")
            .enable_feature("file")
            .add_source(rule)
            .unwrap();

        let rules = compiler.build();

        assert_eq!(
            Scanner::new(&rules)
                .set_module_output(vt_meta)
                .unwrap()
                .scan(b"")
                .unwrap()
                .matching_rules()
                .len(),
            1
        );
    }

    #[test]
    fn in_range_ipv6() {
        let vt_meta = Box::new(
            parse_from_str::<LiveHuntData>(
                r#"
                meta {
                    itw {
                        ip {
                            raw: "2001:db8::1"
                        }
                    }
                }
                net {
                    ip {
                        raw: "2001:0DB8:7654:0010:FEDC:0000:0000:3210"
                    }
                }"#,
            )
            .unwrap(),
        );

        let rule = r#"
           import "vt"
           rule test {
             condition:
               vt.net.ip.raw == "2001:0DB8:7654:0010:FEDC:0000:0000:3210"
               and vt.metadata.itw.ip.raw == "2001:db8::1"
               and vt.net.ip.in_range("2001:db8::1/32")
               and not vt.net.ip.in_range("2001:db8::1/34")
               and vt.metadata.itw.ip.in_range("2001:db8::1/64")
           }"#;

        let mut compiler = Compiler::new();

        compiler
            .enable_feature("ip_address")
            .enable_feature("file")
            .add_source(rule)
            .unwrap();

        let rules = compiler.build();

        assert_eq!(
            Scanner::new(&rules)
                .set_module_output(vt_meta)
                .unwrap()
                .scan(b"")
                .unwrap()
                .matching_rules()
                .len(),
            1
        );
    }

    #[test]
    fn permutation_hyphenation() {
        let vt_meta = Box::new(
            parse_from_str::<LiveHuntData>(
                r#"
                net {
                    domain {
                        raw: "www.virus-total.com"
                    }
                }"#,
            )
            .unwrap(),
        );

        let rule = r#"
           import "vt"
           rule test {
             condition:
               vt.net.domain.permutation_of("www.virustotal.com")
               and vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.ALL)
               and vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.HYPHENATION)
               and not vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.TYPO)
               and not vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.HOMOGLYPH)
               and not vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.SUBDOMAIN)
               and not vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.TLD)
               and not vt.net.domain.permutation_of("www.virus-total.com")
               and not vt.net.domain.permutation_of("www.google.com")
           }"#;

        let mut compiler = Compiler::new();

        compiler
            .enable_feature("ip_address")
            .enable_feature("file")
            .add_source(rule)
            .unwrap();

        let rules = compiler.build();

        assert_eq!(
            Scanner::new(&rules)
                .set_module_output(vt_meta)
                .unwrap()
                .scan(b"")
                .unwrap()
                .matching_rules()
                .len(),
            1
        );
    }

    #[test]
    fn permutation_homoglyph() {
        let vt_meta = Box::new(
            parse_from_str::<LiveHuntData>(
                r#"
                net {
                    domain {
                        raw: "www.vırustotal.com"
                    }
                }"#,
            )
            .unwrap(),
        );

        let rule = r#"
           import "vt"
           rule test {
             condition:
               vt.net.domain.permutation_of("www.virustotal.com")
               and vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.ALL)
               and vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.HOMOGLYPH)
               and not vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.TYPO)
               and not vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.HYPHENATION)
               and not vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.SUBDOMAIN)
               and not vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.TLD)
               and not vt.net.domain.permutation_of("www.vırustotal.com")
               and not vt.net.domain.permutation_of("www.google.com")
           }"#;

        let mut compiler = Compiler::new();

        compiler
            .enable_feature("ip_address")
            .enable_feature("file")
            .add_source(rule)
            .unwrap();

        let rules = compiler.build();

        assert_eq!(
            Scanner::new(&rules)
                .set_module_output(vt_meta)
                .unwrap()
                .scan(b"")
                .unwrap()
                .matching_rules()
                .len(),
            1
        );
    }

    #[test]
    fn permutation_tld() {
        let vt_meta = Box::new(
            parse_from_str::<LiveHuntData>(
                r#"
                net {
                    domain {
                        raw: "www.virustotal.com.es"
                    }
                }"#,
            )
            .unwrap(),
        );

        let rule = r#"
           import "vt"
           rule test {
             condition:
               vt.net.domain.permutation_of("www.virustotal.com")
               and vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.ALL)
               and vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.TLD)
               and not vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.TYPO)
               and not vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.HYPHENATION)
               and not vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.HOMOGLYPH)
               and not vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.SUBDOMAIN)
               and not vt.net.domain.permutation_of("www.virustotal.com.es")
               and not vt.net.domain.permutation_of("www.google.com")
           }"#;

        let mut compiler = Compiler::new();

        compiler
            .enable_feature("ip_address")
            .enable_feature("file")
            .add_source(rule)
            .unwrap();

        let rules = compiler.build();

        assert_eq!(
            Scanner::new(&rules)
                .set_module_output(vt_meta)
                .unwrap()
                .scan(b"")
                .unwrap()
                .matching_rules()
                .len(),
            1
        );
    }

    #[test]
    fn permutation_typo() {
        let vt_meta = Box::new(
            parse_from_str::<LiveHuntData>(
                r#"
                net {
                    domain {
                        raw: "www.viirustotal.com"
                    }
                }"#,
            )
            .unwrap(),
        );

        let rule = r#"
           import "vt"
           rule test {
             condition:
               vt.net.domain.permutation_of("www.virustotal.com")
               and vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.ALL)
               and vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.TYPO)
               and not vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.HYPHENATION)
               and not vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.HOMOGLYPH)
               and not vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.SUBDOMAIN)
               and not vt.net.domain.permutation_of("www.viirustotal.com")
               // and not vt.net.domain.permutation_of("www.vırustotal.com")
               and not vt.net.domain.permutation_of("www.google.com")
           }"#;

        let mut compiler = Compiler::new();

        compiler
            .enable_feature("ip_address")
            .enable_feature("file")
            .add_source(rule)
            .unwrap();

        let rules = compiler.build();

        assert_eq!(
            Scanner::new(&rules)
                .set_module_output(vt_meta)
                .unwrap()
                .scan(b"")
                .unwrap()
                .matching_rules()
                .len(),
            1
        );
    }

    #[test]
    fn permutation_subdomain() {
        let vt_meta = Box::new(
            parse_from_str::<LiveHuntData>(
                r#"
                net {
                    domain {
                        raw: "www.virustotal.c.om"
                    }
                }"#,
            )
            .unwrap(),
        );

        let rule = r#"
           import "vt"
           rule test {
             condition:
               vt.net.domain.permutation_of("www.virustotal.com")
               and vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.ALL)
               and vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.SUBDOMAIN)
               and not vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.HYPHENATION)
               and not vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.HOMOGLYPH)
               and not vt.net.domain.permutation_of("www.virustotal.com", vt.Domain.Permutation.TYPO)
               and not vt.net.domain.permutation_of("www.vir.ustotal.com")
               and not vt.net.domain.permutation_of("www.google.com")
           }"#;

        let mut compiler = Compiler::new();

        compiler
            .enable_feature("ip_address")
            .enable_feature("file")
            .add_source(rule)
            .unwrap();

        let rules = compiler.build();

        assert_eq!(
            Scanner::new(&rules)
                .set_module_output(vt_meta)
                .unwrap()
                .scan(b"")
                .unwrap()
                .matching_rules()
                .len(),
            1
        );
    }
}
