/*! Implementation of the `vt` module.

This a VirusTotal-specific module that provides additional context and metadata
about files, URLs, IP addresses and domains scanned in VirusTotal.
*/

use std::net::IpAddr;
#[cfg(feature = "vt-module-domain-permutations")]
use std::ops::BitAnd;
use std::rc::Rc;
#[cfg(feature = "vt-module-domain-permutations")]
use std::sync::LazyLock;

use ipnet::IpNet;
#[cfg(feature = "vt-module-domain-permutations")]
use protobuf::EnumFull;
#[cfg(feature = "vt-module-domain-permutations")]
use twistrs::permutate::Domain;

use crate::modules::prelude::*;
use crate::modules::protos::titan::*;
#[cfg(feature = "vt-module-domain-permutations")]
use crate::modules::protos::vtnet::enriched_domain::Permutation;
use crate::types::Struct;

#[cfg(feature = "vt-module-domain-permutations")]
static BITSQUATTING: LazyLock<i64> = LazyLock::new(|| {
    Struct::enum_value_i64(&Permutation::BITSQUATTING.descriptor()).unwrap()
});

#[cfg(feature = "vt-module-domain-permutations")]
static TYPO: LazyLock<i64> = LazyLock::new(|| {
    Struct::enum_value_i64(&Permutation::TYPO.descriptor()).unwrap()
});

#[cfg(feature = "vt-module-domain-permutations")]
static HYPHENATION: LazyLock<i64> = LazyLock::new(|| {
    Struct::enum_value_i64(&Permutation::HYPHENATION.descriptor()).unwrap()
});

#[cfg(feature = "vt-module-domain-permutations")]
static HOMOGLYPH: LazyLock<i64> = LazyLock::new(|| {
    Struct::enum_value_i64(&Permutation::HOMOGLYPH.descriptor()).unwrap()
});

#[cfg(feature = "vt-module-domain-permutations")]
static SUBDOMAIN: LazyLock<i64> = LazyLock::new(|| {
    Struct::enum_value_i64(&Permutation::SUBDOMAIN.descriptor()).unwrap()
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

#[cfg(feature = "vt-module-domain-permutations")]
#[module_export(name = "permutation_of", method_of = "vt.net.EnrichedDomain")]
fn all_permutations(
    ctx: &mut ScanContext,
    domain: Rc<Struct>,
    target: RuntimeString,
) -> bool {
    permutations(ctx, domain, target, 0xffffff)
}

#[cfg(feature = "vt-module-domain-permutations")]
#[module_export(name = "permutation_of", method_of = "vt.net.EnrichedDomain")]
fn permutations(
    ctx: &mut ScanContext,
    domain: Rc<Struct>,
    target: RuntimeString,
    permutation_kinds: i64,
) -> bool {
    let domain = match domain
        .field_by_name("raw")
        .unwrap()
        .type_value
        .as_string()
        .to_str()
        .ok()
        .and_then(|d| Domain::new(d).ok())
    {
        Some(d) => d,
        None => return false,
    };

    let target =
        match target.to_str(ctx).ok().and_then(|t| Domain::new(t).ok()) {
            Some(s) => s,
            None => return false,
        };

    // The domain is not a permutation of itself.
    if domain == target {
        return false;
    }

    if TYPO.bitand(&permutation_kinds) != 0 {
        for permutation in target
            .addition()
            .chain(target.insertion())
            .chain(target.omission())
            .chain(target.repetition())
            .chain(target.replacement())
            .chain(target.vowel_swap())
        {
            if permutation.domain == domain {
                return true;
            }
        }
    }

    if HOMOGLYPH.bitand(&permutation_kinds) != 0 {
        if let Ok(permutations) = target.homoglyph() {
            for permutation in permutations {
                if permutation.domain == domain {
                    return true;
                }
            }
        }
    }

    if HYPHENATION.bitand(&permutation_kinds) != 0 {
        for permutation in target.hyphentation() {
            if permutation.domain == domain {
                return true;
            }
        }
    }

    if SUBDOMAIN.bitand(&permutation_kinds) != 0 {
        for permutation in target.subdomain() {
            if permutation.domain == domain {
                return true;
            }
        }
    }

    if BITSQUATTING.bitand(&permutation_kinds) != 0 {
        for permutation in target.bitsquatting() {
            if permutation.domain == domain {
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

    #[cfg(feature = "vt-module-domain-permutations")]
    #[test]
    fn permutation_constants() {
        let rule = r#"
           import "vt"
           rule test {
             condition:
               vt.Domain.Permutation.ALL == vt.Domain.Permutation.TYPO
                | vt.Domain.Permutation.HYPHENATION
                | vt.Domain.Permutation.HOMOGLYPH
                | vt.Domain.Permutation.SUBDOMAIN
                | vt.Domain.Permutation.BITSQUATTING
           }"#;

        let mut compiler = Compiler::new();

        compiler
            .enable_feature("ip_address")
            .enable_feature("file")
            .add_source(rule)
            .unwrap();

        let rules = compiler.build();

        assert_eq!(
            Scanner::new(&rules).scan(b"").unwrap().matching_rules().len(),
            1
        );
    }

    #[cfg(feature = "vt-module-domain-permutations")]
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

    #[cfg(feature = "vt-module-domain-permutations")]
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

    #[cfg(feature = "vt-module-domain-permutations")]
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

    #[cfg(feature = "vt-module-domain-permutations")]
    #[test]
    fn permutation_subdomain() {
        let vt_meta = Box::new(
            parse_from_str::<LiveHuntData>(
                r#"
                net {
                    domain {
                        raw: "www.vir.ustotal.com"
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
