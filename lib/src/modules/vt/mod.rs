/*! Implementation of the `vt` module.

This a VirusTotal-specific module that provides additional context and metadata
about files, URLs, IP addresses and domains scanned in VirusTotal.
*/

mod bitsquatting;
mod homoglyphs;
mod interleaved;
mod typos;

use std::net::IpAddr;
use std::ops::BitAnd;
use std::rc::Rc;
use std::sync::LazyLock;

use bstr::BStr;
use ipnet::IpNet;
use protobuf::EnumFull;

use crate::modules::prelude::*;
use crate::modules::protos::titan::*;
use crate::modules::protos::vtnet::enriched_domain::Permutation;
use crate::modules::vt::bitsquatting::bitsquatting;
use crate::modules::vt::homoglyphs::is_homoglyph;
use crate::modules::vt::interleaved::interleaved;
use crate::modules::vt::typos::{
    doubling, insertion, omission, replacement, swap, vowel_swap,
};
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
    target: RuntimeString,
) -> bool {
    permutations(ctx, domain, target, 0x1F)
}

#[module_export(name = "permutation_of", method_of = "vt.net.EnrichedDomain")]
fn permutations(
    ctx: &mut ScanContext,
    scanned_domain: Rc<Struct>,
    legitimate_domain: RuntimeString,
    permutation_kinds: i64,
) -> bool {
    let scanned_domain =
        scanned_domain.field_by_name("raw").unwrap().type_value.as_string();

    let scanned_domain = match parse_domain(scanned_domain.as_bstr()) {
        Some(d) => d,
        None => return false,
    };

    let legit_domain = match parse_domain(legitimate_domain.as_bstr(ctx)) {
        Some(s) => s,
        None => return false,
    };

    // The domain is not a permutation of itself.
    if scanned_domain == legit_domain {
        return false;
    }

    // Both domains must have the same TLD.
    if scanned_domain.tld != legit_domain.tld {
        return false;
    }

    let scanned_prefix = scanned_domain.prefix;
    let scanned_domain = match scanned_domain.domain {
        Some(d) => d,
        None => return false,
    };

    let legit_prefix = legit_domain.prefix;
    let legit_domain = match legit_domain.domain {
        Some(d) => d,
        None => return false,
    };

    if TYPO.bitand(&permutation_kinds) != 0
        && (insertion(legit_domain, scanned_domain)
            || omission(legit_domain, scanned_domain)
            || replacement(legit_domain, scanned_domain)
            || doubling(legit_domain, scanned_domain)
            || swap(legit_domain, scanned_domain)
            || vowel_swap(legit_domain, scanned_domain))
    {
        return true;
    }

    if HOMOGLYPH.bitand(&permutation_kinds) != 0
        && is_homoglyph(legit_domain, scanned_domain)
    {
        return true;
    }

    if BITSQUATTING.bitand(&permutation_kinds) != 0
        && bitsquatting(legit_domain, scanned_domain)
    {
        return true;
    }

    if SUBDOMAIN.bitand(&permutation_kinds) != 0 {
        if let (Some(legit), Some(scanned)) = (legit_prefix, scanned_prefix) {
            if interleaved(legit, scanned, '.') {
                return true;
            }
        }
    }

    if HYPHENATION.bitand(&permutation_kinds) != 0
        && interleaved(legit_domain, scanned_domain, '-')
    {
        return true;
    }

    false
}

/// Parses a domain name and returns its parts. For instance,
/// for `www.virustotal.com` it returns:
///
/// ```text
/// DomainParts {
///   prefix: Some("www.virustotal"),
///   subdomain: Some("www"),
///   domain: Some("virustotal"),
///   tld: "com",
/// }
/// ```
///
/// Returns `None` if the argument is not a valid domain name.
fn parse_domain(domain: &BStr) -> Option<DomainParts> {
    let domain_len = domain.len();
    let suffix_len = psl::suffix(domain)?.as_bytes().len();
    let tld = domain[domain_len - suffix_len..].to_str().ok()?;
    let suffix_plus_dot = suffix_len + 1;

    if domain_len <= suffix_plus_dot {
        return Some(DomainParts {
            prefix: None,
            subdomain: None,
            domain: None,
            tld,
        });
    }

    let prefix = domain.get(..domain_len - suffix_plus_dot)?.to_str().ok()?;

    let (mut subdomain, mut domain) = match prefix.rsplit_once('.') {
        Some((subdomain, domain)) => (Some(subdomain), Some(domain)),
        None => (None, Some(prefix)),
    };

    // The psl::suffix function can incorrectly parse domains like
    // "www.gov.uk", returning "www" as the domain and "gov.uk" as the public
    // suffix. This happens because both "gov.uk" and "uk" are valid public
    // suffixes, leading to ambiguity:
    //
    // Possible interpretations:
    // - "www.gov.uk": subdomain="www", domain="gov", suffix="uk" (correct)
    // - "www.gov.uk": subdomain="", domain="www", suffix="gov.uk" (incorrect)
    //
    // However, for "www.tfl.gov.uk":
    // - subdomain="www.tfl", domain="gov", suffix="uk" (incorrect)
    // - subdomain="www", domain="tfl", suffix="gov.uk" (correct)
    //
    // This workaround checks for common subdomains (e.g., "www") and correctly
    // assigns the domain and subdomain fields to handle these cases.
    if matches!(
        domain,
        Some("www")
            | Some("ftp")
            | Some("m")
            | Some("mail")
            | Some("webmail")
            | Some("ns1")
            | Some("ns2")
    ) {
        subdomain = domain;
        domain = None;
    }

    Some(DomainParts { prefix: Some(prefix), subdomain, domain, tld })
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DomainParts<'a> {
    pub prefix: Option<&'a str>,
    pub subdomain: Option<&'a str>,
    pub domain: Option<&'a str>,
    pub tld: &'a str,
}

#[cfg(test)]
mod tests {
    use crate::modules::protos::titan::LiveHuntData;
    use crate::modules::vt::{parse_domain, DomainParts};
    use crate::{Compiler, Scanner};
    use bstr::BStr;
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

    macro_rules! squatting {
        ($legit_domain:literal, $scanned_domain:literal) => {{
            let vt_meta = Box::new(
                parse_from_str::<LiveHuntData>(
                    format!(
                        "net {{ domain {{ raw: \"{}\" }} }}",
                        $scanned_domain
                    )
                    .as_str(),
                )
                .unwrap(),
            );

            let rule = format!(
                r#"
           import "vt"
           rule test {{
             condition:
               vt.net.domain.permutation_of("{}")
           }}"#,
                $legit_domain
            );

            let mut compiler = Compiler::new();

            compiler
                .enable_feature("ip_address")
                .enable_feature("file")
                .add_source(rule.as_str())
                .unwrap();

            let rules = compiler.build();

            let result = Scanner::new(&rules)
                .set_module_output(vt_meta)
                .unwrap()
                .scan(b"")
                .unwrap()
                .matching_rules()
                .len()
                == 1;

            result
        }};
    }

    #[test]
    fn test_parse_domain() {
        assert_eq!(
            parse_domain(BStr::new("www.google.com")),
            Some(DomainParts {
                prefix: Some("www.google"),
                subdomain: Some("www"),
                domain: Some("google"),
                tld: "com"
            })
        );

        assert_eq!(
            parse_domain(BStr::new("gov.uk")),
            Some(DomainParts {
                prefix: None,
                subdomain: None,
                domain: None,
                tld: "gov.uk"
            })
        );

        assert_eq!(
            parse_domain(BStr::new("www.gov.uk")),
            Some(DomainParts {
                prefix: Some("www"),
                subdomain: Some("www"),
                domain: None,
                tld: "gov.uk"
            })
        );

        assert_eq!(
            parse_domain(BStr::new("ftp.gov.uk")),
            Some(DomainParts {
                prefix: Some("ftp"),
                subdomain: Some("ftp"),
                domain: None,
                tld: "gov.uk"
            })
        );

        assert_eq!(
            parse_domain(BStr::new("www.ncbi.nlm.nih.gov")),
            Some(DomainParts {
                prefix: Some("www.ncbi.nlm.nih"),
                subdomain: Some("www.ncbi.nlm"),
                domain: Some("nih"),
                tld: "gov"
            })
        );
    }

    #[test]
    fn test_squatting() {
        // the 'b' was omitted.
        assert!(squatting!("bankofamerica.com", "ankofamerica.com"));
        // the `o` was omitted.
        assert!(squatting!("bankofamerica.com", "bankfamerica.com"));
        // the `k` is repeated.
        assert!(squatting!("bankofamerica.com", "bankkofamerica.com"));
        // the `l` was inserted.
        assert!(squatting!("bankofamerica.com", "banklofamerica.com"));
        // 'q' is close to 'a' in the keyboard.
        assert!(squatting!("bankofamerica.com", "bqnkofamerica.com"));
        // 'ɑ' is a homoglyph of 'a'
        assert!(squatting!("bankofamerica.com", "bɑnkofamerica.com"));
        // transposition of "a" and "b".
        assert!(squatting!("bankofamerica.com", "abnkofamerica.com"));
        // insertion of hyphens.
        assert!(squatting!("bankofamerica.com", "bank-of-america.com"));
        // the `e` was replaced with `d`, which is close in the keyboard.
        assert!(squatting!("bankofamerica.com", "bankofamdrica.com"));
        // the vowel `a` was replaced with `e`.
        assert!(squatting!("bankofamerica.com", "bonkofamerica.com"));
        // bitsquatting, the `k` and the `c` differ in one bit.
        assert!(squatting!("bankofamerica.com", "bancofamerica.com"));
        // subdomain
        assert!(squatting!("bankofamerica.com", "bankof.america.com"));
        assert!(squatting!("bankofamerica.com", "bank.of.america.com"));

        // test some negative cases
        assert!(!squatting!("www.google.com", "notifications.google.com"));
        assert!(!squatting!("www.ing.com", "www.ncbi.nlm.nih.gov"));
        assert!(!squatting!("www.google.com", "www.goggle.es"));
        assert!(!squatting!("www.google.com", "www.goore.com"));
    }
}
