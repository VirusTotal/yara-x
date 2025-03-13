/*! Implementation of the `vt` module.

This a VirusTotal-specific module that provides additional context and metadata
about files, URLs, IP addresses and domains scanned in VirusTotal.
*/

use std::net::IpAddr;
use std::rc::Rc;

use ipnet::IpNet;
use twistrs::permutate::Domain;

use crate::modules::prelude::*;
use crate::modules::protos::titan::*;
use crate::types::Struct;

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

#[module_export(method_of = "vt.net.EnrichedDomain")]
fn permutation_of(
    ctx: &mut ScanContext,
    domain: Rc<Struct>,
    s: RuntimeString,
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

    let permutations = match s.all() {
        Ok(permutations) => permutations,
        Err(_) => return false,
    };

    for permutation in permutations {
        if permutation.domain.fqdn.as_bytes() == domain.as_bytes() {
            return true;
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
    fn permutation_of() {
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
}
