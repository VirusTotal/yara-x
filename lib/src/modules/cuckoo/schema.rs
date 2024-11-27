use std::fmt;

use serde::de::Error;
use serde::{de::Visitor, Deserialize, Deserializer};

#[derive(serde::Deserialize, Debug)]
pub(super) struct DomainJson {
    pub domain: String,
}

#[derive(serde::Deserialize, Debug)]
pub(super) struct HttpJson {
    #[serde(rename = "user-agent")]
    pub user_agent: Option<String>,
    pub method: Option<String>, // string ftw
    pub uri: String,
}

#[derive(serde::Deserialize, Debug)]
pub(super) struct TcpJson {
    pub dst: Option<String>,
    pub dst_domain: Option<String>,
    pub dport: u64,
}

#[derive(serde::Deserialize, Debug)]
pub(super) struct UdpJson {
    pub dst: Option<String>,
    pub dst_domain: Option<String>,
    pub dport: u64,
}

#[derive(/* serde::Deserialize, - custom */ Debug)]
pub(super) struct NetworkJson {
    pub domains: Option<Vec<DomainJson>>,
    pub http: Option<Vec<HttpJson>>,
    pub tcp: Option<Vec<TcpJson>>,
    pub udp: Option<Vec<UdpJson>>,
    pub hosts: Option<Vec<String>>,
}

#[derive(serde::Deserialize, Debug)]
pub(super) struct SummaryJson {
    pub mutexes: Option<Vec<String>>,
    pub files: Option<Vec<String>>,
    pub keys: Option<Vec<String>>,
}

#[derive(serde::Deserialize, Debug)]
pub(super) struct BehaviorJson {
    pub summary: SummaryJson,
}

#[derive(serde::Deserialize, Debug)]
pub(super) struct CuckooJson {
    pub network: NetworkJson,
    pub behavior: BehaviorJson,
}

impl<'de> Deserialize<'de> for NetworkJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MyVisitor;

        impl<'de> Visitor<'de> for MyVisitor {
            type Value = NetworkJson;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt.write_str("string or object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                // Must not parse `old_domains` before the whole map is
                // searched if there is a `domains` field, then the value for
                // the key `old_domains` should be ignored - specifically, it
                // is okay if the `old_domains` does not have the expected
                // structure if `domains` is present.
                let mut old_domains = None::<serde_json::Value>;
                let mut domains = None::<serde_json::Value>;

                let mut http = None::<Vec<HttpJson>>;
                let mut tcp = None::<Vec<TcpJson>>;
                let mut udp = None::<Vec<UdpJson>>;
                let mut hosts = None::<Vec<String>>;

                while let Some((key, val)) =
                    map.next_entry::<String, serde_json::Value>()?
                {
                    match key.as_str() {
                        "domains" => {
                            domains = Some(val);
                        }
                        "dns" => {
                            if domains.is_some() {
                                continue; // prefer "domains" over "dns"
                            }
                            old_domains = Some(val);
                        }
                        "http" => {
                            http = Some(
                                Deserialize::deserialize(val)
                                    .map_err(Error::custom)?,
                            );
                        }
                        "tcp" => {
                            tcp = Some(
                                Deserialize::deserialize(val)
                                    .map_err(Error::custom)?,
                            );
                        }
                        "udp" => {
                            udp = Some(
                                Deserialize::deserialize(val)
                                    .map_err(Error::custom)?,
                            );
                        }
                        "hosts" => {
                            hosts = Some(
                                Deserialize::deserialize(val)
                                    .map_err(Error::custom)?,
                            );
                        }
                        _ => {}
                    }
                }

                #[derive(serde::Deserialize, Debug)]
                struct OldDomainJson {
                    pub hostname: String,
                }

                let domains: Option<Vec<DomainJson>> =
                    match (domains, old_domains) {
                        (Some(domains), _) => {
                            Deserialize::deserialize(domains)
                                .map_err(Error::custom)?
                        }
                        (None, Some(old_domains)) => {
                            let old_domains: Vec<OldDomainJson> =
                                Deserialize::deserialize(old_domains)
                                    .map_err(Error::custom)?;

                            Some(
                                old_domains
                                    .into_iter()
                                    .map(|old| DomainJson {
                                        domain: old.hostname,
                                    })
                                    .collect(),
                            )
                        }
                        (None, None) => None, // domains field is optional
                    };

                Ok(NetworkJson { domains, http, tcp, udp, hosts })
            }
        }

        deserializer.deserialize_any(MyVisitor)
    }
}
