use std::cell::RefCell;

#[cfg(feature = "logging")]
use log::error;
use serde_json::{Map, Value};

use crate::compiler::RegexpId;
use crate::modules::prelude::*;
use crate::modules::protos::cuckoo::*;

#[cfg(test)]
mod tests;

thread_local! {
    static CUCKOO_REPORT: RefCell<Option<Map<String, Value>>> = const { RefCell::new(None) };
}

#[module_main]
fn main(_data: &[u8], meta: Option<&[u8]>) -> Cuckoo {
    if let Some(meta) = meta {
        match serde_json::from_slice::<Value>(meta) {
            Ok(Value::Object(json)) => CUCKOO_REPORT.set(Some(json)),
            Ok(_) => {
                #[cfg(feature = "logging")]
                error!("cuckoo report is not a valid JSON")
            }
            #[cfg(feature = "logging")]
            Err(err) => error!("can't parse cuckoo report: {}", err),
            #[cfg(not(feature = "logging"))]
            Err(_) => {}
        }
    }
    Cuckoo::new()
}

#[module_export(name = "network.dns_lookup")]
fn network_dns_lookup(ctx: &ScanContext, regexp_id: RegexpId) -> bool {
    CUCKOO_REPORT.with_borrow(|report| {
        let find_match = |objects: &Vec<Value>, field_name: &str| {
            objects.iter().any(|object| {
                object
                    .get(field_name)
                    .and_then(|val| val.as_str())
                    .map(|val| ctx.regexp_matches(regexp_id, val.as_bytes()))
                    .unwrap_or(false)
            })
        };

        // The top-level object contains a "network" key that contains
        // network-related information.
        let network = report.as_ref().and_then(|report| report.get("network"));

        // Recent versions of Cuckoo generate domain resolution information with
        // this format:
        //
        //       "domains": [
        //           {
        //               "ip": "192.168.0.1",
        //               "domain": "foo.bar.com"
        //           }
        //        ]
        //
        // But older versions with this other format:
        //
        //       "dns": [
        //           {
        //               "ip": "192.168.0.1",
        //               "hostname": "foo.bar.com"
        //           }
        //        ]
        //
        // Additionally, the newer versions also have a "dns" field. So, let's try
        // to locate the "domains" field first, if not found fall back to the older
        // format.
        if network
            .and_then(|report| report.get("domains"))
            .and_then(|domains| domains.as_array())
            .map(|domains| find_match(domains, "domain"))
            .unwrap_or(false)
        {
            return true;
        }

        if network
            .and_then(|report| report.get("dns"))
            .and_then(|dns| dns.as_array())
            .map(|dns| find_match(dns, "hostname"))
            .unwrap_or(false)
        {
            return true;
        }

        false
    })
}

enum RequestType {
    Get,
    Post,
    Both,
}

fn http_request(
    ctx: &ScanContext,
    regexp_id: RegexpId,
    request_type: RequestType,
) -> bool {
    CUCKOO_REPORT.with_borrow(|report| {
        report
            .as_ref()
            .and_then(|report| report.get("network"))
            .and_then(|network| network.get("http"))
            .and_then(|http| http.as_array())
            .map(|http| {
                http.iter().any(|request| {
                    let req_method = match request
                        .get("method")
                        .and_then(|req_method| req_method.as_str())
                    {
                        Some(req_method) => req_method,
                        None => return false,
                    };

                    let req_uri = match request
                        .get("uri")
                        .and_then(|req_uri| req_uri.as_str())
                    {
                        Some(req_uri) => req_uri,
                        None => return false,
                    };

                    match request_type {
                        RequestType::Get => {
                            if !req_method.eq_ignore_ascii_case("get") {
                                return false;
                            }
                        }
                        RequestType::Post => {
                            if !req_method.eq_ignore_ascii_case("post") {
                                return false;
                            }
                        }
                        RequestType::Both => {
                            if !req_method.eq_ignore_ascii_case("get")
                                && !req_method.eq_ignore_ascii_case("post")
                            {
                                return false;
                            }
                        }
                    }

                    return ctx.regexp_matches(regexp_id, req_uri.as_bytes());
                })
            })
            .unwrap_or(false)
    })
}

#[module_export(name = "network.http_request")]
fn network_http_request(ctx: &ScanContext, regexp_id: RegexpId) -> bool {
    http_request(ctx, regexp_id, RequestType::Both)
}

#[module_export(name = "network.http_get")]
fn network_http_get(ctx: &ScanContext, regexp_id: RegexpId) -> bool {
    http_request(ctx, regexp_id, RequestType::Get)
}

#[module_export(name = "network.http_post")]
fn network_http_post(ctx: &ScanContext, regexp_id: RegexpId) -> bool {
    http_request(ctx, regexp_id, RequestType::Post)
}

#[module_export(name = "network.http_user_agent")]
fn network_http_user_agent(ctx: &ScanContext, regexp_id: RegexpId) -> bool {
    CUCKOO_REPORT.with_borrow(|report| {
        report
            .as_ref()
            .and_then(|report| report.get("network"))
            .and_then(|network| network.get("http"))
            .and_then(|http| http.as_array())
            .map(|http| {
                http.iter()
                    .filter_map(|request| request.get("user-agent"))
                    .filter_map(|ua| ua.as_str())
                    .any(|ua| ctx.regexp_matches(regexp_id, ua.as_bytes()))
            })
            .unwrap_or(false)
    })
}

fn network_conn(
    ctx: &ScanContext,
    regexp_id: RegexpId,
    conn: &str,
    port: i64,
) -> bool {
    CUCKOO_REPORT.with_borrow(|report| {
        report
            .as_ref()
            .and_then(|report| report.get("network"))
            .and_then(|network| network.get(conn))
            .and_then(|connections| connections.as_array())
            .map(|connections| {
                connections.iter().any(|conn| {
                    let dst_port = match conn
                        .get("dport")
                        .and_then(|dst_port| dst_port.as_i64())
                    {
                        Some(dst_port) => dst_port,
                        None => return false,
                    };

                    let dst_addr = match conn
                        .get("dst")
                        .and_then(|dst_addr| dst_addr.as_str())
                    {
                        Some(dst_addr) => dst_addr,
                        None => return false,
                    };

                    dst_port == port
                        && ctx.regexp_matches(regexp_id, dst_addr.as_bytes())
                })
            })
            .unwrap_or(false)
    })
}

#[module_export(name = "network.tcp")]
fn network_tcp(ctx: &ScanContext, regexp_id: RegexpId, port: i64) -> bool {
    network_conn(ctx, regexp_id, "tcp", port)
}

#[module_export(name = "network.udp")]
fn network_udp(ctx: &ScanContext, regexp_id: RegexpId, port: i64) -> bool {
    network_conn(ctx, regexp_id, "udp", port)
}

#[module_export(name = "network.host")]
fn network_host(ctx: &ScanContext, regexp_id: RegexpId) -> bool {
    CUCKOO_REPORT.with_borrow(|report| {
        report
            .as_ref()
            .and_then(|report| report.get("network"))
            .and_then(|network| network.get("hosts"))
            .and_then(|hosts| hosts.as_array())
            .map(|hosts| {
                hosts
                    .iter()
                    .filter_map(|host| host.as_str())
                    .any(|host| ctx.regexp_matches(regexp_id, host.as_bytes()))
            })
            .unwrap_or(false)
    })
}

#[module_export(name = "sync.mutex")]
fn sync_mutex(ctx: &ScanContext, regexp_id: RegexpId) -> bool {
    CUCKOO_REPORT.with_borrow(|report| {
        report
            .as_ref()
            .and_then(|report| report.get("behavior"))
            .and_then(|behaviour| behaviour.get("summary"))
            .and_then(|summary| summary.get("mutexes"))
            .and_then(|mutexes| mutexes.as_array())
            .map(|mutexes| {
                mutexes
                    .iter()
                    .filter_map(|m| m.as_str())
                    .any(|m| ctx.regexp_matches(regexp_id, m.as_bytes()))
            })
            .unwrap_or(false)
    })
}

#[module_export(name = "filesystem.file_access")]
fn filesystem_file_access(ctx: &ScanContext, regexp_id: RegexpId) -> bool {
    CUCKOO_REPORT.with_borrow(|report| {
        report
            .as_ref()
            .and_then(|report| report.get("behavior"))
            .and_then(|behaviour| behaviour.get("summary"))
            .and_then(|summary| summary.get("files"))
            .and_then(|files| files.as_array())
            .map(|files| {
                files
                    .iter()
                    .filter_map(|file| file.as_str())
                    .any(|file| ctx.regexp_matches(regexp_id, file.as_bytes()))
            })
            .unwrap_or(false)
    })
}

#[module_export(name = "registry.key_access")]
fn registry_key_access(ctx: &ScanContext, regexp_id: RegexpId) -> bool {
    CUCKOO_REPORT.with_borrow(|report| {
        report
            .as_ref()
            .and_then(|report| report.get("behavior"))
            .and_then(|behaviour| behaviour.get("summary"))
            .and_then(|summary| summary.get("keys"))
            .and_then(|keys| keys.as_array())
            .map(|keys| {
                keys.iter()
                    .filter_map(|key| key.as_str())
                    .any(|key| ctx.regexp_matches(regexp_id, key.as_bytes()))
            })
            .unwrap_or(false)
    })
}
