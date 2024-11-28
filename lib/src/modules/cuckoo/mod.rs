#[cfg(feature = "logging")]
use log::error;

use crate::compiler::RegexpId;
use crate::modules::prelude::*;
use crate::modules::protos::cuckoo::*;

mod schema;
#[cfg(test)]
mod tests;

use std::cell::RefCell;
use std::rc::Rc;
thread_local! {
    static LOCAL_DATA: RefCell<Option<Rc<schema::CuckooJson>>> = const { RefCell::new(None) };
}

fn get_local() -> Option<Rc<schema::CuckooJson>> {
    LOCAL_DATA.with(|data| data.borrow().clone())
}

fn set_local(value: schema::CuckooJson) {
    LOCAL_DATA.with(|data| {
        *data.borrow_mut() = Some(Rc::new(value));
    });
}

#[module_main]
fn main(_data: &[u8], meta: Option<&[u8]>) -> Cuckoo {
    let parsed =
        serde_json::from_slice::<schema::CuckooJson>(meta.unwrap_or_default());

    match parsed {
        Ok(parsed) => {
            set_local(parsed);
        }
        #[cfg(feature = "logging")]
        Err(e) => {
            error!("can't parse cuckoo report: {}", e);
        }
        #[cfg(not(feature = "logging"))]
        Err(_) => {}
    };

    Cuckoo::new()
}

#[module_export(name = "network.dns_lookup")]
fn network_dns_lookup_r(
    ctx: &ScanContext,
    regexp_id: RegexpId,
) -> Option<i64> {
    Some(
        get_local()?
            .network
            .domains
            .iter()
            .flatten()
            .filter(|domain| {
                ctx.regexp_matches(regexp_id, domain.domain.as_bytes())
            })
            .count() as _,
    )
}

#[module_export(name = "network.http_request")]
fn network_http_request_r(
    ctx: &ScanContext,
    regexp_id: RegexpId,
) -> Option<i64> {
    Some(
        get_local()?
            .network
            .http
            .iter()
            .flatten()
            .filter(|http| {
                http.method.is_some() // ~> is request (is not response)
                    && ctx.regexp_matches(regexp_id, http.uri.as_bytes())
            })
            .count() as _,
    )
}

#[module_export(name = "network.http_get")]
fn network_http_get_r(ctx: &ScanContext, regexp_id: RegexpId) -> Option<i64> {
    Some(
        get_local()?
            .network
            .http
            .iter()
            .flatten()
            .filter(|http| {
                http.method
                    .as_ref()
                    .map(|method| method.eq_ignore_ascii_case("get"))
                    .unwrap_or(false)
                    && ctx.regexp_matches(regexp_id, http.uri.as_bytes())
            })
            .count() as _,
    )
}

#[module_export(name = "network.http_post")]
fn network_http_post_r(ctx: &ScanContext, regexp_id: RegexpId) -> Option<i64> {
    Some(
        get_local()?
            .network
            .http
            .iter()
            .flatten()
            .filter(|http| {
                http.method
                    .as_ref()
                    .map(|method| method.eq_ignore_ascii_case("post"))
                    .unwrap_or(false)
                    && ctx.regexp_matches(regexp_id, http.uri.as_bytes())
            })
            .count() as _,
    )
}

#[module_export(name = "network.http_user_agent")]
fn network_http_user_agent_r(
    ctx: &ScanContext,
    regexp_id: RegexpId,
) -> Option<i64> {
    Some(
        get_local()?
            .network
            .http
            .iter()
            .flatten()
            .flat_map(|http| http.user_agent.iter())
            .filter(|user_agent| {
                ctx.regexp_matches(regexp_id, user_agent.as_bytes())
            })
            .count() as _,
    )
}

#[module_export(name = "network.tcp")]
fn network_tcp_ri(
    ctx: &ScanContext,
    dst_re: RegexpId,
    port: i64,
) -> Option<i64> {
    Some(
        get_local()?
            .network
            .tcp
            .iter()
            .flatten()
            .filter(|tcp| {
                tcp.dport == port as u64
                    && tcp
                        .dst
                        .iter()
                        .chain(tcp.dst_domain.iter())
                        .any(|dst| ctx.regexp_matches(dst_re, dst.as_bytes()))
            })
            .count() as _,
    )
}

#[module_export(name = "network.udp")]
fn network_udp_ri(
    ctx: &ScanContext,
    dst_re: RegexpId,
    port: i64,
) -> Option<i64> {
    Some(
        get_local()?
            .network
            .udp
            .iter()
            .flatten()
            .filter(|udp| {
                udp.dport == port as u64
                    && udp
                        .dst
                        .iter()
                        .chain(udp.dst_domain.iter())
                        .any(|dst| ctx.regexp_matches(dst_re, dst.as_bytes()))
            })
            .count() as _,
    )
}

#[module_export(name = "network.host")]
fn network_host_r(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    Some(
        get_local()?
            .network
            .hosts
            .iter()
            .flatten()
            .filter(|host| ctx.regexp_matches(re, host.as_bytes()))
            .count() as _,
    )
}

#[module_export(name = "sync.mutex")]
fn sync_mutex_r(ctx: &ScanContext, mutex_re: RegexpId) -> Option<i64> {
    Some(
        get_local()?
            .behavior
            .summary
            .mutexes
            .iter()
            .flatten()
            .filter(|mutex| ctx.regexp_matches(mutex_re, mutex.as_bytes()))
            .count() as _,
    )
}

#[module_export(name = "filesystem.file_access")]
fn filesystem_file_access_r(
    ctx: &ScanContext,
    regexp_id: RegexpId,
) -> Option<i64> {
    Some(
        get_local()?
            .behavior
            .summary
            .files
            .iter()
            .flatten()
            .filter(|file| ctx.regexp_matches(regexp_id, file.as_bytes()))
            .count() as _,
    )
}

#[module_export(name = "registry.key_access")]
fn registry_key_access_r(
    ctx: &ScanContext,
    regexp_id: RegexpId,
) -> Option<i64> {
    Some(
        get_local()?
            .behavior
            .summary
            .keys
            .iter()
            .flatten()
            .filter(|key| ctx.regexp_matches(regexp_id, key.as_bytes()))
            .count() as _,
    )
}
