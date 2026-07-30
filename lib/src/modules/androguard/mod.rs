/*
Port of the Koodous `androguard` YARA module (Apache-2.0, The Koodous Authors)
to YARA-X.

Like the original C module — and like YARA-X's own `cuckoo` module — this does
NOT parse the scanned file. It consumes an external JSON report (the androguard
analysis of an APK) handed to the scanner as module metadata under the key
"androguard", and exposes functions to query it:

    androguard.certificate.issuer(/regex/)    androguard.certificate.issuer("string")
    androguard.certificate.subject(/regex/)   androguard.certificate.subject("string")
    androguard.certificate.sha1("hex")
    androguard.url(/regex/)                   androguard.url("string")
    androguard.app_name(/regex/)              androguard.app_name("string")
    androguard.permission(/regex/)            androguard.permission("string")
    androguard.activity(/regex/)              androguard.activity("string")
    androguard.main_activity(/regex/)         androguard.main_activity("string")
    androguard.service(/regex/)               androguard.service("string")
    androguard.receiver(/regex/)              androguard.receiver("string")
    androguard.package_name(/regex/)          androguard.package_name("string")
    androguard.min_sdk / max_sdk / target_sdk   // integers
    androguard.rootkit_behavior()      // 1 if hidden from the launcher AND
                                        // requesting a high-privilege/
                                        // persistence permission — see below.
*/

use crate::compiler::RegexId;
use crate::mods::prelude::*;
use crate::modules::protos::androguard::*;

mod schema;

use std::cell::RefCell;
use std::rc::Rc;

thread_local! {
    static LOCAL_DATA: RefCell<Option<Rc<schema::AndroguardJson>>> =
        const { RefCell::new(None) };
    /// Hash of the metadata bytes last parsed into LOCAL_DATA, so Phase 3's
    /// repeated rescans of the same androguard report against many buffers
    /// don't re-run serde_json::from_slice every scan() call.
    static LOCAL_DATA_HASH: RefCell<u64> = const { RefCell::new(0) };
}

fn get_local() -> Option<Rc<schema::AndroguardJson>> {
    LOCAL_DATA.with(|data| data.borrow().clone())
}

fn set_local(value: schema::AndroguardJson) {
    LOCAL_DATA.with(|data| {
        *data.borrow_mut() = Some(Rc::new(value));
    });
}

/// FNV-1a hash of the raw metadata bytes — cheap, no allocation.
fn meta_hash(meta: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in meta {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Build the protobuf output from an already-parsed report (cheap: a few
/// integer field copies), used both on a fresh parse and a cache hit.
fn build_output(report: &schema::AndroguardJson) -> Androguard {
    let mut out = Androguard::new();
    if let Some(v) = report.min_sdk_version {
        out.set_min_sdk(v);
    }
    if let Some(v) = report.max_sdk_version {
        out.set_max_sdk(v);
    }
    if let Some(v) = report.target_sdk_version {
        out.set_target_sdk(v);
    }
    out.set_permissions_number(
        report.permissions.as_ref().map(|p| p.len() as i64).unwrap_or(0),
    );
    out
}

fn main(
    ctx: &mut ModuleContext,
    _data: &[u8],
) -> Result<Androguard, ModuleError> {
    let meta = match ctx.get_module_metadata("androguard") {
        None | Some([]) => {
            set_local(schema::AndroguardJson::default());
            LOCAL_DATA_HASH.with(|h| *h.borrow_mut() = 0);
            return Ok(Androguard::new());
        }
        Some(meta) => meta,
    };

    // Skip re-parsing if this exact metadata was already parsed on this thread.
    let hash = meta_hash(meta);
    if LOCAL_DATA_HASH.with(|h| *h.borrow()) == hash {
        if let Some(cached) = get_local() {
            return Ok(build_output(&cached));
        }
    }

    let report = match serde_json::from_slice::<schema::AndroguardJson>(meta) {
        Ok(parsed) => parsed,
        Err(e) => {
            set_local(schema::AndroguardJson::default());
            LOCAL_DATA_HASH.with(|h| *h.borrow_mut() = 0);
            return Err(ModuleError::MetadataError { err: e.to_string() });
        }
    };

    let out = build_output(&report);
    LOCAL_DATA_HASH.with(|h| *h.borrow_mut() = hash);
    set_local(report);
    Ok(out)
}

// ── helpers ────────────────────────────────────────────────────────────────

/// 1 if any element of `list` matches the regex, else 0.
#[inline]
fn any_regex(ctx: &ScanContext, regexp_id: RegexId, list: Option<&Vec<String>>) -> i64 {
    match list {
        Some(items) => items
            .iter()
            .any(|s| ctx.regexp_matches(regexp_id, s.as_bytes())) as i64,
        None => 0,
    }
}

/// 1 if any element of `list` equals `needle` (case-insensitive, like the C
/// module's strcasecmp), else 0.
#[inline]
fn any_eqic(list: Option<&Vec<String>>, needle: &str) -> i64 {
    match list {
        Some(items) => items.iter().any(|s| s.eq_ignore_ascii_case(needle)) as i64,
        None => 0,
    }
}

#[inline]
fn one_regex(ctx: &ScanContext, regexp_id: RegexId, value: Option<&String>) -> i64 {
    matches!(value, Some(v) if ctx.regexp_matches(regexp_id, v.as_bytes())) as i64
}

#[inline]
fn one_eqic(value: Option<&String>, needle: &str) -> i64 {
    matches!(value, Some(v) if v.eq_ignore_ascii_case(needle)) as i64
}

// ── certificate.* ──────────────────────────────────────────────────────────

#[module_export(name = "certificate.issuer")]
fn certificate_issuer_r(ctx: &ScanContext, re: RegexId) -> i64 {
    one_regex(
        ctx,
        re,
        get_local()
            .and_then(|l| l.certificate.as_ref().and_then(|c| c.issuer_dn.clone()))
            .as_ref(),
    )
}

#[module_export(name = "certificate.issuer")]
fn certificate_issuer_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    one_eqic(
        get_local()
            .and_then(|l| l.certificate.as_ref().and_then(|c| c.issuer_dn.clone()))
            .as_ref(),
        needle,
    )
}

#[module_export(name = "certificate.subject")]
fn certificate_subject_r(ctx: &ScanContext, re: RegexId) -> i64 {
    one_regex(
        ctx,
        re,
        get_local()
            .and_then(|l| l.certificate.as_ref().and_then(|c| c.subject_dn.clone()))
            .as_ref(),
    )
}

#[module_export(name = "certificate.subject")]
fn certificate_subject_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    one_eqic(
        get_local()
            .and_then(|l| l.certificate.as_ref().and_then(|c| c.subject_dn.clone()))
            .as_ref(),
        needle,
    )
}

#[module_export(name = "certificate.sha1")]
fn certificate_sha1(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    one_eqic(
        get_local()
            .and_then(|l| l.certificate.as_ref().and_then(|c| c.sha1.clone()))
            .as_ref(),
        needle,
    )
}

// ── url ────────────────────────────────────────────────────────────────────

#[module_export(name = "url")]
fn url_r(ctx: &ScanContext, re: RegexId) -> i64 {
    any_regex(ctx, re, get_local().and_then(|l| l.urls.clone()).as_ref())
}

#[module_export(name = "url")]
fn url_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    any_eqic(get_local().and_then(|l| l.urls.clone()).as_ref(), needle)
}

// ── app_name ───────────────────────────────────────────────────────────────

#[module_export(name = "app_name")]
fn app_name_r(ctx: &ScanContext, re: RegexId) -> i64 {
    one_regex(ctx, re, get_local().and_then(|l| l.app_name.clone()).as_ref())
}

#[module_export(name = "app_name")]
fn app_name_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    one_eqic(get_local().and_then(|l| l.app_name.clone()).as_ref(), needle)
}

// ── permission (permissions + new_permissions) ─────────────────────────────

#[module_export(name = "permission")]
fn permission_r(ctx: &ScanContext, re: RegexId) -> i64 {
    let local = get_local();
    let a = any_regex(ctx, re, local.as_ref().and_then(|l| l.permissions.as_ref()));
    if a != 0 {
        return 1;
    }
    any_regex(ctx, re, local.as_ref().and_then(|l| l.new_permissions.as_ref()))
}

#[module_export(name = "permission")]
fn permission_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    let local = get_local();
    let a = any_eqic(local.as_ref().and_then(|l| l.permissions.as_ref()), needle);
    if a != 0 {
        return 1;
    }
    any_eqic(local.as_ref().and_then(|l| l.new_permissions.as_ref()), needle)
}

// ── activity / main_activity ───────────────────────────────────────────────

#[module_export(name = "activity")]
fn activity_r(ctx: &ScanContext, re: RegexId) -> i64 {
    any_regex(ctx, re, get_local().and_then(|l| l.activities.clone()).as_ref())
}

#[module_export(name = "activity")]
fn activity_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    any_eqic(get_local().and_then(|l| l.activities.clone()).as_ref(), needle)
}

// ── receiver (broadcast receivers) ─────────────────────────────────────────

#[module_export(name = "receiver")]
fn receiver_r(ctx: &ScanContext, re: RegexId) -> i64 {
    any_regex(ctx, re, get_local().and_then(|l| l.receivers.clone()).as_ref())
}

#[module_export(name = "receiver")]
fn receiver_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    any_eqic(get_local().and_then(|l| l.receivers.clone()).as_ref(), needle)
}

#[module_export(name = "main_activity")]
fn main_activity_r(ctx: &ScanContext, re: RegexId) -> i64 {
    one_regex(
        ctx,
        re,
        get_local().and_then(|l| l.main_activity.clone()).as_ref(),
    )
}

#[module_export(name = "main_activity")]
fn main_activity_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    one_eqic(get_local().and_then(|l| l.main_activity.clone()).as_ref(), needle)
}

// ── service ────────────────────────────────────────────────────────────────

#[module_export(name = "service")]
fn service_r(ctx: &ScanContext, re: RegexId) -> i64 {
    any_regex(ctx, re, get_local().and_then(|l| l.services.clone()).as_ref())
}

#[module_export(name = "service")]
fn service_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    any_eqic(get_local().and_then(|l| l.services.clone()).as_ref(), needle)
}

// ── package_name ───────────────────────────────────────────────────────────

#[module_export(name = "package_name")]
fn package_name_r(ctx: &ScanContext, re: RegexId) -> i64 {
    one_regex(
        ctx,
        re,
        get_local().and_then(|l| l.package_name.clone()).as_ref(),
    )
}

#[module_export(name = "package_name")]
fn package_name_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    one_eqic(get_local().and_then(|l| l.package_name.clone()).as_ref(), needle)
}

// ── rootkit_behavior ─────────────────────────────────────────────────────
//
// Stealth-rootkit pattern: no launchable (MAIN/LAUNCHER) activity declared —
// i.e. the app can't be opened from the home screen/app drawer at all — AND
// at least one high-privilege or persistence permission. Neither signal is
// proof on its own (some legitimate apps have no launcher activity, and
// device-admin/accessibility/overlay/boot-completed each have legitimate
// uses individually); together they're the classic "install silently, hide
// the icon, persist via one of these" combination.

/// Same high-privilege/persistence permission set the host app's own Java
/// heuristic uses (ScanEngine.ROOTKIT_SUSPICIOUS_PERMS) — device-admin and
/// accessibility grant near-total device control, SYSTEM_ALERT_WINDOW
/// enables overlay attacks, and boot-completed plus any of the others gives
/// silent persistence across reboots with no icon ever needed to relaunch.
const ROOTKIT_SUSPICIOUS_PERMS: &[&str] = &[
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.PACKAGE_USAGE_STATS",
];

#[module_export(name = "rootkit_behavior")]
fn rootkit_behavior(_ctx: &ScanContext) -> i64 {
    let local = get_local();
    let Some(local) = local.as_ref() else { return 0 };

    // "Hidden": the report has no main_activity at all, or an explicitly
    // empty one — both mean the host found no enabled MAIN/LAUNCHER
    // activity while parsing the manifest.
    let hidden = match &local.main_activity {
        None => true,
        Some(s) => s.is_empty(),
    };
    if !hidden {
        return 0;
    }

    let has_suspicious_perm = |perms: &Option<Vec<String>>| -> bool {
        perms
            .as_ref()
            .map(|list| {
                list.iter()
                    .any(|p| ROOTKIT_SUSPICIOUS_PERMS.iter().any(|s| p.eq_ignore_ascii_case(s)))
            })
            .unwrap_or(false)
    };
    i64::from(
        has_suspicious_perm(&local.permissions) || has_suspicious_perm(&local.new_permissions),
    )
}

// ── device_admin_permission ──────────────────────────────────────────────
//
// Standalone check for `android.permission.BIND_DEVICE_ADMIN` in the
// manifest's permission declarations. Unlike rootkit_behavior() which
// combines this with the hidden-launcher heuristic, this function returns
// 1 whenever the APK merely *declares* the device-admin permission,
// regardless of whether it also hides its icon.

#[module_export(name = "device_admin_permission")]
fn device_admin_permission(_ctx: &ScanContext) -> i64 {
    let local = get_local();
    let Some(local) = local.as_ref() else { return 0 };
    let has_it = |perms: &Option<Vec<String>>| -> bool {
        perms
            .as_ref()
            .map(|list| {
                list.iter()
                    .any(|p| p.eq_ignore_ascii_case("android.permission.BIND_DEVICE_ADMIN"))
            })
            .unwrap_or(false)
    };
    i64::from(has_it(&local.permissions) || has_it(&local.new_permissions))
}

// ── Manifest <meta-data> support ─────────────────────────────────────────────

#[module_export(name = "metadata")]
fn metadata_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    get_local()
        .as_ref()
        .and_then(|l| l.meta_data.as_ref())
        .map(|list| {
            list.iter()
                .any(|m| m.name.as_deref() == Some(needle)) as i64
        })
        .unwrap_or(0)
}

#[module_export(name = "metadata")]
fn metadata_r(ctx: &ScanContext, regex: RegexId) -> i64 {
    get_local()
        .as_ref()
        .and_then(|l| l.meta_data.as_ref())
        .map(|list| {
            list.iter()
                .any(|m| {
                    m.name.as_ref()
                        .map(|n| ctx.regexp_matches(regex, n.as_bytes()))
                        .unwrap_or(false)
                }) as i64
        })
        .unwrap_or(0)
}

register_module!("androguard", Androguard, main);
