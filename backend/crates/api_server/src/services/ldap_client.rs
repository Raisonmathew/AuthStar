//! LDAP client — real bind, rootDSE probe, user/group search, and password writeback.
//!
//! Wraps the `ldap3` crate to provide a clean async interface for:
//!
//! - `test_bind` — verify connectivity + credentials by performing a simple
//!   bind and probing the rootDSE (returns server vendor/version info).
//! - `search_users` — search returning raw LDAP entries so the caller can
//!   apply its own attribute-mapper logic.
//! - `search_groups` — search a groups base DN and resolve membership.
//! - `verify_user_password` — re-bind as an LDAP user entry (used by the
//!   login-flow integration for federated authentication).
//! - `write_user_password` — LDAP modify to update `userPassword` (WRITABLE mode).
//!
//! ## Transport
//!
//! | `use_ssl` | `start_tls` | behaviour                        |
//! |-----------|-------------|----------------------------------|
//! | `false`   | `false`     | plain `ldap://`                  |
//! | `false`   | `true`      | `ldap://` + STARTTLS upgrade     |
//! | `true`    | *any*       | `ldaps://` (TLS from the start)  |
//!
//! All TLS connections use rustls (no OpenSSL dependency).
//!
//! ## SSRF / referral safety
//!
//! `ldap3` 0.11.x does **not** auto-follow referrals — they are surfaced as
//! `SearchItem::Referral` values in the result set but the library never opens
//! a second outbound connection to the referral URL.  This means there is no
//! SSRF risk from attacker-controlled referral targets in directory entries.
//! Our use of `.success()` on search results accepts LDAP result code 10
//! (referral) as non-error, so partial results with referrals don't abort a sync.

use ldap3::{LdapConnAsync, LdapConnSettings, Mod, Scope, SearchEntry};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tracing::{info, warn};

// ── Scope helper ──────────────────────────────────────────────────────────────

/// Parse a string search scope name (from DB config) into a `ldap3::Scope`.
/// Unknown values default to `Subtree`.
pub fn parse_scope(s: &str) -> Scope {
    match s {
        "onelevel" | "one" => Scope::OneLevel,
        "base" => Scope::Base,
        _ => Scope::Subtree,
    }
}

pub use ldap3::Ldap as LdapHandle;

// ── Public Types ──────────────────────────────────────────────────────────────

/// A single LDAP entry returned by a search.
#[derive(Debug, Clone)]
pub struct LdapEntry {
    pub dn: String,
    pub attrs: HashMap<String, Vec<String>>,
}

#[derive(Debug)]
pub struct BindTestResult {
    pub success: bool,
    pub message: String,
    pub ldap_versions: Vec<String>,
    pub naming_contexts: Vec<String>,
}

#[derive(Debug)]
pub struct SearchResult {
    pub entries: Vec<LdapEntry>,
    pub pages: u32,
}

/// A synced LDAP group with resolved member DNs or UIDs.
#[derive(Debug, Clone)]
pub struct LdapGroup {
    pub dn: String,
    pub uuid: Option<String>,
    pub name: String,
    /// Member identifiers — either DNs or UIDs, depending on `group_membership_type`.
    pub members: HashSet<String>,
}

// ── Connection helper ─────────────────────────────────────────────────────────

/// Open an LDAP connection, trying the primary `host` first, then each entry
/// in `fallback_hosts` (comma-separated values from config, already split).
/// Returns the first successfully connected handle; returns an error only when
/// every candidate host has been exhausted.
async fn open_connection(
    host: &str,
    port: i32,
    use_ssl: bool,
    start_tls: bool,
    skip_tls_verify: bool,
    conn_timeout_secs: u64,
    read_timeout_secs: u64,
    fallback_hosts: &[&str],
) -> Result<ldap3::Ldap, String> {
    // Build ordered candidate list: primary first, then fallbacks.
    let all_hosts: Vec<&str> = std::iter::once(host)
        .chain(fallback_hosts.iter().copied())
        .collect();

    let mut last_err = String::new();

    for (idx, &h) in all_hosts.iter().enumerate() {
        let url = if use_ssl {
            format!("ldaps://{}:{}", h, port)
        } else {
            format!("ldap://{}:{}", h, port)
        };

        let settings = LdapConnSettings::new()
            .set_conn_timeout(Duration::from_secs(conn_timeout_secs.max(3)))
            .set_starttls(start_tls && !use_ssl)
            .set_no_tls_verify(skip_tls_verify && (use_ssl || (start_tls && !use_ssl)));

        let (conn, mut ldap) = match LdapConnAsync::with_settings(settings, &url).await {
            Ok(pair) => pair,
            Err(e) => {
                last_err = format!("Failed to connect to {url}: {e}");
                if idx == 0 && all_hosts.len() > 1 {
                    warn!(
                        host = h,
                        port,
                        fallbacks = all_hosts.len() - 1,
                        "Primary LDAP host unreachable, trying fallback(s)"
                    );
                }
                continue;
            }
        };

        // drive! spawns the connection driver task.
        ldap3::drive!(conn);

        // Set per-operation read timeout.
        ldap.with_timeout(Duration::from_secs(read_timeout_secs.max(5)));

        // STARTTLS upgrade (belt-and-suspenders; settings already requested it).
        if start_tls && !use_ssl {
            if let Err(e) = ldap.extended(ldap3::exop::WhoAmI).await {
                last_err = format!("STARTTLS negotiation failed on {h}: {e}");
                continue;
            }
        }

        if idx > 0 {
            info!(
                host = h,
                port, "LDAP connection established via fallback host"
            );
        }

        return Ok(ldap);
    }

    Err(if last_err.is_empty() {
        "No LDAP hosts configured".to_string()
    } else {
        last_err
    })
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Test bind + rootDSE probe.
pub async fn test_bind(
    host: &str,
    port: i32,
    use_ssl: bool,
    start_tls: bool,
    skip_tls_verify: bool,
    bind_dn: &str,
    bind_password: &str,
    conn_timeout_secs: u64,
    read_timeout_secs: u64,
    fallback_hosts: &[&str],
) -> BindTestResult {
    let mut ldap = match open_connection(
        host,
        port,
        use_ssl,
        start_tls,
        skip_tls_verify,
        conn_timeout_secs,
        read_timeout_secs,
        fallback_hosts,
    )
    .await
    {
        Ok(l) => l,
        Err(e) => {
            return BindTestResult {
                success: false,
                message: e,
                ldap_versions: vec![],
                naming_contexts: vec![],
            }
        }
    };

    let bind_res = if bind_dn.is_empty() {
        ldap.simple_bind("", "").await
    } else {
        ldap.simple_bind(bind_dn, bind_password).await
    };

    let bind_res = match bind_res {
        Ok(r) => r,
        Err(e) => {
            let _ = ldap.unbind().await;
            return BindTestResult {
                success: false,
                message: format!("Bind request failed: {e}"),
                ldap_versions: vec![],
                naming_contexts: vec![],
            };
        }
    };

    if let Err(e) = bind_res.success() {
        let _ = ldap.unbind().await;
        return BindTestResult {
            success: false,
            message: format!("Bind rejected by server: {e}"),
            ldap_versions: vec![],
            naming_contexts: vec![],
        };
    }

    info!(host, port, bind_dn, "LDAP bind succeeded");

    // rootDSE probe (non-fatal on failure)
    let rootdse_attrs = &["namingContexts", "supportedLDAPVersion", "vendorName"];
    let (ldap_versions, naming_contexts) = match ldap
        .search("", Scope::Base, "(objectClass=*)", rootdse_attrs)
        .await
    {
        Ok(res) => match res.success() {
            Ok((entries, _)) => {
                let first = entries.into_iter().next().map(SearchEntry::construct);
                let versions = first
                    .as_ref()
                    .and_then(|e| e.attrs.get("supportedLDAPVersion").cloned())
                    .unwrap_or_default();
                let contexts = first
                    .as_ref()
                    .and_then(|e| e.attrs.get("namingContexts").cloned())
                    .unwrap_or_default();
                (versions, contexts)
            }
            Err(e) => {
                warn!(host, port, error = %e, "rootDSE search error (non-fatal)");
                (vec![], vec![])
            }
        },
        Err(e) => {
            warn!(host, port, error = %e, "rootDSE probe failed (non-fatal)");
            (vec![], vec![])
        }
    };

    let _ = ldap.unbind().await;

    BindTestResult {
        success: true,
        message: format!(
            "Bind succeeded against {}:{}{}",
            host,
            port,
            if naming_contexts.is_empty() {
                String::new()
            } else {
                format!("; namingContexts: {}", naming_contexts.join(", "))
            }
        ),
        ldap_versions,
        naming_contexts,
    }
}

/// Search `base_dn` for entries matching `filter`.
/// Performs a single-page search (suitable for ≤10K entries).
pub async fn search_users(
    host: &str,
    port: i32,
    use_ssl: bool,
    start_tls: bool,
    skip_tls_verify: bool,
    bind_dn: &str,
    bind_password: &str,
    base_dn: &str,
    filter: &str,
    attrs: &[&str],
    _page_size: i32,
    conn_timeout_secs: u64,
    read_timeout_secs: u64,
    fallback_hosts: &[&str],
    scope: Scope,
) -> Result<SearchResult, String> {
    let mut ldap = open_connection(
        host,
        port,
        use_ssl,
        start_tls,
        skip_tls_verify,
        conn_timeout_secs,
        read_timeout_secs,
        fallback_hosts,
    )
    .await?;

    let bind_res = if bind_dn.is_empty() {
        ldap.simple_bind("", "").await
    } else {
        ldap.simple_bind(bind_dn, bind_password).await
    };

    bind_res
        .map_err(|e| format!("Bind failed during sync: {e}"))?
        .success()
        .map_err(|e| format!("Bind rejected during sync: {e}"))?;

    let (rs, _res) = ldap
        .search(base_dn, scope, filter, attrs)
        .await
        .map_err(|e| format!("LDAP search failed: {e}"))?
        .success()
        .map_err(|e| format!("LDAP search error: {e}"))?;

    let entries: Vec<LdapEntry> = rs
        .into_iter()
        .map(SearchEntry::construct)
        .map(|se| LdapEntry {
            dn: se.dn,
            attrs: se.attrs,
        })
        .collect();

    let count = entries.len();
    let _ = ldap.unbind().await;

    info!(
        host,
        port,
        base_dn,
        filter,
        entries = count,
        "LDAP search completed"
    );

    Ok(SearchResult { entries, pages: 1 })
}

/// Re-bind as the given user DN with the provided password.
/// Returns `Ok(true)` if accepted, `Ok(false)` if rejected.
pub async fn verify_user_password(
    host: &str,
    port: i32,
    use_ssl: bool,
    start_tls: bool,
    skip_tls_verify: bool,
    user_dn: &str,
    password: &str,
    conn_timeout_secs: u64,
    read_timeout_secs: u64,
    fallback_hosts: &[&str],
) -> Result<bool, String> {
    let mut ldap = open_connection(
        host,
        port,
        use_ssl,
        start_tls,
        skip_tls_verify,
        conn_timeout_secs,
        read_timeout_secs,
        fallback_hosts,
    )
    .await?;
    let result = ldap
        .simple_bind(user_dn, password)
        .await
        .map_err(|e| format!("Bind request error: {e}"))?;
    let ok = result.success().is_ok();
    let _ = ldap.unbind().await;
    Ok(ok)
}

/// Search `groups_dn` for groups matching `(objectClass=<group_object_class>)`.
/// Returns a list of groups with their resolved member identifiers.
pub async fn search_groups(
    host: &str,
    port: i32,
    use_ssl: bool,
    start_tls: bool,
    skip_tls_verify: bool,
    bind_dn: &str,
    bind_password: &str,
    groups_dn: &str,
    group_object_class: &str,
    group_name_attr: &str,
    group_membership_attr: &str,
    uuid_attr: &str,
    conn_timeout_secs: u64,
    read_timeout_secs: u64,
    fallback_hosts: &[&str],
    scope: Scope,
) -> Result<Vec<LdapGroup>, String> {
    let mut ldap = open_connection(
        host,
        port,
        use_ssl,
        start_tls,
        skip_tls_verify,
        conn_timeout_secs,
        read_timeout_secs,
        fallback_hosts,
    )
    .await?;

    let bind_res = if bind_dn.is_empty() {
        ldap.simple_bind("", "").await
    } else {
        ldap.simple_bind(bind_dn, bind_password).await
    };
    bind_res
        .map_err(|e| format!("Bind failed during group search: {e}"))?
        .success()
        .map_err(|e| format!("Bind rejected during group search: {e}"))?;

    let filter = format!("(objectClass={group_object_class})");
    let attrs = vec![
        group_name_attr,
        group_membership_attr,
        uuid_attr,
        "objectGUID",
        "entryUUID",
    ];

    let (rs, _res) = ldap
        .search(groups_dn, scope, &filter, &attrs)
        .await
        .map_err(|e| format!("LDAP group search failed: {e}"))?
        .success()
        .map_err(|e| format!("LDAP group search error: {e}"))?;

    let groups: Vec<LdapGroup> = rs
        .into_iter()
        .map(SearchEntry::construct)
        .filter_map(|se| {
            let name = se
                .attrs
                .get(group_name_attr)
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_else(|| se.dn.clone());

            let uuid = se
                .attrs
                .get(uuid_attr)
                .or_else(|| se.attrs.get("entryUUID"))
                .or_else(|| se.attrs.get("objectGUID"))
                .and_then(|v| v.first())
                .cloned();

            let members: HashSet<String> = se
                .attrs
                .get(group_membership_attr)
                .map(|v| v.iter().cloned().collect())
                .unwrap_or_default();

            Some(LdapGroup {
                dn: se.dn,
                uuid,
                name,
                members,
            })
        })
        .collect();

    let _ = ldap.unbind().await;
    Ok(groups)
}

/// Perform an LDAP modify to update the `userPassword` attribute.
/// Only valid when the LDAP connection's `edit_mode` is `WRITABLE`.
pub async fn write_user_password(
    host: &str,
    port: i32,
    use_ssl: bool,
    start_tls: bool,
    skip_tls_verify: bool,
    bind_dn: &str,
    bind_password: &str,
    user_dn: &str,
    new_password: &str,
    conn_timeout_secs: u64,
    read_timeout_secs: u64,
    fallback_hosts: &[&str],
) -> Result<(), String> {
    let mut ldap = open_connection(
        host,
        port,
        use_ssl,
        start_tls,
        skip_tls_verify,
        conn_timeout_secs,
        read_timeout_secs,
        fallback_hosts,
    )
    .await?;

    ldap.simple_bind(bind_dn, bind_password)
        .await
        .map_err(|e| format!("Bind failed for password writeback: {e}"))?
        .success()
        .map_err(|e| format!("Bind rejected for password writeback: {e}"))?;

    let mods = vec![Mod::Replace("userPassword", HashSet::from([new_password]))];

    ldap.modify(user_dn, mods)
        .await
        .map_err(|e| format!("LDAP modify failed: {e}"))?
        .success()
        .map_err(|e| format!("LDAP modify error: {e}"))?;

    let _ = ldap.unbind().await;
    Ok(())
}

// ── Connection-pooling helpers (for sync tasks) ───────────────────────────────

/// Open and bind a service-account connection for reuse across multiple operations.
/// Call `ldap.unbind().await` when done.
pub async fn bind_service_account(
    host: &str,
    port: i32,
    use_ssl: bool,
    start_tls: bool,
    skip_tls_verify: bool,
    bind_dn: &str,
    bind_password: &str,
    conn_timeout_secs: u64,
    read_timeout_secs: u64,
    fallback_hosts: &[&str],
) -> Result<LdapHandle, String> {
    let mut ldap = open_connection(
        host,
        port,
        use_ssl,
        start_tls,
        skip_tls_verify,
        conn_timeout_secs,
        read_timeout_secs,
        fallback_hosts,
    )
    .await?;

    let bind_res = if bind_dn.is_empty() {
        ldap.simple_bind("", "").await
    } else {
        ldap.simple_bind(bind_dn, bind_password).await
    };

    bind_res
        .map_err(|e| format!("Service-account bind failed: {e}"))?
        .success()
        .map_err(|e| format!("Service-account bind rejected: {e}"))?;

    info!(host, port, bind_dn, "Service-account LDAP bind established");
    Ok(ldap)
}

/// Search users on an already-bound LDAP handle (no re-bind).
pub async fn search_users_on_ldap(
    ldap: &mut LdapHandle,
    base_dn: &str,
    filter: &str,
    attrs: &[&str],
    scope: Scope,
) -> Result<SearchResult, String> {
    let (rs, _res) = ldap
        .search(base_dn, scope, filter, attrs)
        .await
        .map_err(|e| format!("LDAP search failed: {e}"))?
        .success()
        .map_err(|e| format!("LDAP search error: {e}"))?;

    let entries: Vec<LdapEntry> = rs
        .into_iter()
        .map(SearchEntry::construct)
        .map(|se| LdapEntry {
            dn: se.dn,
            attrs: se.attrs,
        })
        .collect();

    let count = entries.len();
    info!(
        base_dn,
        filter,
        entries = count,
        "LDAP search completed (pooled)"
    );
    Ok(SearchResult { entries, pages: 1 })
}

/// Search groups on an already-bound LDAP handle (no re-bind).
pub async fn search_groups_on_ldap(
    ldap: &mut LdapHandle,
    groups_dn: &str,
    group_object_class: &str,
    group_name_attr: &str,
    group_membership_attr: &str,
    uuid_attr: &str,
    scope: Scope,
) -> Result<Vec<LdapGroup>, String> {
    let filter = format!("(objectClass={group_object_class})");
    let attrs = vec![
        group_name_attr,
        group_membership_attr,
        uuid_attr,
        "objectGUID",
        "entryUUID",
    ];

    let (rs, _res) = ldap
        .search(groups_dn, scope, &filter, &attrs)
        .await
        .map_err(|e| format!("LDAP group search failed: {e}"))?
        .success()
        .map_err(|e| format!("LDAP group search error: {e}"))?;

    let groups: Vec<LdapGroup> = rs
        .into_iter()
        .map(SearchEntry::construct)
        .filter_map(|se| {
            let name = se
                .attrs
                .get(group_name_attr)
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_else(|| se.dn.clone());

            let uuid = se
                .attrs
                .get(uuid_attr)
                .or_else(|| se.attrs.get("entryUUID"))
                .or_else(|| se.attrs.get("objectGUID"))
                .and_then(|v| v.first())
                .cloned();

            let members: HashSet<String> = se
                .attrs
                .get(group_membership_attr)
                .map(|v| v.iter().cloned().collect())
                .unwrap_or_default();

            Some(LdapGroup {
                dn: se.dn,
                uuid,
                name,
                members,
            })
        })
        .collect();

    Ok(groups)
}

/// Create a new LDAP user entry (for WRITABLE sync registrations).
/// Builds an `inetOrgPerson` / AD `user` entry and performs an LDAP ADD.
pub async fn write_user_to_ldap(
    host: &str,
    port: i32,
    use_ssl: bool,
    start_tls: bool,
    skip_tls_verify: bool,
    bind_dn: &str,
    bind_password: &str,
    user_dn: &str,
    username: &str,
    first_name: &str,
    last_name: &str,
    email: &str,
    conn_timeout_secs: u64,
    read_timeout_secs: u64,
    fallback_hosts: &[&str],
) -> Result<(), String> {
    let mut ldap = open_connection(
        host,
        port,
        use_ssl,
        start_tls,
        skip_tls_verify,
        conn_timeout_secs,
        read_timeout_secs,
        fallback_hosts,
    )
    .await?;

    ldap.simple_bind(bind_dn, bind_password)
        .await
        .map_err(|e| format!("Bind failed for user creation: {e}"))?
        .success()
        .map_err(|e| format!("Bind rejected for user creation: {e}"))?;

    let cn = if first_name.is_empty() && last_name.is_empty() {
        username.to_string()
    } else if last_name.is_empty() {
        first_name.to_string()
    } else {
        format!("{first_name} {last_name}")
    };

    let sn = if last_name.is_empty() {
        username
    } else {
        last_name
    };

    let attrs: Vec<(&str, HashSet<&str>)> = vec![
        (
            "objectClass",
            HashSet::from(["inetOrgPerson", "organizationalPerson", "person", "top"]),
        ),
        ("uid", HashSet::from([username])),
        ("cn", HashSet::from([cn.as_str()])),
        ("sn", HashSet::from([sn])),
        (
            "givenName",
            HashSet::from([if first_name.is_empty() {
                username
            } else {
                first_name
            }]),
        ),
        ("mail", HashSet::from([email])),
    ];

    ldap.add(user_dn, attrs)
        .await
        .map_err(|e| format!("LDAP ADD failed: {e}"))?
        .success()
        .map_err(|e| format!("LDAP ADD rejected: {e}"))?;

    let _ = ldap.unbind().await;
    info!(
        user_dn,
        email, "LDAP user entry created (sync registration)"
    );
    Ok(())
}
