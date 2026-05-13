use api_server::services::ldap_client;
use std::env;

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} must be set for LDAP integration tests"))
}

fn optional_env(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn optional_bool(name: &str, default: bool) -> bool {
    env::var(name)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(default)
}

#[tokio::test]
#[ignore = "requires a live LDAP directory and LDAP_TEST_* environment variables"]
async fn paged_user_search_returns_directory_entries() {
    let host = required_env("LDAP_TEST_HOST");
    let port = optional_env("LDAP_TEST_PORT", "389")
        .parse::<i32>()
        .expect("LDAP_TEST_PORT must be an integer");
    let bind_dn = required_env("LDAP_TEST_BIND_DN");
    let bind_password = required_env("LDAP_TEST_BIND_PASSWORD");
    let base_dn = required_env("LDAP_TEST_BASE_DN");
    let filter = optional_env("LDAP_TEST_USER_FILTER", "(objectClass=person)");
    let page_size = optional_env("LDAP_TEST_PAGE_SIZE", "2")
        .parse::<i32>()
        .expect("LDAP_TEST_PAGE_SIZE must be an integer");
    let expected_min_entries = optional_env("LDAP_TEST_EXPECT_MIN_ENTRIES", "1")
        .parse::<usize>()
        .expect("LDAP_TEST_EXPECT_MIN_ENTRIES must be an integer");
    let fallback_hosts = optional_env("LDAP_TEST_FAILOVER_HOSTS", "");
    let fallback_hosts: Vec<&str> = fallback_hosts
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .collect();

    let result = ldap_client::search_users(
        &host,
        port,
        optional_bool("LDAP_TEST_USE_SSL", false),
        optional_bool("LDAP_TEST_START_TLS", false),
        optional_bool("LDAP_TEST_SKIP_TLS_VERIFY", false),
        &bind_dn,
        &bind_password,
        &base_dn,
        &filter,
        &["dn", "cn", "mail", "uid", "sAMAccountName"],
        page_size,
        10,
        10,
        &fallback_hosts,
        ldap_client::parse_scope(&optional_env("LDAP_TEST_SEARCH_SCOPE", "subtree")),
    )
    .await
    .expect("LDAP paged user search should succeed");

    assert!(
        result.entries.len() >= expected_min_entries,
        "expected at least {expected_min_entries} LDAP entries, got {}",
        result.entries.len()
    );
    assert!(result.entries.iter().all(|entry| !entry.dn.is_empty()));
    if page_size > 0 && expected_min_entries > page_size as usize {
        assert!(
            result.pages > 1,
            "expected paged search to report multiple pages"
        );
    }
}
