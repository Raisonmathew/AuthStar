//! `idaas doctor` — readiness diagnostic CLI.
//!
//! ## Why this exists
//!
//! When `docker compose up` or `kubectl rollout` fails, operators currently
//! have to grep through Rust panic backtraces to figure out *which* of ~70
//! config knobs is misconfigured. `idaas doctor` flips that around: it loads
//! the same env the server would see, runs network probes against every
//! external dependency, and prints a concise pass/warn/fail report.
//!
//! It is intentionally **read-only** and never mutates the database, Redis,
//! or the runtime. Safe to run against production.
//!
//! ## What it checks
//!
//! 1. **Profile + APP_ENV** — which `RuntimeProfile` is active, what default
//!    overrides have been applied.
//! 2. **Required secrets present** — JWT keypair, COMPILER_SK_B64,
//!    FACTOR/LDAP/OAUTH_TOKEN/SSO encryption keys.
//! 3. **DATABASE_URL connectivity** — opens a single connection and runs
//!    `SELECT 1`.
//! 4. **REDIS_URL connectivity** — opens a connection and PINGs.
//! 5. **RUNTIME_GRPC_ADDR connectivity** — opens a TCP socket (avoids
//!    requiring the gRPC server to actually be live, which is a
//!    chicken-and-egg problem during rollout).
//! 6. **Optional protocol readiness** — for each of OAuth DCR / SAML / SCIM
//!    / LDAP / Stripe / Email, prints whether it is configured and what
//!    behaviour to expect (enabled / disabled-with-501).
//!
//! ## Output format
//!
//! Plain ASCII (works in any terminal), one finding per line, prefixed with
//! `[OK]`, `[WARN]`, or `[FAIL]`. Exit code is `0` if no `FAIL` findings,
//! `1` otherwise. `--format=json` emits a machine-readable report for CI.

use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    Ok,
    Warn,
    Fail,
}

impl Severity {
    fn tag(self) -> &'static str {
        match self {
            Self::Ok => "[OK]  ",
            Self::Warn => "[WARN]",
            Self::Fail => "[FAIL]",
        }
    }
}

#[derive(Clone, Debug)]
struct Finding {
    severity: Severity,
    category: &'static str,
    message: String,
    detail: Option<String>,
}

impl Finding {
    fn ok(category: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Ok,
            category,
            message: message.into(),
            detail: None,
        }
    }
    fn warn(category: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warn,
            category,
            message: message.into(),
            detail: None,
        }
    }
    fn fail(category: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Fail,
            category,
            message: message.into(),
            detail: None,
        }
    }
    fn with_detail(mut self, d: impl Into<String>) -> Self {
        self.detail = Some(d.into());
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    Text,
    Json,
}

struct Args {
    format: Format,
    timeout: Duration,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            format: Format::Text,
            timeout: Duration::from_secs(5),
        }
    }
}

pub fn run(argv: &[String]) -> i32 {
    let args = match parse(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("idaas doctor: {e}\n");
            print_help();
            return 2;
        }
    };

    // Apply profile defaults so the doctor sees the same env the server would.
    // Mirrors what `Config::from_env` does, but without loading the full
    // Config (which would itself fail when secrets are missing — exactly the
    // case we want to *report* on).
    let _ = dotenvy::dotenv();
    crate::config::RuntimeProfile::from_env().apply_defaults();
    crate::services::secret_provider::preload_from_env();

    let mut findings: Vec<Finding> = Vec::new();
    findings.push(profile_finding());
    findings.extend(secret_findings());
    findings.extend(protocol_findings());

    // Connectivity probes need an async runtime. Build a small current-thread
    // one rather than `#[tokio::main]` because the CLI dispatcher runs before
    // the server's runtime is started.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("idaas doctor: failed to start tokio runtime: {e}");
            return 1;
        }
    };
    rt.block_on(async {
        findings.push(probe_database(args.timeout).await);
        findings.push(probe_redis(args.timeout).await);
        findings.push(probe_runtime(args.timeout).await);
    });

    let exit_code = if findings.iter().any(|f| f.severity == Severity::Fail) {
        1
    } else {
        0
    };

    match args.format {
        Format::Text => print_text(&findings),
        Format::Json => print_json(&findings),
    }
    exit_code
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let mut args = Args::default();
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        match a.as_str() {
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--format" => {
                i += 1;
                args.format = parse_format(argv.get(i).ok_or("--format requires a value")?)?;
            }
            v if v.starts_with("--format=") => {
                args.format = parse_format(&v["--format=".len()..])?;
            }
            "--timeout" => {
                i += 1;
                let v = argv.get(i).ok_or("--timeout requires seconds")?;
                args.timeout = Duration::from_secs(
                    v.parse().map_err(|_| format!("invalid --timeout `{v}`"))?,
                );
            }
            v if v.starts_with("--timeout=") => {
                let n: u64 = v["--timeout=".len()..]
                    .parse()
                    .map_err(|_| "invalid --timeout".to_string())?;
                args.timeout = Duration::from_secs(n);
            }
            other => return Err(format!("unknown flag `{other}`")),
        }
        i += 1;
    }
    Ok(args)
}

fn parse_format(v: &str) -> Result<Format, String> {
    match v {
        "text" => Ok(Format::Text),
        "json" => Ok(Format::Json),
        other => Err(format!("unknown --format `{other}` (expected text|json)")),
    }
}

fn print_help() {
    eprintln!(
        "idaas doctor \u{2014} probe configuration and external dependencies

USAGE:
    idaas doctor [OPTIONS]

OPTIONS:
    --format <text|json>    Output format (default: text).
    --timeout <SECS>        Per-probe timeout in seconds (default: 5).
    -h, --help              Show this help.

EXIT CODES:
    0  no FAIL findings
    1  one or more FAIL findings (or runtime error)
    2  invalid arguments"
    );
}

fn profile_finding() -> Finding {
    let profile = crate::config::RuntimeProfile::from_env();
    let app_env = std::env::var("APP_ENV").unwrap_or_else(|_| "development".into());
    Finding::ok(
        "profile",
        format!("profile={} app_env={}", profile.as_str(), app_env),
    )
}

/// Required secrets. Each entry: (env var, human label, fail-in-production).
const REQUIRED_SECRETS: &[(&str, &str, bool)] = &[
    ("JWT_PRIVATE_KEY", "JWT signing key (private)", true),
    ("JWT_PUBLIC_KEY", "JWT verifying key (public)", true),
    ("DATABASE_URL", "Postgres connection string", true),
    ("REDIS_URL", "Redis connection string", true),
    (
        "FACTOR_ENCRYPTION_KEY",
        "TOTP factor encryption key",
        false,
    ),
    (
        "COMPILER_SK_B64",
        "EIAA capsule signing key (Ed25519)",
        false,
    ),
    (
        "OAUTH_TOKEN_ENCRYPTION_KEY",
        "OAuth refresh-token encryption key",
        false,
    ),
    ("SSO_ENCRYPTION_KEY", "SSO state encryption key", false),
];

fn secret_findings() -> Vec<Finding> {
    let is_prod = std::env::var("APP_ENV")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(false);

    REQUIRED_SECRETS
        .iter()
        .map(|(key, label, prod_required)| {
            let present = std::env::var(key).map(|v| !v.is_empty()).unwrap_or(false);
            if present {
                Finding::ok("secrets", format!("{label} present ({key})"))
            } else if is_prod && *prod_required {
                Finding::fail(
                    "secrets",
                    format!("{label} MISSING in production ({key})"),
                )
                .with_detail(format!(
                    "Run `idaas bootstrap` to generate, or set {key} explicitly."
                ))
            } else {
                Finding::warn("secrets", format!("{label} not set ({key})"))
                    .with_detail(format!(
                        "Will be auto-generated at startup OR feature disabled. Run `idaas bootstrap` for stable values."
                    ))
            }
        })
        .collect()
}

/// Optional protocol gates. Each entry: (label, env var(s) that enable it, behaviour-when-missing).
fn protocol_findings() -> Vec<Finding> {
    fn any_present(keys: &[&str]) -> bool {
        keys.iter()
            .any(|k| std::env::var(k).map(|v| !v.is_empty()).unwrap_or(false))
    }

    let probes: &[(&str, &[&str], &str)] = &[
        (
            "OAuth Dynamic Client Registration",
            &["OAUTH_DCR_INITIAL_ACCESS_TOKEN"],
            "POST /oauth/register returns 403 until set",
        ),
        (
            "Stripe billing",
            &["STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET"],
            "Billing endpoints return 501 until set",
        ),
        (
            "Email (SMTP/SendGrid)",
            &["SENDGRID_API_KEY", "SMTP_HOST"],
            "Verification emails skipped, warning logged",
        ),
        (
            "LDAP outbound",
            &["LDAP_BIND_DN", "LDAP_URL"],
            "LDAP federation disabled until set",
        ),
        (
            "SAML IdP signing",
            &["SAML_IDP_PRIVATE_KEY", "SAML_IDP_CERTIFICATE"],
            "SAML SSO disabled until set",
        ),
        (
            "Geo IP enrichment",
            &["IPLOCATE_API_KEY"],
            "Risk scoring runs without geo context",
        ),
    ];

    probes
        .iter()
        .map(|(label, keys, behaviour)| {
            if any_present(keys) {
                Finding::ok("protocol", format!("{label} enabled"))
            } else {
                Finding::warn("protocol", format!("{label} disabled"))
                    .with_detail((*behaviour).to_string())
            }
        })
        .collect()
}

async fn probe_database(timeout: Duration) -> Finding {
    let url = match std::env::var("DATABASE_URL") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            return Finding::fail("database", "DATABASE_URL not set")
                .with_detail("Apply a runtime profile or set DATABASE_URL explicitly.");
        }
    };

    let connect = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(timeout)
        .connect(&url);

    match tokio::time::timeout(timeout + Duration::from_secs(1), connect).await {
        Ok(Ok(pool)) => {
            let q = sqlx::query("SELECT 1").execute(&pool).await;
            pool.close().await;
            match q {
                Ok(_) => Finding::ok("database", format!("Postgres reachable @ {}", redact_url(&url))),
                Err(e) => Finding::fail("database", "Postgres SELECT 1 failed")
                    .with_detail(e.to_string()),
            }
        }
        Ok(Err(e)) => Finding::fail("database", "Postgres connect failed")
            .with_detail(format!("{e} (url={})", redact_url(&url))),
        Err(_) => Finding::fail("database", "Postgres connect timed out")
            .with_detail(format!("timeout after {:?} (url={})", timeout, redact_url(&url))),
    }
}

async fn probe_redis(timeout: Duration) -> Finding {
    let url = match std::env::var("REDIS_URL") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            return Finding::fail("redis", "REDIS_URL not set")
                .with_detail("Apply a runtime profile or set REDIS_URL explicitly.");
        }
    };

    let client = match redis::Client::open(url.as_str()) {
        Ok(c) => c,
        Err(e) => return Finding::fail("redis", "REDIS_URL parse failed").with_detail(e.to_string()),
    };

    let conn_fut = client.get_async_connection();
    let mut conn = match tokio::time::timeout(timeout, conn_fut).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            return Finding::fail("redis", "Redis connect failed")
                .with_detail(format!("{e} (url={})", redact_url(&url)));
        }
        Err(_) => {
            return Finding::fail("redis", "Redis connect timed out")
                .with_detail(format!("timeout after {:?}", timeout));
        }
    };

    match redis::cmd("PING").query_async::<_, String>(&mut conn).await {
        Ok(s) if s == "PONG" => Finding::ok("redis", format!("Redis reachable @ {}", redact_url(&url))),
        Ok(other) => Finding::warn("redis", format!("Redis PING returned `{other}` (expected PONG)")),
        Err(e) => Finding::fail("redis", "Redis PING failed").with_detail(e.to_string()),
    }
}

async fn probe_runtime(timeout: Duration) -> Finding {
    let addr = std::env::var("RUNTIME_GRPC_ADDR")
        .unwrap_or_else(|_| "http://127.0.0.1:50061".into());

    // Parse host:port out of the URL. tonic accepts http(s)://host:port; we only
    // need the host:port piece for a TCP socket probe.
    let host_port = match parse_host_port(&addr) {
        Some(hp) => hp,
        None => {
            return Finding::fail("runtime", format!("RUNTIME_GRPC_ADDR `{addr}` is not parseable"));
        }
    };

    let connect = tokio::net::TcpStream::connect(&host_port);
    match tokio::time::timeout(timeout, connect).await {
        Ok(Ok(_)) => Finding::ok("runtime", format!("Runtime gRPC reachable @ {addr}")),
        Ok(Err(e)) => Finding::fail("runtime", format!("Runtime TCP connect failed @ {addr}"))
            .with_detail(e.to_string()),
        Err(_) => Finding::fail("runtime", format!("Runtime TCP connect timed out @ {addr}"))
            .with_detail(format!("timeout after {:?}", timeout)),
    }
}

/// Convert `http://host:port[/path]` (or `host:port`) into `host:port` for TCP probing.
fn parse_host_port(addr: &str) -> Option<String> {
    let stripped = addr
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_start_matches("grpc://");
    let host_port = stripped.split('/').next()?;
    if host_port.contains(':') {
        Some(host_port.to_string())
    } else {
        // Default port if URL omitted it.
        Some(format!("{host_port}:50061"))
    }
}

/// Redact userinfo from a URL so we can safely echo it in logs.
/// `postgres://user:pass@host/db` -> `postgres://***@host/db`.
fn redact_url(url: &str) -> String {
    if let Some((scheme, rest)) = url.split_once("://") {
        if let Some((_, host_part)) = rest.split_once('@') {
            return format!("{scheme}://***@{host_part}");
        }
    }
    url.to_string()
}

fn print_text(findings: &[Finding]) {
    let mut by_cat: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        by_cat.entry(f.category).or_default().push(f);
    }
    println!("idaas doctor report");
    println!("===================");
    for (cat, items) in &by_cat {
        println!("\n# {cat}");
        for f in items {
            println!("{} {}", f.severity.tag(), f.message);
            if let Some(d) = &f.detail {
                println!("       \u{2514}\u{2500} {d}");
            }
        }
    }
    let fails = findings.iter().filter(|f| f.severity == Severity::Fail).count();
    let warns = findings.iter().filter(|f| f.severity == Severity::Warn).count();
    let oks = findings.iter().filter(|f| f.severity == Severity::Ok).count();
    println!("\nSummary: {oks} OK, {warns} WARN, {fails} FAIL");
}

fn print_json(findings: &[Finding]) {
    let arr: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "severity": match f.severity {
                    Severity::Ok => "ok",
                    Severity::Warn => "warn",
                    Severity::Fail => "fail",
                },
                "category": f.category,
                "message": f.message,
                "detail": f.detail,
            })
        })
        .collect();
    let summary = serde_json::json!({
        "ok": findings.iter().filter(|f| f.severity == Severity::Ok).count(),
        "warn": findings.iter().filter(|f| f.severity == Severity::Warn).count(),
        "fail": findings.iter().filter(|f| f.severity == Severity::Fail).count(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "findings": arr,
            "summary": summary,
        }))
        .unwrap()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_strips_userinfo() {
        assert_eq!(
            redact_url("postgres://u:p@host:5432/db"),
            "postgres://***@host:5432/db"
        );
        assert_eq!(redact_url("redis://redis:6379"), "redis://redis:6379");
    }

    #[test]
    fn parse_host_port_handles_schemes() {
        assert_eq!(
            parse_host_port("http://runtime:50061"),
            Some("runtime:50061".to_string())
        );
        assert_eq!(
            parse_host_port("127.0.0.1:50061"),
            Some("127.0.0.1:50061".to_string())
        );
        assert_eq!(
            parse_host_port("http://runtime"),
            Some("runtime:50061".to_string())
        );
    }

    #[test]
    fn parse_format_accepts_text_and_json() {
        assert_eq!(parse_format("text").unwrap(), Format::Text);
        assert_eq!(parse_format("json").unwrap(), Format::Json);
        assert!(parse_format("yaml").is_err());
    }

    #[test]
    fn parse_default_args() {
        let a = parse(&[]).unwrap();
        assert_eq!(a.format, Format::Text);
        assert_eq!(a.timeout, Duration::from_secs(5));
    }

    #[test]
    fn parse_timeout_split() {
        let a = parse(&["--timeout".into(), "10".into()]).unwrap();
        assert_eq!(a.timeout, Duration::from_secs(10));
    }
}
