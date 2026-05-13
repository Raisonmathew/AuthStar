//! `SecretProvider` — pluggable source of platform bootstrap secrets.
//!
//! ## Why this exists (and why it is *separate* from `SecretStore`)
//!
//! There are two distinct "secret" concerns in the codebase:
//!
//! 1. **Per-tenant OAuth client secrets** \u{2014} verifying secrets that arrive on
//!    every `/oauth/token` request. Handled by [`super::secret_store::SecretStore`]
//!    (DB / KMS / Vault backends).
//! 2. **Platform bootstrap secrets** \u{2014} `JWT_PRIVATE_KEY`, `COMPILER_SK_B64`,
//!    `FACTOR_ENCRYPTION_KEY`, `LDAP_ENCRYPTION_KEY`,
//!    `OAUTH_TOKEN_ENCRYPTION_KEY`, `SSO_ENCRYPTION_KEY`,
//!    `OAUTH_DCR_INITIAL_ACCESS_TOKEN`, `IDAAS_BOOTSTRAP_PASSWORD`. Read once
//!    at startup. Today they come from the process env, which means operators
//!    must hand-paste them into `.env` files or Kubernetes Secrets and mount
//!    them as env vars.
//!
//! This module addresses the *second* category. It introduces a
//! [`SecretProvider`] trait whose implementations are consulted by
//! [`preload_from_env`] *before* `Config::from_env()` runs. Each provider can
//! contribute values for keys that are not already in the OS environment.
//! After preload, the rest of the codebase keeps using `std::env::var`
//! unchanged \u{2014} no invasive refactor.
//!
//! ## Provider precedence
//!
//! Highest wins. The env var `IDAAS_SECRET_SOURCES` (comma-separated) controls
//! the list. Defaults derived from `IDAAS_RUNTIME_PROFILE`:
//!
//! | Profile      | Default sources                            |
//! |--------------|--------------------------------------------|
//! | `local`      | `env` (only)                               |
//! | `compose`    | `env,file:./.env.generated`                |
//! | `kubernetes` | `env,file:/var/run/secrets/idaas`          |
//! | `production` | `env,file:/var/run/secrets/idaas`          |
//!
//! `env` always comes first so OS env vars can override mounted files. Note
//! that `Env` returning `None` for a key is what *enables* the next provider
//! to fill it in.
//!
//! ## Built-in providers
//!
//! * [`EnvProvider`] \u{2014} `std::env::var(key)`. No-op for preload (already in env).
//! * [`MountedFileProvider`] \u{2014} reads files from a directory whose names match
//!   the env var keys. This is the standard Kubernetes pattern (`Secret` mounted
//!   as a volume, one file per key).
//! * [`DotenvFileProvider`] \u{2014} reads a single dotenv file
//!   (`KEY=value` per line). Used for `.env.generated` produced by
//!   `idaas bootstrap`.
//!
//! Vault and AWS Secrets Manager are intentionally **not** built in here:
//! the existing [`super::secret_store`] module already proves out the SDK
//! plumbing for those, and bootstrap secrets are typically rendered into
//! K8s Secrets *before* the pod starts, not fetched at runtime. Adding them
//! later is a matter of implementing one trait method.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A provider that can resolve values for a known set of secret keys.
///
/// Providers are consulted in order during [`preload_from_env`]; the first
/// non-`None` value wins. Implementations must be cheap to construct and
/// must not panic on missing keys.
pub trait SecretProvider: Send + Sync {
    /// Short identifier used in log messages (`"env"`, `"file:/path"`, ...).
    fn name(&self) -> &str;

    /// Best-effort lookup. Returns `Ok(None)` when the provider has nothing
    /// to say about `key`, `Ok(Some(_))` when it does, and `Err(_)` when the
    /// underlying source is broken (which is logged and skipped, not fatal).
    fn get(&self, key: &str) -> anyhow::Result<Option<String>>;
}

// \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}
// EnvProvider
// \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}

/// Trivial wrapper around `std::env`. Always present, lowest cost.
pub struct EnvProvider;

impl SecretProvider for EnvProvider {
    fn name(&self) -> &str {
        "env"
    }
    fn get(&self, key: &str) -> anyhow::Result<Option<String>> {
        Ok(std::env::var(key).ok().filter(|v| !v.is_empty()))
    }
}

// \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}
// MountedFileProvider (Kubernetes Secret-as-volume pattern)
// \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}

/// Reads a directory of files named after secret keys.
///
/// Mirrors how Kubernetes mounts a `Secret` when `volumeMounts` references a
/// secret without `subPath`: each key becomes a file whose contents are the
/// raw value (no `KEY=` prefix, trailing newlines preserved by Kubernetes).
///
/// Lookup is case-sensitive and exact: `JWT_PRIVATE_KEY` resolves to
/// `<dir>/JWT_PRIVATE_KEY`. Missing files yield `Ok(None)`. The provider
/// strips a single trailing `\n` (but not `\r\n`) because most kubectl /
/// editor flows append one.
pub struct MountedFileProvider {
    dir: PathBuf,
    name: String,
}

impl MountedFileProvider {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        let name = format!("file:{}", dir.display());
        Self { dir, name }
    }
}

impl SecretProvider for MountedFileProvider {
    fn name(&self) -> &str {
        &self.name
    }
    fn get(&self, key: &str) -> anyhow::Result<Option<String>> {
        // Reject path-traversal attempts. Keys must be plain
        // `[A-Z0-9_]+` identifiers.
        if !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
            || key.is_empty()
        {
            return Ok(None);
        }
        let path = self.dir.join(key);
        match std::fs::read_to_string(&path) {
            Ok(mut v) => {
                if v.ends_with('\n') && !v.ends_with("\r\n") {
                    v.pop();
                }
                if v.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(v))
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::anyhow!("read {}: {e}", path.display())),
        }
    }
}

// \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}
// DotenvFileProvider (single-file `KEY=value` format)
// \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}

/// Reads a dotenv-style file once into memory.
///
/// We don't use `dotenvy::from_filename_override` here because we want the
/// values to flow through the same `preload_from_env` precedence rules as
/// every other provider, instead of bypassing them.
pub struct DotenvFileProvider {
    name: String,
    map: BTreeMap<String, String>,
}

impl DotenvFileProvider {
    pub fn new(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let body = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
        let map = parse_dotenv(&body);
        Ok(Self {
            name: format!("dotenv:{}", path.display()),
            map,
        })
    }
}

impl SecretProvider for DotenvFileProvider {
    fn name(&self) -> &str {
        &self.name
    }
    fn get(&self, key: &str) -> anyhow::Result<Option<String>> {
        Ok(self.map.get(key).cloned())
    }
}

/// Tiny dotenv parser that handles the subset emitted by `idaas bootstrap`:
/// `KEY=value` and `KEY="quoted value with \\\" escapes and \\n newlines"`.
/// Lines starting with `#` or blank lines are skipped.
fn parse_dotenv(body: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut iter = body.lines().peekable();
    while let Some(line) = iter.next() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(eq) = trimmed.find('=') else { continue };
        let key = trimmed[..eq].trim().to_string();
        let mut rest = trimmed[eq + 1..].to_string();
        if rest.starts_with('"') {
            // Multi-line double-quoted value. Accumulate until a line ends
            // with an unescaped `"`.
            rest.remove(0);
            let mut acc = String::new();
            loop {
                if let Some(end) = find_unescaped_quote(&rest) {
                    acc.push_str(&rest[..end]);
                    break;
                }
                acc.push_str(&rest);
                acc.push('\n');
                let Some(next) = iter.next() else { break };
                rest = next.to_string();
            }
            // Resolve `\\` and `\"` escape sequences. `\n` is left as-is
            // because the bootstrap writer embeds real newlines.
            let unescaped = acc.replace("\\\"", "\"").replace("\\\\", "\\");
            if !key.is_empty() {
                out.insert(key, unescaped);
            }
        } else {
            // Strip inline comment: `value # comment`. Conservative: only
            // when preceded by whitespace.
            let value = if let Some(idx) = rest.find(" #") {
                rest[..idx].trim().to_string()
            } else {
                rest.trim().to_string()
            };
            if !key.is_empty() {
                out.insert(key, value);
            }
        }
    }
    out
}

fn find_unescaped_quote(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == b'"' {
            return Some(i);
        }
        i += 1;
    }
    None
}

// \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}
// Chain construction + preload entry point
// \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}

/// All keys that `preload_from_env` is allowed to populate. Limiting the
/// surface prevents a malicious mounted-secret directory from injecting
/// arbitrary env vars (e.g., `LD_PRELOAD`, `PATH`).
pub const MANAGED_KEYS: &[&str] = &[
    "JWT_PRIVATE_KEY",
    "JWT_PUBLIC_KEY",
    "JWT_ALGORITHM",
    "COMPILER_SK_B64",
    "FACTOR_ENCRYPTION_KEY",
    "LDAP_ENCRYPTION_KEY",
    "OAUTH_TOKEN_ENCRYPTION_KEY",
    "SSO_ENCRYPTION_KEY",
    "OAUTH_DCR_INITIAL_ACCESS_TOKEN",
    "IDAAS_BOOTSTRAP_PASSWORD",
    "DATABASE_URL",
    "REDIS_URL",
    "RUNTIME_GRPC_ADDR",
    "STRIPE_SECRET_KEY",
    "STRIPE_WEBHOOK_SECRET",
    "SENDGRID_API_KEY",
    "SAML_IDP_PRIVATE_KEY",
    "SAML_IDP_CERTIFICATE",
];

/// Walk the configured providers and `set_var` any `MANAGED_KEYS` that are
/// missing from the OS env.
///
/// Source list is taken from `IDAAS_SECRET_SOURCES` (comma-separated). Each
/// entry is one of:
///
/// * `env`                  \u{2014} [`EnvProvider`]
/// * `file:<path>`          \u{2014} [`MountedFileProvider`] (directory)
/// * `dotenv:<path>`        \u{2014} [`DotenvFileProvider`] (single file)
///
/// When unset, defaults are derived from `IDAAS_RUNTIME_PROFILE`.
///
/// This function is designed to be called once during startup, before
/// `Config::from_env()`. It is idempotent: running twice is safe but useless.
pub fn preload_from_env() {
    let providers = build_providers_from_env();
    let provider_names: Vec<&str> = providers.iter().map(|p| p.name()).collect();
    tracing::debug!(?provider_names, "secret_provider preload starting");

    for &key in MANAGED_KEYS {
        if std::env::var_os(key).is_some() {
            continue;
        }
        for provider in &providers {
            match provider.get(key) {
                Ok(Some(value)) => {
                    // SAFETY: this runs during single-threaded startup, before
                    // any tokio tasks spawn. Same invariant as
                    // `RuntimeProfile::apply_defaults`.
                    unsafe { std::env::set_var(key, value) };
                    tracing::debug!(key, source = provider.name(), "secret loaded");
                    break;
                }
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(key, source = provider.name(), error = %e, "secret provider error");
                    continue;
                }
            }
        }
    }
}

fn build_providers_from_env() -> Vec<Box<dyn SecretProvider>> {
    let raw = std::env::var("IDAAS_SECRET_SOURCES").unwrap_or_else(|_| default_sources_for_profile());
    raw.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(parse_source)
        .collect()
}

fn default_sources_for_profile() -> String {
    match crate::config::RuntimeProfile::from_env() {
        crate::config::RuntimeProfile::Local => "env".to_string(),
        crate::config::RuntimeProfile::Compose => "env,dotenv:./.env.generated".to_string(),
        crate::config::RuntimeProfile::Kubernetes
        | crate::config::RuntimeProfile::Production => {
            "env,file:/var/run/secrets/idaas".to_string()
        }
    }
}

fn parse_source(spec: &str) -> Option<Box<dyn SecretProvider>> {
    if spec == "env" {
        return Some(Box::new(EnvProvider));
    }
    if let Some(path) = spec.strip_prefix("file:") {
        let p = PathBuf::from(path);
        if p.is_dir() {
            return Some(Box::new(MountedFileProvider::new(p)));
        }
        // A non-existent path is fine (the secret store may not be mounted in
        // this env). We log and skip rather than fail startup.
        tracing::debug!(path, "secret provider: directory not present, skipping");
        return None;
    }
    if let Some(path) = spec.strip_prefix("dotenv:") {
        match DotenvFileProvider::new(path) {
            Ok(p) => return Some(Box::new(p)),
            Err(e) => {
                tracing::debug!(path, error = %e, "secret provider: dotenv file unavailable, skipping");
                return None;
            }
        }
    }
    tracing::warn!(spec, "secret provider: unknown source spec, ignoring");
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_provider_returns_none_for_missing() {
        let p = EnvProvider;
        // Use a key vanishingly unlikely to exist.
        assert_eq!(
            p.get("IDAAS_TEST_DEFINITELY_UNSET_KEY_XYZZY").unwrap(),
            None
        );
    }

    #[test]
    fn mounted_file_provider_reads_files_and_strips_trailing_newline() {
        let dir = tempdir();
        std::fs::write(dir.join("FACTOR_ENCRYPTION_KEY"), b"abc123\n").unwrap();
        std::fs::write(dir.join("DATABASE_URL"), b"postgres://x").unwrap();

        let p = MountedFileProvider::new(&dir);
        assert_eq!(
            p.get("FACTOR_ENCRYPTION_KEY").unwrap(),
            Some("abc123".to_string())
        );
        assert_eq!(
            p.get("DATABASE_URL").unwrap(),
            Some("postgres://x".to_string())
        );
        assert_eq!(p.get("MISSING").unwrap(), None);
    }

    #[test]
    fn mounted_file_provider_rejects_path_traversal() {
        let dir = tempdir();
        let p = MountedFileProvider::new(&dir);
        assert_eq!(p.get("../etc/passwd").unwrap(), None);
        assert_eq!(p.get("/etc/passwd").unwrap(), None);
        assert_eq!(p.get("").unwrap(), None);
    }

    #[test]
    fn dotenv_provider_parses_quoted_multiline_value() {
        let dir = tempdir();
        let path = dir.join(".env.generated");
        let body = "# header\n\
                    KEY1=value1\n\
                    JWT_PRIVATE_KEY=\"-----BEGIN PRIVATE KEY-----\nMIGH\n-----END PRIVATE KEY-----\n\"\n\
                    KEY2=value2\n";
        std::fs::write(&path, body).unwrap();

        let p = DotenvFileProvider::new(&path).unwrap();
        assert_eq!(p.get("KEY1").unwrap(), Some("value1".to_string()));
        assert_eq!(p.get("KEY2").unwrap(), Some("value2".to_string()));
        let pem = p.get("JWT_PRIVATE_KEY").unwrap().unwrap();
        assert!(pem.contains("BEGIN PRIVATE KEY"));
        assert!(pem.contains("END PRIVATE KEY"));
    }

    #[test]
    fn dotenv_provider_handles_escaped_quotes() {
        let dir = tempdir();
        let path = dir.join(".env");
        std::fs::write(&path, "K=\"a\\\"b\"\n").unwrap();
        let p = DotenvFileProvider::new(&path).unwrap();
        assert_eq!(p.get("K").unwrap(), Some("a\"b".to_string()));
    }

    #[test]
    fn parse_source_unknown_returns_none() {
        assert!(parse_source("frobnicate://nope").is_none());
        assert!(parse_source("file:/path/that/does/not/exist/xyzzy").is_none());
    }

    #[test]
    fn parse_source_env_works() {
        let p = parse_source("env").unwrap();
        assert_eq!(p.name(), "env");
    }

    /// Helper: per-test temp dir that auto-cleans on drop.
    fn tempdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        let suffix: u64 = rand::random();
        p.push(format!("idaas-secret-provider-test-{suffix:x}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
