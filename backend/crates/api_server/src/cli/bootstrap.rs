//! `idaas bootstrap` — one-shot secret material generator.
//!
//! ## What it produces
//!
//! | Variable                         | Source                                     | Format                                |
//! |----------------------------------|--------------------------------------------|---------------------------------------|
//! | `JWT_PRIVATE_KEY`                | Fresh ES256 (P-256) keypair                | PKCS#8 PEM                            |
//! | `JWT_PUBLIC_KEY`                 | Public half of the same keypair            | SubjectPublicKeyInfo PEM              |
//! | `COMPILER_SK_B64`                | Fresh Ed25519 secret seed                  | base64 (standard, no padding)         |
//! | `FACTOR_ENCRYPTION_KEY`          | 32 random bytes                            | base64url-no-pad                      |
//! | `LDAP_ENCRYPTION_KEY`            | 32 random bytes                            | base64url-no-pad                      |
//! | `OAUTH_TOKEN_ENCRYPTION_KEY`     | 32 random bytes                            | base64url-no-pad                      |
//! | `SSO_ENCRYPTION_KEY`             | 32 random bytes                            | base64url-no-pad                      |
//! | `OAUTH_DCR_INITIAL_ACCESS_TOKEN` | 32 random bytes                            | base64url-no-pad (token-prefix free)  |
//! | `IDAAS_BOOTSTRAP_PASSWORD`       | 24-character ASCII password                | mixed-case + digits + symbols         |
//!
//! ## Output formats
//!
//! * `--format=env` (default) — write a dotenv file (`.env.generated` by
//!   default). Suitable for local laptops and Docker Compose. Operators move
//!   the values into their actual `.env` and burn the generated file.
//! * `--format=k8s` — emit a `kind: Secret` YAML manifest to stdout. Pipe to
//!   `kubectl apply -f -` or commit to a sealed-secrets / SOPS workflow.
//! * `--format=json` — emit a JSON object. Useful for HashiCorp Vault `kv put`
//!   or an external secret-injection tool.
//!
//! ## Safety guarantees
//!
//! * **No silent overwrite.** If the output file exists, the command exits
//!   non-zero unless `--force` is passed.
//! * **CSPRNG only.** All randomness comes from `OsRng` (via `rand::thread_rng`
//!   for ed25519-dalek and directly for symmetric keys / passwords).
//! * **PEM keys are PKCS#8.** They drop straight into `jsonwebtoken`'s
//!   `EncodingKey::from_ec_pem` without manual reformatting.
//! * **stdout is never used for secrets in `env` format.** The file path is
//!   echoed to stderr so shell redirection cannot accidentally leak the
//!   contents into a pipeline.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use base64::Engine;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rand::{rngs::OsRng, RngCore};

/// Output format selector for the generated secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    /// dotenv file (default).
    Env,
    /// Kubernetes Secret manifest on stdout.
    K8s,
    /// JSON object on stdout.
    Json,
}

/// Parsed command-line arguments for `idaas bootstrap`.
struct Args {
    format: Format,
    out: Option<PathBuf>,
    force: bool,
    namespace: String,
    secret_name: String,
}

impl Default for Args {
    fn default() -> Self {
        // Default format follows the runtime profile when set: kubernetes /
        // production profiles emit a Secret manifest because writing a file
        // on a control-plane host would be the wrong call.
        let format = match std::env::var("IDAAS_RUNTIME_PROFILE")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "kubernetes" | "production" => Format::K8s,
            _ => Format::Env,
        };
        Self {
            format,
            out: None,
            force: false,
            namespace: "idaas".to_string(),
            secret_name: "idaas-bootstrap".to_string(),
        }
    }
}

/// Entry point invoked from [`crate::cli::maybe_dispatch`].
pub fn run(argv: &[String]) -> i32 {
    let args = match parse(argv) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("idaas bootstrap: {msg}\n");
            print_help();
            return 2;
        }
    };

    let secrets = match generate() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("idaas bootstrap: failed to generate secrets: {e}");
            return 1;
        }
    };

    let result = match args.format {
        Format::Env => write_env(&args, &secrets),
        Format::K8s => write_k8s(&args, &secrets),
        Format::Json => write_json(&secrets),
    };

    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("idaas bootstrap: {e}");
            1
        }
    }
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
            "--force" | "-f" => args.force = true,
            "--format" => {
                i += 1;
                let v = argv.get(i).ok_or("--format requires a value")?;
                args.format = parse_format(v)?;
            }
            v if v.starts_with("--format=") => {
                args.format = parse_format(&v["--format=".len()..])?;
            }
            "--out" | "-o" => {
                i += 1;
                let v = argv.get(i).ok_or("--out requires a path")?;
                args.out = Some(PathBuf::from(v));
            }
            v if v.starts_with("--out=") => {
                args.out = Some(PathBuf::from(&v["--out=".len()..]));
            }
            "--namespace" => {
                i += 1;
                args.namespace = argv.get(i).ok_or("--namespace requires a value")?.clone();
            }
            v if v.starts_with("--namespace=") => {
                args.namespace = v["--namespace=".len()..].to_string();
            }
            "--name" => {
                i += 1;
                args.secret_name = argv.get(i).ok_or("--name requires a value")?.clone();
            }
            v if v.starts_with("--name=") => {
                args.secret_name = v["--name=".len()..].to_string();
            }
            other => return Err(format!("unknown flag `{other}`")),
        }
        i += 1;
    }
    Ok(args)
}

fn parse_format(v: &str) -> Result<Format, String> {
    match v {
        "env" | "dotenv" => Ok(Format::Env),
        "k8s" | "kubernetes" => Ok(Format::K8s),
        "json" => Ok(Format::Json),
        other => Err(format!(
            "unknown --format `{other}` (expected env|k8s|json)"
        )),
    }
}

fn print_help() {
    eprintln!(
        "idaas bootstrap — generate every secret the platform needs

USAGE:
    idaas bootstrap [OPTIONS]

OPTIONS:
    --format <env|k8s|json>   Output format. Defaults follow IDAAS_RUNTIME_PROFILE
                              (kubernetes/production -> k8s, otherwise env).
    --out <PATH>              File path for env format (default: .env.generated).
                              Ignored for k8s/json (stdout is used).
    --force                   Overwrite the output file if it already exists.
    --namespace <NS>          Kubernetes namespace for k8s output (default: idaas).
    --name <NAME>             Kubernetes Secret name (default: idaas-bootstrap).
    -h, --help                Show this help.

EXAMPLES:
    idaas bootstrap                          # write .env.generated
    idaas bootstrap --out backend/.env       # write directly to backend/.env
    idaas bootstrap --format k8s | kubectl apply -f -
    idaas bootstrap --format json > secrets.json"
    );
}

/// Bag of generated secret material.
struct Secrets {
    jwt_private_pem: String,
    jwt_public_pem: String,
    compiler_sk_b64: String,
    factor_key: String,
    ldap_key: String,
    oauth_token_key: String,
    sso_key: String,
    dcr_initial_access_token: String,
    bootstrap_password: String,
}

fn generate() -> anyhow::Result<Secrets> {
    // ES256 (P-256) keypair as PKCS#8 PEM.
    let signing = P256SigningKey::random(&mut OsRng);
    let verifying = signing.verifying_key();
    let jwt_private_pem = signing
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("ES256 PKCS#8 PEM encode: {e}"))?
        .to_string();
    let jwt_public_pem = verifying
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("ES256 SPKI PEM encode: {e}"))?;

    // Ed25519 EIAA compiler signing seed.
    let compiler = Ed25519SigningKey::generate(&mut OsRng);
    let compiler_sk_b64 =
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(compiler.to_bytes());

    Ok(Secrets {
        jwt_private_pem,
        jwt_public_pem,
        compiler_sk_b64,
        factor_key: rand_b64url_32(),
        ldap_key: rand_b64url_32(),
        oauth_token_key: rand_b64url_32(),
        sso_key: rand_b64url_32(),
        dcr_initial_access_token: rand_b64url_32(),
        bootstrap_password: random_password(24),
    })
}

/// 32 bytes of CSPRNG output, base64url-no-pad encoded.
///
/// This matches what existing consumers (auth_core's symmetric key loaders)
/// already accept and is the format prescribed by `backend/.env.example`.
fn rand_b64url_32() -> String {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// Generate an ASCII password of `len` characters drawn from a mixed
/// alphabet. Avoids ambiguous characters (`O`/`0`, `l`/`1`) that confuse
/// operators copy-pasting from terminals.
fn random_password(len: usize) -> String {
    const CHARSET: &[u8] =
        b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";
    let mut out = String::with_capacity(len);
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    for b in buf {
        out.push(CHARSET[(b as usize) % CHARSET.len()] as char);
    }
    out
}

fn write_env(args: &Args, s: &Secrets) -> anyhow::Result<()> {
    let path = args
        .out
        .clone()
        .unwrap_or_else(|| PathBuf::from(".env.generated"));

    if path.exists() && !args.force {
        anyhow::bail!(
            "refusing to overwrite existing file `{}` (pass --force to override)",
            path.display()
        );
    }

    // PEM keys contain newlines; dotenv consumers (dotenvy) accept them when
    // wrapped in double quotes with literal `\n`. We choose double-quoted
    // multi-line because dotenvy supports it and it round-trips cleanly.
    let body = format!(
        "# Generated by `idaas bootstrap` — do not commit this file.\n\
         # Move these values into your secret manager and delete this file.\n\
         \n\
         JWT_PRIVATE_KEY=\"{jwt_priv}\"\n\
         JWT_PUBLIC_KEY=\"{jwt_pub}\"\n\
         JWT_ALGORITHM=ES256\n\
         \n\
         COMPILER_SK_B64={compiler}\n\
         \n\
         FACTOR_ENCRYPTION_KEY={factor}\n\
         LDAP_ENCRYPTION_KEY={ldap}\n\
         OAUTH_TOKEN_ENCRYPTION_KEY={oauth_tok}\n\
         SSO_ENCRYPTION_KEY={sso}\n\
         \n\
         OAUTH_DCR_INITIAL_ACCESS_TOKEN={dcr}\n\
         IDAAS_BOOTSTRAP_PASSWORD={pw}\n",
        jwt_priv = escape_double_quoted(&s.jwt_private_pem),
        jwt_pub = escape_double_quoted(&s.jwt_public_pem),
        compiler = s.compiler_sk_b64,
        factor = s.factor_key,
        ldap = s.ldap_key,
        oauth_tok = s.oauth_token_key,
        sso = s.sso_key,
        dcr = s.dcr_initial_access_token,
        pw = s.bootstrap_password,
    );

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    let mut f = opts
        .open(&path)
        .map_err(|e| anyhow::anyhow!("open {}: {e}", path.display()))?;
    f.write_all(body.as_bytes())?;
    // Best-effort: tighten file permissions on Unix so the secrets file is
    // not group/world readable. No-op on Windows.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    eprintln!("idaas bootstrap: wrote {}", path.display());
    eprintln!(
        "idaas bootstrap: admin password: {} (also stored in IDAAS_BOOTSTRAP_PASSWORD)",
        s.bootstrap_password
    );
    eprintln!(
        "idaas bootstrap: NEXT STEPS — move these values into your secret manager, then delete the file."
    );
    Ok(())
}

/// Escape a string for inclusion in a `KEY="..."` dotenv value.
/// The only characters that matter inside double quotes are `"` and `\`.
fn escape_double_quoted(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn write_k8s(args: &Args, s: &Secrets) -> anyhow::Result<()> {
    // Kubernetes Secret values are base64-encoded (standard alphabet, with
    // padding). Wrapping the raw secret strings in base64 is what lets PEM
    // newlines and password symbols survive the YAML round-trip.
    let b64 = |v: &str| base64::engine::general_purpose::STANDARD.encode(v.as_bytes());

    let manifest = format!(
        "apiVersion: v1\n\
         kind: Secret\n\
         metadata:\n  \
           name: {name}\n  \
           namespace: {ns}\n\
         type: Opaque\n\
         data:\n  \
           JWT_PRIVATE_KEY: {jwt_priv}\n  \
           JWT_PUBLIC_KEY: {jwt_pub}\n  \
           JWT_ALGORITHM: {alg}\n  \
           COMPILER_SK_B64: {compiler}\n  \
           FACTOR_ENCRYPTION_KEY: {factor}\n  \
           LDAP_ENCRYPTION_KEY: {ldap}\n  \
           OAUTH_TOKEN_ENCRYPTION_KEY: {oauth_tok}\n  \
           SSO_ENCRYPTION_KEY: {sso}\n  \
           OAUTH_DCR_INITIAL_ACCESS_TOKEN: {dcr}\n  \
           IDAAS_BOOTSTRAP_PASSWORD: {pw}\n",
        name = args.secret_name,
        ns = args.namespace,
        jwt_priv = b64(&s.jwt_private_pem),
        jwt_pub = b64(&s.jwt_public_pem),
        alg = b64("ES256"),
        compiler = b64(&s.compiler_sk_b64),
        factor = b64(&s.factor_key),
        ldap = b64(&s.ldap_key),
        oauth_tok = b64(&s.oauth_token_key),
        sso = b64(&s.sso_key),
        dcr = b64(&s.dcr_initial_access_token),
        pw = b64(&s.bootstrap_password),
    );

    print!("{manifest}");
    Ok(())
}

fn write_json(s: &Secrets) -> anyhow::Result<()> {
    let v = serde_json::json!({
        "JWT_PRIVATE_KEY": s.jwt_private_pem,
        "JWT_PUBLIC_KEY": s.jwt_public_pem,
        "JWT_ALGORITHM": "ES256",
        "COMPILER_SK_B64": s.compiler_sk_b64,
        "FACTOR_ENCRYPTION_KEY": s.factor_key,
        "LDAP_ENCRYPTION_KEY": s.ldap_key,
        "OAUTH_TOKEN_ENCRYPTION_KEY": s.oauth_token_key,
        "SSO_ENCRYPTION_KEY": s.sso_key,
        "OAUTH_DCR_INITIAL_ACCESS_TOKEN": s.dcr_initial_access_token,
        "IDAAS_BOOTSTRAP_PASSWORD": s.bootstrap_password,
    });
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_defaults() {
        let a = parse(&[]).expect("default parse");
        assert!(matches!(a.format, Format::Env | Format::K8s));
        assert!(!a.force);
        assert!(a.out.is_none());
    }

    #[test]
    fn parse_format_long() {
        let a = parse(&["--format=json".into()]).unwrap();
        assert_eq!(a.format, Format::Json);
    }

    #[test]
    fn parse_format_split() {
        let a = parse(&["--format".into(), "k8s".into()]).unwrap();
        assert_eq!(a.format, Format::K8s);
    }

    #[test]
    fn parse_unknown_flag_fails() {
        assert!(parse(&["--nope".into()]).is_err());
    }

    #[test]
    fn generate_produces_well_formed_secrets() {
        let s = generate().expect("generate");
        // ES256 PEM markers
        assert!(s.jwt_private_pem.contains("BEGIN PRIVATE KEY"));
        assert!(s.jwt_public_pem.contains("BEGIN PUBLIC KEY"));
        // Ed25519 seed is exactly 32 bytes => 43 base64-no-pad chars.
        assert_eq!(s.compiler_sk_b64.len(), 43);
        // 32 bytes base64url-no-pad => 43 chars.
        for k in [&s.factor_key, &s.ldap_key, &s.oauth_token_key, &s.sso_key, &s.dcr_initial_access_token] {
            assert_eq!(k.len(), 43, "expected 32-byte base64url-no-pad, got {k}");
            assert!(!k.contains('+') && !k.contains('/') && !k.contains('='));
        }
        assert_eq!(s.bootstrap_password.len(), 24);
    }

    #[test]
    fn each_invocation_yields_distinct_keys() {
        let a = generate().unwrap();
        let b = generate().unwrap();
        assert_ne!(a.factor_key, b.factor_key);
        assert_ne!(a.compiler_sk_b64, b.compiler_sk_b64);
        assert_ne!(a.jwt_private_pem, b.jwt_private_pem);
    }

    #[test]
    fn escape_double_quoted_handles_quotes_and_backslashes() {
        assert_eq!(escape_double_quoted("a\"b\\c"), "a\\\"b\\\\c");
    }
}
