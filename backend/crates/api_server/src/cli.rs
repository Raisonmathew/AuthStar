//! IDaaS operator CLI surface (subcommand dispatch).
//!
//! ## Why this exists
//!
//! The IDaaS server binary historically had exactly one mode: "boot the HTTP
//! API". That made plug-and-play onboarding hard:
//!
//! * Operators had to copy-paste OpenSSL recipes from the README to mint a JWT
//!   ES256 key, an Ed25519 EIAA compiler key, and four 32-byte symmetric
//!   encryption keys (`FACTOR_ENCRYPTION_KEY`, `LDAP_ENCRYPTION_KEY`,
//!   `OAUTH_TOKEN_ENCRYPTION_KEY`, `SSO_ENCRYPTION_KEY`).
//! * Every fresh laptop / CI environment / Kubernetes cluster duplicated the
//!   same fragile manual procedure.
//! * Misgenerated values (wrong base64 alphabet, missing PKCS#8 wrapping,
//!   keys shorter than 32 bytes) caused obscure runtime panics rather than
//!   actionable errors at startup.
//!
//! The CLI flips this around: a single `idaas bootstrap` command produces a
//! `.env.generated` file (or a Kubernetes Secret manifest) containing every
//! secret the platform needs, with strong defaults baked in.
//!
//! ## Dispatch model
//!
//! `main.rs` calls [`maybe_dispatch`] before any async runtime work. If
//! `argv[1]` is a recognized subcommand we run it and exit. Otherwise we
//! return `None` and the caller continues with the normal server bootstrap.
//! This avoids pulling in `clap` (saving compile time) while still allowing a
//! later migration when the surface area grows.

pub mod bootstrap;
pub mod doctor;

/// Try to dispatch a CLI subcommand based on `argv[1]`.
///
/// Returns `Some(exit_code)` (where `0` means success) if a subcommand
/// handled the invocation. The caller MUST exit with that code rather than
/// continuing to the server boot path.
///
/// Returns `None` when no subcommand is present (or the user explicitly
/// passed `serve`, the implicit default), so the caller proceeds with the
/// standard async runtime startup.
pub fn maybe_dispatch() -> Option<i32> {
    let mut args = std::env::args();
    // argv[0] is the binary path — discard it.
    let _ = args.next();
    let Some(subcommand) = args.next() else {
        return None;
    };
    let rest: Vec<String> = args.collect();

    match subcommand.as_str() {
        // Implicit default: behave as before.
        "serve" => None,
        "bootstrap" => Some(bootstrap::run(&rest)),
        "doctor" => Some(doctor::run(&rest)),
        "help" | "--help" | "-h" => {
            print_help();
            Some(0)
        }
        // If the first argument starts with `-` it is almost certainly a flag
        // intended for the (default) server, not a subcommand. Fall through.
        other if other.starts_with('-') => None,
        other => {
            eprintln!("idaas: unknown subcommand `{other}`\n");
            print_help();
            Some(2)
        }
    }
}

fn print_help() {
    eprintln!(
        "IDaaS server CLI

USAGE:
    idaas [SUBCOMMAND] [OPTIONS]

SUBCOMMANDS:
    serve         Run the HTTP API (default when no subcommand is given).
    bootstrap     Generate every secret the platform needs (JWT keys, EIAA
                  compiler key, symmetric encryption keys, admin password,
                  OAuth DCR initial-access token) and write them to a file
    doctor        Probe configuration and external dependencies; print a
                  pass/warn/fail report. Read-only and safe in production.
                  or Kubernetes Secret manifest.
    help          Show this help text.

Run `idaas bootstrap --help` for subcommand-specific options."
    );
}
