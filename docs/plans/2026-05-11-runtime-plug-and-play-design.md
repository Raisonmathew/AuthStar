# Runtime Plug-and-Play — Enterprise Design

**Status:** Draft (in implementation)
**Date:** 2026-05-11
**Owner:** Platform Eng
**Scope:** Backend (`api_server`, `runtime_service`), Compose, K8s base, docs

---

## 1. Problem Statement

Today the IDaaS stack is *operationally fragile* on first boot. Concrete failures:

| # | File:Line | Symptom |
|---|-----------|---------|
| 1 | [infrastructure/docker-compose/docker-compose.dev.yml](infrastructure/docker-compose/docker-compose.dev.yml#L113-L121) | `runtime` container has no `env_file`, no `RUNTIME_DATABASE_URL`. Hard-fails in `APP_ENV=production`/`staging`. |
| 2 | [backend/crates/api_server/src/config.rs](backend/crates/api_server/src/config.rs) | Default `RUNTIME_GRPC_ADDR=http://127.0.0.1:50061` — wrong inside Compose (should be `http://runtime:50061`). |
| 3 | [infrastructure/docker-compose/docker-compose.dev.yml](infrastructure/docker-compose/docker-compose.dev.yml#L117-L118) | Runtime gRPC port `50061` is **publicly published**, contradicting source comment requiring internal-only access. |
| 4 | [backend/crates/api_server/src/state.rs](backend/crates/api_server/src/state.rs) | Multiple secrets (`COMPILER_SK_B64`, `JWT_PRIVATE_KEY`, `FACTOR_ENCRYPTION_KEY`, `LDAP_ENCRYPTION_KEY`, `OAUTH_TOKEN_ENCRYPTION_KEY`) must be hand-generated. No bootstrap. |
| 5 | n/a | Optional protocols (SCIM, LDAP, SAML, OAuth DCR, Stripe, email) gate startup instead of being lazy. |
| 6 | n/a | No readiness/diagnostic CLI to tell operators *what* is missing. |

**Net effect:** A new operator cannot run `docker compose up` and get a working stack without reading source code and generating five different keys by hand.

---

## 2. Goals

1. **Zero-edit local boot:** `docker compose up` produces a functional stack from a clean checkout.
2. **Profile-aware defaults:** the same binary chooses sane wiring for `local`, `compose`, `kubernetes`, `production`.
3. **One-command secret bootstrap:** `idaas bootstrap` generates all required secrets, writing to `.env.generated` (dev) or K8s `Secret` manifests (prod).
4. **Diagnostic readiness check:** `idaas doctor` prints a redacted, color-coded readiness report.
5. **Lazy optional protocols:** missing optional config disables the feature; never a startup crash.
6. **No regression** of production hard-fail safety: production still refuses to boot with weak/default secrets.

---

## 3. Non-Goals

- Replacing Vault / AWS Secrets Manager / K8s External Secrets in production.
- Auto-generating TLS certificates (cert-manager / Let's Encrypt remains separate).
- Multi-cluster service discovery (Consul / etcd integration).

---

## 4. Architecture — Three Layers

### Layer A: Runtime Profiles

New env: `IDAAS_RUNTIME_PROFILE = local | compose | kubernetes | production` (default: `local`).

Profile drives **defaults only** — every value remains overridable by explicit env.

| Setting | local | compose | kubernetes | production |
|---|---|---|---|---|
| `RUNTIME_GRPC_ADDR` | `http://127.0.0.1:50061` | `http://runtime:50061` | `http://runtime.idaas.svc.cluster.local:50061` | *required* |
| `DATABASE_URL` | local default | `postgres://...@postgres:5432/idaas` | from `Secret` | *required* |
| `REDIS_URL` | `redis://127.0.0.1:6379` | `redis://redis:6379` | `redis://redis.idaas.svc:6379` | *required* |
| Hard-fail on missing secrets | warn | warn | fail | fail |
| Auto-generate dev keys | yes | yes | no | no |

Implementation: `Config::apply_profile_defaults(profile)` runs after `.env` load, before validation.

### Layer B: Bootstrap Command

New subcommand: `idaas bootstrap [--profile <p>] [--out <path>] [--force]`.

Generates:

- JWT ES256 key pair (PEM) → `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`
- Ed25519 capsule signing key → `COMPILER_SK_B64`, `RUNTIME_COMPILER_PK_B64` (paired)
- AES-256-GCM keys → `FACTOR_ENCRYPTION_KEY`, `LDAP_ENCRYPTION_KEY`, `OAUTH_TOKEN_ENCRYPTION_KEY`, `SSO_STATE_ENCRYPTION_KEY`
- Random `OAUTH_DCR_INITIAL_ACCESS_TOKEN`
- Optional bootstrap admin password (printed once)

Output formats by profile:
- `local`/`compose` → writes `backend/.env.generated` (gitignored), prints “source it or merge into `.env`”.
- `kubernetes` → emits `bootstrap-secrets.yaml` (`kind: Secret`, `stringData:`).
- `production` → refuses unless `--force`, then prints to stdout for piping into Vault CLI.

Idempotency: refuses to overwrite existing keys without `--force`. Exit code 0 on success, 2 on conflict.

### Layer C: Service Discovery

Compose: services reference each other by service name (`postgres`, `redis`, `runtime`). Runtime gRPC port becomes `expose:` not `ports:` (internal-only, matches source comment).

Kubernetes: `base/runtime-service.yaml` becomes `ClusterIP` only; `NetworkPolicy` restricts ingress to the `api-server` pod label. (Already partially in place — verify.)

---

## 5. SecretProvider Abstraction (forward-looking)

Trait `SecretProvider` with impls: `Env`, `LocalGenerated(.env.generated)`, `Vault`, `AwsSecretsManager`, `Kubernetes`. Selection via `IDAAS_SECRET_PROVIDER`. **Phase 4+** — out of scope for first cut; `Env` + `LocalGenerated` ship now.

---

## 6. ConfigDoctor (`idaas doctor`)

Prints a table:

```
[OK]   DATABASE_URL                postgres://idaas_user:****@postgres:5432/idaas
[OK]   RUNTIME_GRPC_ADDR           http://runtime:50061  (reachable)
[WARN] LDAP_ENCRYPTION_KEY         not set — falls back to FACTOR_ENCRYPTION_KEY
[FAIL] JWT_PRIVATE_KEY             missing (required in production)
[SKIP] STRIPE_SECRET_KEY           billing disabled
```

All values redacted to last-4 chars. Exit code = number of `[FAIL]` rows.

---

## 7. Lazy Optional Protocols

Convert these from startup-required to runtime-checked:

- **SCIM** — already token-gated; verify endpoints return 503 when `SCIM_BEARER_TOKEN` unset.
- **LDAP** — `LDAP_*` missing ⇒ scheduler does not spawn (currently logs warning — keep).
- **SAML** — IdP missing ⇒ `/auth/saml/*` returns 404.
- **OAuth DCR** — `OAUTH_DCR_INITIAL_ACCESS_TOKEN` missing ⇒ `/oauth/register` returns 403 (already implemented — verify).
- **Stripe** — keys missing ⇒ billing endpoints return 501.
- **Email** — SMTP missing ⇒ verification emails skipped, log warning, do not crash.

---

## 8. Migration / Rollout

| Phase | Scope | Risk | Reversible | Status |
|---|---|---|---|---|
| 1 | Compose wiring fix | low | yes | ✅ shipped |
| 2 | Profile defaults in `config.rs` | low | yes | ✅ shipped |
| 3 | `idaas bootstrap` subcommand | low (additive) | yes | ✅ shipped |
| 4 | `idaas doctor` subcommand | low (additive) | yes | ✅ shipped |
| 5 | `SecretProvider` preload chain | low (additive) | yes | ✅ shipped |
| 6 | Lazy protocol gates (Stripe 501, audit) | medium | yes | ✅ shipped |
| 7 | Docs + env example refresh | none | yes | ✅ shipped |

No DB migrations. No breaking API changes. All env vars retain prior names.

---

## 9. Testing Strategy

- Unit: `Config::apply_profile_defaults` per-profile snapshot tests.
- Integration: `idaas bootstrap --profile local --out /tmp/x` then load via `Config::from_env_file`.
- E2E: clean-checkout `docker compose up` boot test in CI; assert `/health` returns 200 within 60 s.
- Negative: `APP_ENV=production` without keys must still hard-fail (regression guard).

---

## 10. Open Questions

1. New subcommand binary or flag on `api_server`? → **Decision:** flag on `api_server` (`api_server bootstrap …`) to avoid new crate.
2. `.env.generated` precedence vs `.env`? → **Decision:** `.env.generated` loaded *before* `.env` so user `.env` can override.
3. Do we ship a generated `JWT_PUBLIC_KEY` env or a JWKS endpoint? → both; JWKS already exists, env is for convenience.
