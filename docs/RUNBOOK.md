# AuthStar IDaaS — Operations Runbook

> **Audience:** On-call engineers, SRE, platform operators  
> **Last Updated:** See git history  
> **Emergency Contact:** See your organization's incident response page

---

## Table of Contents

1. [Key Rotation Procedures](#1-key-rotation-procedures)
2. [EIAA Runtime Service Failure](#2-eiaa-runtime-service-failure)
3. [Audit Writer Backpressure Response](#3-audit-writer-backpressure-response)
4. [Redis Sentinel Failover](#4-redis-sentinel-failover)
5. [Database Emergency Restore (PITR)](#5-database-emergency-restore-pitr)
6. [Compromised Tenant Isolation](#6-compromised-tenant-isolation)
7. [Rate Limit Tuning Guide](#7-rate-limit-tuning-guide)
8. [Migration Rollback Procedure](#8-migration-rollback-procedure)
9. [Health Check Reference](#9-health-check-reference)
10. [Prometheus Alert Reference](#10-prometheus-alert-reference)

---

## 1. Key Rotation Procedures

### 1.1 JWT Signing Key (ES256 — `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY`)

**Impact:** Rotating the JWT key invalidates all in-flight access tokens (60–900s TTL). Users are transparently re-authenticated on their next request via the silent refresh path (httpOnly `refresh_token` cookie). **No user action required.**

**Procedure:**

```bash
# 1. Generate new ES256 keypair
openssl ecparam -genkey -name prime256v1 -noout -out new_jwt_private.pem
openssl ec -in new_jwt_private.pem -pubout -out new_jwt_public.pem

# 2. Update AWS Secrets Manager
aws secretsmanager update-secret \
  --secret-id idaas/production/backend \
  --secret-string "$(
    aws secretsmanager get-secret-value --secret-id idaas/production/backend \
      --query SecretString --output text | \
    jq --rawfile priv new_jwt_private.pem --rawfile pub new_jwt_public.pem \
       '.jwt_private_key = $priv | .jwt_public_key = $pub'
  )"

# 3. Force ExternalSecret refresh (or wait up to 1h for auto-refresh)
kubectl annotate externalsecret backend-secrets \
  --namespace idaas-platform \
  force-sync=$(date +%s) --overwrite

# 4. Rolling restart (picks up new Secret automatically)
kubectl rollout restart deployment/backend -n idaas-platform
kubectl rollout status deployment/backend -n idaas-platform --timeout=5m
```

**Verification:** `curl -s https://api.example.com/health/ready` should return `200 Ready` after all pods restart.

---

### 1.2 EIAA Capsule Compiler Key (`COMPILER_SK_B64`)

**Impact:** Rotating this key **does not invalidate existing sessions**. It means newly compiled capsules will be signed with the new key. Capsules already in Redis and the database retain the old signature and are still valid (the verifier maintains a key cache with 5-minute TTL — old keys remain trusted for that window).

**⚠️ Warning:** Do not rotate this key without ensuring the new key is present in `signing_keys` (migration 061). The `RuntimeKeyCache` fetches verification keys from there.

```bash
# 1. Generate new Ed25519 key
openssl genpkey -algorithm ed25519 | openssl pkey -outform DER | \
  base64 | tr '+/' '-_' | tr -d '=' > new_compiler_sk_b64.txt

# 2. Insert new public key into signing_keys table BEFORE updating the secret
#    (so the verifier can check new-key attestations immediately)
NEW_SK=$(cat new_compiler_sk_b64.txt)
# The bootstrap CLI can do this:
cargo run -p api_server --bin api_server -- \
  rotate-compiler-key --new-sk "$NEW_SK"

# 3. Update AWS Secrets Manager
aws secretsmanager update-secret ...  # same pattern as 1.1

# 4. Rolling restart
kubectl rollout restart deployment/backend -n idaas-platform
```

---

### 1.3 Encryption Keys (FACTOR / OAUTH_TOKEN / SSO / LDAP)

**⚠️ CAUTION:** These keys protect secrets at rest. Rotating them requires re-encrypting all affected data before the old key is removed. Never remove the old key without completing re-encryption.

```bash
# DO NOT rotate in-place without a migration plan.
# Procedure:
# 1. Add new key as FACTOR_ENCRYPTION_KEY_NEW
# 2. Write a one-time migration script that decrypts with old key, re-encrypts with new key
# 3. Run migration script against a staging copy first
# 4. Run in production during a maintenance window
# 5. Swap env vars (old → new key becomes FACTOR_ENCRYPTION_KEY)
# 6. Remove FACTOR_ENCRYPTION_KEY_NEW
```

---

## 2. EIAA Runtime Service Failure

The EIAA runtime service (`runtime`) executes WASM capsules via gRPC. When it is down, the circuit breaker in `SharedRuntimeClient` opens after 5 consecutive failures (30s recovery window).

**Symptoms:**
- Prometheus alert: `eiaa_circuit_breaker_open` fired
- API returns `403 Forbidden` on all protected routes
- Logs show: `circuit breaker open — rejecting gRPC call`

**Immediate Response:**

```bash
# Check runtime pod status
kubectl get pods -n idaas-platform -l app=runtime

# Check runtime logs
kubectl logs -n idaas-platform -l app=runtime --tail=100

# Check gRPC health
kubectl exec -n idaas-platform deploy/backend -- \
  grpc_health_probe -addr=runtime:50061

# Force restart if pods are in CrashLoopBackOff
kubectl rollout restart deployment/runtime -n idaas-platform
kubectl rollout status deployment/runtime -n idaas-platform --timeout=3m
```

**If runtime cannot recover within 5 minutes:**

The backend is configured `fail_open: false` (all authorization denied until runtime recovers). This is the safe default. Do **not** change `fail_open` to `true` in production — it disables authorization entirely.

Options:
1. Scale up runtime: `kubectl scale deployment/runtime --replicas=5 -n idaas-platform`
2. If WASM capsule is corrupt: re-compile via `POST /api/v1/policy-builder/compile` (requires admin session)
3. Escalate to identity platform team

---

## 3. Audit Writer Backpressure Response

The audit writer buffers EIAA execution records in a 10,000-slot channel. When full, records are dropped — a compliance violation.

**Monitoring:** The `/health/ready` endpoint returns `503` when:
- `audit_writer_channel_fill_pct >= 95%`
- `audit_writer_dropped_total > 0`

Kubernetes stops routing traffic to affected pods automatically.

**Response:**

```bash
# Check current metrics
kubectl exec -n idaas-platform deploy/backend -- \
  curl -s localhost:3000/metrics | grep audit_writer

# Check how many records have been dropped
kubectl exec -n idaas-platform deploy/backend -- \
  curl -s localhost:3000/metrics | grep audit_writer_dropped_total

# If records are being dropped, the disk overflow queue (Sled) should be absorbing them.
# Verify the PVC has space:
kubectl exec -n idaas-platform deploy/backend -- df -h /data/audit_overflow
```

**If the DB is the bottleneck (slow flush):**

```sql
-- Check for blocking queries on eiaa_executions
SELECT pid, query, state, wait_event_type, wait_event, query_start
FROM pg_stat_activity
WHERE query LIKE '%eiaa_executions%'
ORDER BY query_start;

-- Verify index health
ANALYZE eiaa_executions;
```

**Recovery:** Once the DB recovers, the Sled overflow queue is replayed automatically. Check `audit_writer_overflow_replayed_total` metric to confirm.

---

## 4. Redis Sentinel Failover

In production, Redis runs in Sentinel mode (3 nodes required for quorum). Sentinel manages automatic failover when the Redis master becomes unavailable.

**Normal failover (automatic):**
Sentinel detects master failure within 30s (configurable `down-after-milliseconds`). Failover promotes a replica to master and updates all clients. The backend's Redis `ConnectionManager` reconnects automatically.

**Manual verification:**

```bash
# Check Sentinel status
kubectl exec -n idaas-platform deploy/backend -- \
  redis-cli -h redis-sentinel-0.redis-headless -p 26379 sentinel master mymaster

# Check which node is currently master
kubectl exec -n idaas-platform deploy/backend -- \
  redis-cli -h redis-sentinel-0.redis-headless -p 26379 \
  sentinel get-master-addr-by-name mymaster

# Force a manual failover if needed
kubectl exec -n idaas-platform deploy/backend -- \
  redis-cli -h redis-sentinel-0.redis-headless -p 26379 \
  sentinel failover mymaster
```

**If Sentinel quorum is lost (< 2 of 3 nodes available):**
No automatic failover occurs. Sentinel enters a "wait for quorum" state. Restore the missing Sentinel nodes. The backend will continue serving requests using the last known master until reconnect.

---

## 5. Database Emergency Restore (PITR)

**RTO target: < 2 hours. RPO target: < 24 hours (daily backup), < 5 min (WAL archiving if enabled).**

### 5.1 Restore from daily pg_dump backup

```bash
# 1. Find the most recent backup
aws s3 ls s3://<BACKUP_S3_BUCKET>/idaas/production/pg_dumps/ \
  --recursive | sort | tail -5

# 2. Download
aws s3 cp s3://<bucket>/idaas/production/pg_dumps/<timestamp>.dump.gz \
  /tmp/restore.dump.gz

# 3. Decompress
gunzip /tmp/restore.dump.gz

# 4. Restore (WARNING: this overwrites the target database)
pg_restore \
  --clean \
  --if-exists \
  --no-owner \
  --no-privileges \
  --jobs=4 \
  -d "$DATABASE_URL" \
  /tmp/restore.dump

# 5. Verify row counts
psql "$DATABASE_URL" -c "SELECT COUNT(*) FROM users;"
psql "$DATABASE_URL" -c "SELECT COUNT(*) FROM eiaa_executions;"

# 6. Re-run any migrations that occurred after the backup timestamp
cargo run --bin migrate

# 7. Rolling restart to clear in-memory caches
kubectl rollout restart deployment/backend -n idaas-platform
```

### 5.2 After restore: invalidate Redis caches

After restoring from backup, capsule cache and session state in Redis may be inconsistent with the restored DB state.

```bash
# Flush Redis (WARNING: this logs out all active users)
kubectl exec -n idaas-platform deploy/backend -- redis-cli FLUSHDB

# Or selectively purge capsule cache keys
kubectl exec -n idaas-platform deploy/backend -- \
  redis-cli --scan --pattern 'capsule:*' | xargs redis-cli DEL
```

---

## 6. Compromised Tenant Isolation

If a tenant's credentials or API keys are suspected compromised:

```bash
# 1. Revoke all active sessions for the tenant
psql "$DATABASE_URL" -c "
  UPDATE sessions
  SET revoked = true, revoked_at = NOW()
  WHERE tenant_id = '<TENANT_ID>'
    AND expires_at > NOW()
    AND revoked = false;
"

# 2. Invalidate all API keys for the tenant
psql "$DATABASE_URL" -c "
  UPDATE api_keys
  SET revoked = true, revoked_at = NOW()
  WHERE tenant_id = '<TENANT_ID>'
    AND revoked = false;
"

# 3. Purge Redis session cache for the tenant
kubectl exec -n idaas-platform deploy/backend -- \
  redis-cli --scan --pattern "session:*:<TENANT_ID>:*" | xargs redis-cli DEL

# 4. If an agent token is compromised, add it to the blocklist:
curl -X POST https://api.example.com/api/v1/agents/<AGENT_ID>/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "X-Organization-Id: <TENANT_ID>"

# 5. Audit all EIAA executions for the tenant in the last 24h
psql "$DATABASE_URL" -c "
  SELECT decision_ref, action, decision, created_at, input_digest
  FROM eiaa_executions
  WHERE tenant_id = '<TENANT_ID>'
    AND created_at > NOW() - INTERVAL '24 hours'
  ORDER BY created_at DESC
  LIMIT 200;
"
```

---

## 7. Rate Limit Tuning Guide

Rate limits are implemented with a Redis sliding window (`governor` crate). Current thresholds:

| Endpoint Group | Limit | Config |
|---|---|---|
| Auth flow init | 10 req/min per IP | `rate_limit_auth_flow` |
| Auth flow submit | 5 req/min per (IP, flow_id) | `rate_limit_auth_flow_submit` |
| Auth identify | 5 req/min per IP | `rate_limit_password_auth` |
| OAuth token | 10 req/min per IP | `rate_limit_oauth_token` |
| General API | 1000 req/min per org | `rate_limit_api` |
| Public endpoints | 30 req/min per IP | `rate_limit_public` |
| SSO endpoints | 20 req/min per IP | `rate_limit_sso` |

**To tune limits without a code change:**

Rate limits are currently compile-time constants in `middleware/rate_limit.rs`. To make them runtime-configurable, add env var overrides — file a ticket to implement `RATE_LIMIT_AUTH_FLOW_PER_MIN` env var support.

**Temporary emergency increase** (during a legitimate traffic spike):

```bash
# Clear rate limit counters for a specific IP (use with caution)
kubectl exec -n idaas-platform deploy/backend -- \
  redis-cli --scan --pattern "rate_limit:*:<IP_ADDRESS>:*" | xargs redis-cli DEL
```

---

## 8. Migration Rollback Procedure

Rollback SQL files are in `backend/crates/db_migrations/migrations/rollback/`.

**⚠️ WARNING:** Never roll back migrations in production without:
1. A complete database backup taken immediately before
2. Confirmation that no application code depends on the rolled-back schema
3. A tested staging dry-run

```bash
# Dry run: show what the rollback SQL would do (psql --echo-all --dry-run equivalent)
psql "$DATABASE_URL" -f backend/crates/db_migrations/migrations/rollback/077_down.sql \
  --single-transaction --set ON_ERROR_STOP=1

# Execute (replace NNN with the migration number to roll back)
psql "$DATABASE_URL" \
  --single-transaction \
  --set ON_ERROR_STOP=1 \
  -f backend/crates/db_migrations/migrations/rollback/NNN_down.sql

# For cascading rollbacks (e.g. rolling back 077, 076, 075 in order):
for n in 077 076 075; do
  psql "$DATABASE_URL" \
    --single-transaction \
    --set ON_ERROR_STOP=1 \
    -f backend/crates/db_migrations/migrations/rollback/${n}_down.sql
  echo "Rolled back migration ${n}"
done
```

---

## 9. Health Check Reference

| Endpoint | Auth | Returns | Used By |
|---|---|---|---|
| `GET /health` | None | `200 OK` | K8s liveness probe |
| `GET /health/ready` | None | `200 Ready` / `503 Not ready: ...` | K8s readiness probe |
| `GET /metrics` | Network-level (Prometheus only) | Prometheus text format | Prometheus scrape |

**Readiness check** fails when any of:
- PostgreSQL `SELECT 1` fails
- Redis `PING` fails
- Audit writer channel ≥ 95% full
- Any audit records have been dropped since startup

---

## 10. Prometheus Alert Reference

| Alert | Condition | Severity | Action |
|---|---|---|---|
| `EiaaCircuitBreakerOpen` | `eiaa_circuit_breaker_state == 1` | Critical | See §2 |
| `AuditWriterDropping` | `increase(audit_writer_dropped_total[5m]) > 0` | Critical | See §3 |
| `AuditWriterChannelNearFull` | `audit_writer_channel_fill_pct > 80` | Warning | See §3 |
| `HighAuthDenyRate` | `rate(eiaa_decisions_total{result="deny"}[5m]) / rate(eiaa_decisions_total[5m]) > 0.2` | Warning | Possible attack; check risk engine logs |
| `BackendPodNotReady` | `kube_pod_status_ready{pod=~"backend-.*"} == 0` for > 2m | Critical | Check pod logs; see §9 |
| `RedisConnectionFailures` | `increase(redis_connection_errors_total[5m]) > 5` | Warning | See §4 |
| `DatabaseSlowQueries` | `pg_stat_activity_max_tx_duration > 30` | Warning | Check §5.1 for blocking queries |
