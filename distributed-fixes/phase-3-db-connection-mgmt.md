# Phase 3: Database Connection Management

**Duration:** Week 3-4  
**Priority:** P0 (Critical)  
**Dependencies:** Phase 1 (Redis HA)

---

## Problem Statement

### GAP-3: Database Connection Pool Exhaustion

**Current State:**
```rust
// Each API replica creates its own connection pool
let pool = PgPoolOptions::new()
    .max_connections(10)  // ← Per replica
    .connect(&database_url).await?;

// With 5 replicas: 5 × 10 = 50 connections
// With 20 replicas: 20 × 10 = 200 connections (exceeds PostgreSQL max_connections)
```

**Impact:**
- Cannot scale beyond 5-10 replicas without hitting PostgreSQL connection limits
- Connection exhaustion causes cascading failures
- No connection pooling across replicas
- Inefficient resource utilization (idle connections)

**Risk Level:** **CRITICAL** - Blocks horizontal scaling

---

## Target Architecture

### PgBouncer Connection Pooler

```
┌─────────────────────────────────────────────────────────────┐
│  Application Layer (20+ replicas)                           │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  API-1    API-2    API-3    ...    API-20                   │
│  (10 conns)(10 conns)(10 conns)    (10 conns)               │
│     │        │        │                │                     │
│     └────────┼────────┼────────────────┘                     │
│              │        │                                      │
│              ▼        ▼                                      │
│         ┌────────────────────┐                               │
│         │    PgBouncer       │  Transaction pooling          │
│         │  (Connection Pool) │  200 client → 20 server conns │
│         └─────────┬──────────┘                               │
│                   │                                          │
│                   ▼                                          │
│         ┌────────────────────┐                               │
│         │   PostgreSQL       │  max_connections = 100        │
│         │   (20 active conns)│  Plenty of headroom           │
│         └────────────────────┘                               │
│                                                               │
└─────────────────────────────────────────────────────────────┘

Benefits:
- 10:1 connection multiplexing ratio
- Scale to 100+ replicas without DB changes
- Connection reuse reduces latency
- Automatic connection recovery
```

---

## Implementation Steps

### Step 1: Deploy PgBouncer (2 days)

#### Docker Compose (Development)

**File:** `infrastructure/docker-compose/pgbouncer.yml`

```yaml
version: '3.8'

services:
  pgbouncer:
    image: edoburu/pgbouncer:1.21.0
    container_name: idaas-pgbouncer
    environment:
      DATABASE_URL: "postgres://idaas_user:password@postgres:5432/idaas"
      POOL_MODE: transaction
      MAX_CLIENT_CONN: 1000
      DEFAULT_POOL_SIZE: 20
      MIN_POOL_SIZE: 5
      RESERVE_POOL_SIZE: 5
      RESERVE_POOL_TIMEOUT: 3
      MAX_DB_CONNECTIONS: 50
      SERVER_IDLE_TIMEOUT: 600
      SERVER_LIFETIME: 3600
    ports:
      - "6432:5432"
    depends_on:
      - postgres
    networks:
      - idaas-network
    healthcheck:
      test: ["CMD", "pg_isready", "-h", "localhost", "-p", "5432"]
      interval: 10s
      timeout: 5s
      retries: 5

networks:
  idaas-network:
    external: true
```

#### Kubernetes (Production)

**File:** `infrastructure/kubernetes/base/pgbouncer-deployment.yaml`

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: pgbouncer-config
  namespace: idaas-platform
data:
  pgbouncer.ini: |
    [databases]
    idaas = host=postgres-service port=5432 dbname=idaas
    
    [pgbouncer]
    listen_addr = 0.0.0.0
    listen_port = 5432
    auth_type = md5
    auth_file = /etc/pgbouncer/userlist.txt
    
    pool_mode = transaction
    max_client_conn = 10000
    default_pool_size = 50
    min_pool_size = 10
    reserve_pool_size = 10
    reserve_pool_timeout = 3
    max_db_connections = 100
    
    server_idle_timeout = 600
    server_lifetime = 3600
    server_connect_timeout = 15
    query_timeout = 30
    
    log_connections = 1
    log_disconnections = 1
    log_pooler_errors = 1
    
  userlist.txt: |
    "idaas_user" "md5<password_hash>"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pgbouncer
  namespace: idaas-platform
spec:
  replicas: 2  # HA setup
  selector:
    matchLabels:
      app: pgbouncer
  template:
    metadata:
      labels:
        app: pgbouncer
    spec:
      containers:
      - name: pgbouncer
        image: edoburu/pgbouncer:1.21.0
        ports:
        - containerPort: 5432
          name: postgres
        volumeMounts:
        - name: config
          mountPath: /etc/pgbouncer
        resources:
          requests:
            memory: "256Mi"
            cpu: "200m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          tcpSocket:
            port: 5432
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          exec:
            command:
            - /bin/sh
            - -c
            - psql -h localhost -U idaas_user -d pgbouncer -c "SHOW POOLS" > /dev/null
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: pgbouncer-config
---
apiVersion: v1
kind: Service
metadata:
  name: pgbouncer-service
  namespace: idaas-platform
spec:
  selector:
    app: pgbouncer
  ports:
  - port: 5432
    targetPort: 5432
  type: ClusterIP
```

### Step 2: Update Database Configuration (1 day)

**File:** `backend/crates/api_server/src/config.rs`

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub max_lifetime_seconds: u64,
    
    /// Use PgBouncer transaction pooling
    pub use_pgbouncer: bool,
}

impl DatabaseConfig {
    pub fn from_env() -> Result<Self> {
        let use_pgbouncer = env::var("USE_PGBOUNCER")
            .unwrap_or("false".into())
            .parse()?;
        
        let url = if use_pgbouncer {
            env::var("PGBOUNCER_URL")?
        } else {
            env::var("DATABASE_URL")?
        };
        
        Ok(Self {
            url,
            max_connections: env::var("DB_MAX_CONNECTIONS")
                .unwrap_or("10".into())
                .parse()?,
            min_connections: env::var("DB_MIN_CONNECTIONS")
                .unwrap_or("2".into())
                .parse()?,
            acquire_timeout_seconds: env::var("DB_ACQUIRE_TIMEOUT_SECONDS")
                .unwrap_or("30".into())
                .parse()?,
            idle_timeout_seconds: env::var("DB_IDLE_TIMEOUT_SECONDS")
                .unwrap_or("600".into())
                .parse()?,
            max_lifetime_seconds: env::var("DB_MAX_LIFETIME_SECONDS")
                .unwrap_or("1800".into())
                .parse()?,
            use_pgbouncer,
        })
    }
    
    pub fn validate(&self) -> Result<()> {
        if self.use_pgbouncer {
            // With PgBouncer, we can use more connections per replica
            if self.max_connections < 5 {
                tracing::warn!("DB_MAX_CONNECTIONS < 5 with PgBouncer - consider increasing");
            }
        } else {
            // Without PgBouncer, limit connections to avoid exhaustion
            if self.max_connections > 20 {
                return Err(anyhow!(
                    "DB_MAX_CONNECTIONS > 20 without PgBouncer risks connection exhaustion"
                ));
            }
        }
        Ok(())
    }
}
```

### Step 3: Update Connection Pool Setup (1 day)

**File:** `backend/crates/api_server/src/bootstrap.rs`

```rust
pub async fn create_database_pool(config: &DatabaseConfig) -> Result<PgPool> {
    config.validate()?;
    
    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(Duration::from_secs(config.acquire_timeout_seconds))
        .idle_timeout(Duration::from_secs(config.idle_timeout_seconds))
        .max_lifetime(Duration::from_secs(config.max_lifetime_seconds))
        // PgBouncer-specific optimizations
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                if config.use_pgbouncer {
                    // Disable prepared statements (not supported in transaction mode)
                    sqlx::query("SET statement_timeout = '30s'")
                        .execute(&mut *conn)
                        .await?;
                }
                Ok(())
            })
        })
        .connect(&config.url)
        .await?;
    
    tracing::info!(
        max_connections = config.max_connections,
        use_pgbouncer = config.use_pgbouncer,
        "Database connection pool created"
    );
    
    Ok(pool)
}
```

### Step 4: Add Connection Pool Monitoring (2 days)

**New File:** `backend/crates/api_server/src/middleware/db_metrics.rs`

```rust
use axum::{extract::State, middleware::Next, response::Response};
use prometheus::{IntGauge, Histogram, register_int_gauge, register_histogram};
use sqlx::PgPool;

lazy_static! {
    static ref DB_POOL_SIZE: IntGauge = register_int_gauge!(
        "db_pool_size",
        "Current database connection pool size"
    ).unwrap();
    
    static ref DB_POOL_IDLE: IntGauge = register_int_gauge!(
        "db_pool_idle_connections",
        "Number of idle connections in pool"
    ).unwrap();
    
    static ref DB_POOL_UTILIZATION: IntGauge = register_int_gauge!(
        "db_pool_utilization_pct",
        "Database pool utilization percentage"
    ).unwrap();
    
    static ref DB_ACQUIRE_DURATION: Histogram = register_histogram!(
        "db_connection_acquire_duration_seconds",
        "Time to acquire connection from pool"
    ).unwrap();
}

pub async fn track_db_metrics(
    State(pool): State<PgPool>,
    req: Request,
    next: Next,
) -> Response {
    // Update pool metrics
    let size = pool.size();
    let idle = pool.num_idle();
    let utilization = ((size - idle) as f64 / size as f64 * 100.0) as i64;
    
    DB_POOL_SIZE.set(size as i64);
    DB_POOL_IDLE.set(idle as i64);
    DB_POOL_UTILIZATION.set(utilization);
    
    // Track acquisition time
    let timer = DB_ACQUIRE_DURATION.start_timer();
    let _conn = pool.acquire().await;
    timer.observe_duration();
    
    next.run(req).await
}
```

### Step 5: Add PgBouncer Health Checks (1 day)

**New File:** `backend/crates/api_server/src/health/pgbouncer.rs`

```rust
use sqlx::PgPool;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PgBouncerStats {
    pub database: String,
    pub total_requests: i64,
    pub total_received: i64,
    pub total_sent: i64,
    pub total_query_time: i64,
    pub avg_req_per_sec: f64,
    pub avg_recv_per_sec: f64,
    pub avg_sent_per_sec: f64,
}

pub async fn check_pgbouncer_health(pool: &PgPool) -> Result<Vec<PgBouncerStats>> {
    let stats = sqlx::query_as!(
        PgBouncerStats,
        r#"
        SELECT 
            database,
            total_requests,
            total_received,
            total_sent,
            total_query_time,
            avg_req as avg_req_per_sec,
            avg_recv as avg_recv_per_sec,
            avg_sent as avg_sent_per_sec
        FROM pgbouncer.stats
        "#
    )
    .fetch_all(pool)
    .await?;
    
    Ok(stats)
}

pub async fn check_pool_health(pool: &PgPool) -> Result<PoolHealth> {
    let pools = sqlx::query!(
        r#"
        SELECT 
            database,
            user,
            cl_active,
            cl_waiting,
            sv_active,
            sv_idle,
            sv_used,
            sv_tested,
            sv_login,
            maxwait
        FROM pgbouncer.pools
        WHERE database = 'idaas'
        "#
    )
    .fetch_one(pool)
    .await?;
    
    Ok(PoolHealth {
        client_active: pools.cl_active.unwrap_or(0),
        client_waiting: pools.cl_waiting.unwrap_or(0),
        server_active: pools.sv_active.unwrap_or(0),
        server_idle: pools.sv_idle.unwrap_or(0),
        max_wait_seconds: pools.maxwait.unwrap_or(0),
    })
}
```

---

## Testing & Validation

### Test 1: Connection Pool Scaling

```bash
# Start with 5 replicas
kubectl scale deployment/backend --replicas=5 -n idaas-platform

# Monitor connections
watch -n 1 'psql -h pgbouncer -c "SHOW POOLS"'

# Scale to 20 replicas
kubectl scale deployment/backend --replicas=20 -n idaas-platform

# Expected:
# - Client connections: 200 (20 × 10)
# - Server connections: 50 (pooled)
# - No connection errors
# - Latency unchanged
```

### Test 2: Connection Exhaustion Prevention

```bash
# Simulate connection leak
for i in {1..1000}; do
  curl http://localhost:3000/api/v1/health &
done

# Monitor PgBouncer
psql -h pgbouncer -c "SHOW POOLS"

# Expected:
# - Client connections queue up
# - Server connections stay at max_pool_size
# - No PostgreSQL connection errors
# - Requests complete (may be slower)
```

### Test 3: Failover Behavior

```bash
# Kill PgBouncer pod
kubectl delete pod -l app=pgbouncer -n idaas-platform

# Expected:
# - Kubernetes restarts PgBouncer (< 10s)
# - Applications reconnect automatically
# - Brief spike in connection acquire time
# - No data loss
```

### Test 4: Load Test

```bash
# 10k requests/sec for 5 minutes
k6 run --vus 500 --duration 5m tests/db-load-test.js

# Monitor metrics:
# - db_pool_utilization_pct < 80%
# - db_connection_acquire_duration_seconds p99 < 100ms
# - Zero connection timeout errors
```

---

## Monitoring & Alerts

### Grafana Dashboard

```yaml
# Key metrics
- db_pool_size
- db_pool_idle_connections
- db_pool_utilization_pct
- db_connection_acquire_duration_seconds
- pgbouncer_client_connections
- pgbouncer_server_connections
- pgbouncer_max_wait_seconds
```

### Alert Rules

```yaml
# Critical: Pool exhaustion
- alert: DatabasePoolExhausted
  expr: db_pool_utilization_pct > 95
  for: 2m
  severity: critical
  
# Warning: Slow connection acquisition
- alert: SlowDatabaseConnectionAcquisition
  expr: histogram_quantile(0.99, db_connection_acquire_duration_seconds) > 1
  for: 5m
  severity: warning
  
# Warning: PgBouncer queue building
- alert: PgBouncerQueueBuilding
  expr: pgbouncer_client_waiting > 50
  for: 2m
  severity: warning
```

---

## Rollback Plan

```bash
# Disable PgBouncer
kubectl set env deployment/backend \
  USE_PGBOUNCER=false \
  DATABASE_URL=postgres://postgres-service:5432/idaas \
  -n idaas-platform

# Scale down replicas if needed
kubectl scale deployment/backend --replicas=5 -n idaas-platform
```

---

## Success Criteria

- [ ] PgBouncer deployed in HA mode (2 replicas)
- [ ] Scale to 20+ API replicas without connection errors
- [ ] Connection pool utilization < 80% under normal load
- [ ] Connection acquire time p99 < 100ms
- [ ] Zero connection timeout errors in load tests
- [ ] Monitoring dashboards operational
- [ ] Production deployment successful

---

## Next Phase

Once Phase 3 is complete and validated, proceed to [Phase 4: Audit System Resilience](./phase-4-audit-resilience.md).