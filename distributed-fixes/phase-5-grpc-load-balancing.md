# Phase 5: gRPC Load Balancing

**Duration:** Week 5-6  
**Priority:** P1 (High)  
**Dependencies:** Phase 1 (Redis HA)

---

## Problem Statement

### GAP-8: gRPC Not Horizontally Scalable

**Current State:**
```rust
// Single gRPC endpoint hardcoded
let runtime_client = RuntimeClient::connect("http://127.0.0.1:50061").await?;
```

**Impact:**
- Runtime service is a bottleneck (single instance)
- Cannot scale capsule execution horizontally
- No failover if runtime service crashes
- High latency under load

**Risk Level:** **HIGH** - Performance bottleneck

---

## Target Architecture

### Client-Side Load Balancing

```
API Replicas                Runtime Service Replicas
┌──────────┐               ┌──────────────┐
│  API-1   │──┐            │  Runtime-1   │
└──────────┘  │            └──────────────┘
              │                    ▲
┌──────────┐  │                    │
│  API-2   │──┼────Round Robin─────┤
└──────────┘  │                    │
              │                    ▼
┌──────────┐  │            ┌──────────────┐
│  API-3   │──┘            │  Runtime-2   │
└──────────┘               └──────────────┘
                                   ▲
                                   │
                           ┌──────────────┐
                           │  Runtime-3   │
                           └──────────────┘

Features:
- Client-side load balancing (no proxy overhead)
- Health checks with circuit breaker
- Automatic failover
- Connection pooling
```

---

## Implementation (2 weeks)

### Step 1: Service Discovery via DNS

**Kubernetes Service:**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: runtime-service
  namespace: idaas-platform
spec:
  clusterIP: None  # Headless service for DNS-based discovery
  selector:
    app: runtime
  ports:
  - port: 50061
    name: grpc
```

### Step 2: Update Runtime Client

**File:** `backend/crates/api_server/src/clients/runtime_client.rs`

```rust
use tonic::transport::{Channel, Endpoint};
use tower::discover::Change;
use std::sync::Arc;

pub struct LoadBalancedRuntimeClient {
    channel: Channel,
    endpoints: Vec<String>,
}

impl LoadBalancedRuntimeClient {
    pub async fn new(endpoints: Vec<String>) -> Result<Self> {
        let channel = Self::create_channel(&endpoints).await?;
        
        Ok(Self {
            channel,
            endpoints,
        })
    }
    
    async fn create_channel(endpoints: &[String]) -> Result<Channel> {
        let endpoints: Vec<Endpoint> = endpoints
            .iter()
            .map(|addr| {
                Endpoint::from_shared(addr.clone())
                    .unwrap()
                    .timeout(Duration::from_secs(10))
                    .connect_timeout(Duration::from_secs(5))
                    .tcp_keepalive(Some(Duration::from_secs(60)))
            })
            .collect();
        
        let channel = Channel::balance_list(endpoints.into_iter());
        
        Ok(channel)
    }
    
    pub fn client(&self) -> RuntimeServiceClient<Channel> {
        RuntimeServiceClient::new(self.channel.clone())
    }
}
```

---

## Success Criteria

- [ ] 3+ runtime replicas running
- [ ] Requests distributed evenly
- [ ] Failover < 5s
- [ ] Load tests pass

---

## Next Phase

Proceed to [Phase 6: Background Task Coordination](./phase-6-leader-election.md).
