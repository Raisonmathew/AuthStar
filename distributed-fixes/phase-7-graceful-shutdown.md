# Phase 7: Graceful Shutdown & Health Checks

**Duration:** Week 7-8  
**Priority:** P1 (High)  
**Dependencies:** None

---

## Problem Statement

### No Graceful Shutdown

**Current State:**
- SIGTERM kills process immediately
- In-flight requests aborted (502 errors)
- Audit records lost
- No connection draining

**Risk Level:** **HIGH** - User-facing errors during deployments

---

## Target Architecture

### Graceful Shutdown Flow

```
1. Receive SIGTERM
2. Stop accepting new requests (health check fails)
3. Wait for in-flight requests (max 30s)
4. Flush audit buffer
5. Close connections
6. Exit
```

---

## Implementation

```rust
pub async fn graceful_shutdown(
    server: axum::Server,
    state: AppState,
) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };
    
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    
    tracing::info!("Shutdown signal received, starting graceful shutdown");
    
    // Mark unhealthy
    state.health.set_shutting_down();
    
    // Wait for in-flight requests
    tokio::time::sleep(Duration::from_secs(5)).await;
    
    // Flush audit buffer
    state.audit_writer.flush().await;
    
    tracing::info!("Graceful shutdown complete");
}
```

---

## Success Criteria

- [ ] Zero 502 errors during rolling updates
- [ ] All audit records flushed
- [ ] Shutdown completes in < 30s

---

## Next Phase

Proceed to [Phase 8: End-to-End Tracing](./phase-8-tracing.md).
