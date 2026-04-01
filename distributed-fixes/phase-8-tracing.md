# Phase 8: End-to-End Tracing

**Duration:** Week 8-9  
**Priority:** P2 (Medium)  
**Dependencies:** None

---

## Problem Statement

### GAP-5: No End-to-End Tracing

**Current State:**
- Cannot correlate frontend → API → gRPC → DB
- Debugging distributed issues is difficult
- No visibility into request flow

**Risk Level:** **MEDIUM** - Observability gap

---

## Target Architecture

### W3C TraceContext Propagation

```
Frontend                API Server              Runtime Service
   │                        │                         │
   │  traceparent header    │                         │
   ├───────────────────────>│                         │
   │                        │  traceparent header     │
   │                        ├────────────────────────>│
   │                        │                         │
   │                        │<────────────────────────┤
   │<───────────────────────┤                         │
   │                        │                         │

All spans linked by trace_id
```

---

## Implementation

### OpenTelemetry Integration

```rust
use opentelemetry::trace::TraceContextExt;
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub async fn trace_middleware(
    req: Request,
    next: Next,
) -> Response {
    let trace_id = req.headers()
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .map(|s| extract_trace_id(s));
    
    let span = tracing::info_span!(
        "http_request",
        trace_id = ?trace_id,
        method = %req.method(),
        path = %req.uri().path(),
    );
    
    next.run(req).instrument(span).await
}
```

---

## Success Criteria

- [ ] Traces visible in Jaeger/Tempo
- [ ] Can trace request across all services
- [ ] Latency breakdown available

---

## Next Phase

Proceed to [Phase 9: Integration Testing](./phase-9-testing.md).
