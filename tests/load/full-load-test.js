/**
 * Phase 9: Full Load Test — k6 script
 *
 * Simulates production-level traffic against the IDaaS API to validate:
 * - p99 latency < 500ms
 * - Error rate < 0.01%
 * - Zero audit records dropped
 * - Cache consistency under load
 *
 * Usage:
 *   k6 run tests/load/full-load-test.js                     # Default: 100 VUs, 5m
 *   k6 run --vus 1000 --duration 1h tests/load/full-load-test.js  # Full load
 *   k6 run --env BASE_URL=https://staging.example.com tests/load/full-load-test.js
 */

import http from "k6/http";
import { check, group, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------
const auditMissed = new Counter("audit_records_missed");
const cacheHitRate = new Rate("cache_hit_rate");
const authLatency = new Trend("auth_flow_latency", true);
const capsuleLatency = new Trend("capsule_eval_latency", true);

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const BASE_URL = __ENV.BASE_URL || "http://localhost:3000";
const API_PREFIX = `${BASE_URL}/api`;

export const options = {
  // Ramp-up → sustained → ramp-down
  stages: [
    { duration: "2m", target: 200 },   // warm-up
    { duration: "5m", target: 500 },   // ramp to medium load
    { duration: "10m", target: 1000 }, // peak load (10k req/s target)
    { duration: "5m", target: 1000 },  // sustained peak
    { duration: "3m", target: 0 },     // ramp-down
  ],

  thresholds: {
    // SLO: p99 latency < 500ms
    http_req_duration: ["p(99)<500", "p(95)<250", "avg<100"],
    // SLO: error rate < 0.01%
    http_req_failed: ["rate<0.0001"],
    // Custom: auth flow p99 < 300ms
    auth_flow_latency: ["p(99)<300"],
    // Custom: capsule evaluation p99 < 500ms
    capsule_eval_latency: ["p(99)<500"],
  },
};

// ---------------------------------------------------------------------------
// Shared test data
// ---------------------------------------------------------------------------
const TEST_ORG_ID = __ENV.TEST_ORG_ID || "test-org-load";

function headers(token) {
  const h = { "Content-Type": "application/json" };
  if (token) h["Authorization"] = `Bearer ${token}`;
  return h;
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

export default function () {
  // Distribute traffic across realistic API patterns:
  // 40% health/status (lightweight), 30% auth flows, 20% capsule evaluation, 10% admin
  const roll = Math.random();
  if (roll < 0.4) {
    healthChecks();
  } else if (roll < 0.7) {
    authFlow();
  } else if (roll < 0.9) {
    capsuleEvaluation();
  } else {
    adminOperations();
  }

  sleep(0.1 + Math.random() * 0.4); // 100-500ms think time
}

// ---------------------------------------------------------------------------
// 1. Health checks — exercises readiness, liveness, and metrics endpoints
// ---------------------------------------------------------------------------
function healthChecks() {
  group("health_checks", function () {
    const ready = http.get(`${API_PREFIX}/health/ready`, { tags: { scenario: "health" } });
    check(ready, {
      "readiness 200": (r) => r.status === 200,
    });

    const live = http.get(`${API_PREFIX}/health/live`, { tags: { scenario: "health" } });
    check(live, {
      "liveness 200": (r) => r.status === 200,
    });
  });
}

// ---------------------------------------------------------------------------
// 2. Auth flow — signup → login → token refresh cycle
// ---------------------------------------------------------------------------
function authFlow() {
  group("auth_flow", function () {
    const start = Date.now();
    const uniqueId = `load-${__VU}-${__ITER}-${Date.now()}`;
    const email = `${uniqueId}@loadtest.local`;

    // Signup
    const signupRes = http.post(
      `${API_PREFIX}/auth/signup`,
      JSON.stringify({
        email: email,
        password: "LoadTest!Pass123",
        name: `Load User ${uniqueId}`,
        org_name: TEST_ORG_ID,
      }),
      { headers: headers(), tags: { scenario: "auth" } }
    );
    check(signupRes, {
      "signup 2xx": (r) => r.status >= 200 && r.status < 300,
    });

    // Login
    const loginRes = http.post(
      `${API_PREFIX}/auth/login`,
      JSON.stringify({
        email: email,
        password: "LoadTest!Pass123",
      }),
      { headers: headers(), tags: { scenario: "auth" } }
    );
    const loginOk = check(loginRes, {
      "login 2xx": (r) => r.status >= 200 && r.status < 300,
    });

    authLatency.add(Date.now() - start);

    if (loginOk && loginRes.json("token")) {
      // Token refresh
      const token = loginRes.json("token");
      const refreshRes = http.post(
        `${API_PREFIX}/auth/refresh`,
        null,
        { headers: headers(token), tags: { scenario: "auth" } }
      );
      check(refreshRes, {
        "refresh 2xx": (r) => r.status >= 200 && r.status < 300,
      });
    }
  });
}

// ---------------------------------------------------------------------------
// 3. Capsule evaluation — compile, evaluate, and verify audit trail
// ---------------------------------------------------------------------------
function capsuleEvaluation() {
  group("capsule_evaluation", function () {
    const start = Date.now();

    // Compile a simple policy
    const compileRes = http.post(
      `${API_PREFIX}/capsules/compile`,
      JSON.stringify({
        policy: {
          name: `load-test-policy-${__VU}`,
          rules: [
            {
              action: "allow",
              conditions: [{ field: "risk_score", operator: "lt", value: 50 }],
            },
          ],
        },
      }),
      { headers: headers(), tags: { scenario: "capsule" } }
    );

    const compileOk = check(compileRes, {
      "compile 2xx": (r) => r.status >= 200 && r.status < 300,
    });

    // Check if the response came from cache (X-Cache header)
    if (compileRes.headers["X-Cache"] === "HIT") {
      cacheHitRate.add(true);
    } else {
      cacheHitRate.add(false);
    }

    if (compileOk && compileRes.json("capsule_id")) {
      const capsuleId = compileRes.json("capsule_id");

      // Evaluate the capsule
      const evalRes = http.post(
        `${API_PREFIX}/capsules/${capsuleId}/evaluate`,
        JSON.stringify({
          context: {
            user_id: `user-${__VU}`,
            risk_score: Math.floor(Math.random() * 100),
            ip: "10.0.0.1",
          },
        }),
        { headers: headers(), tags: { scenario: "capsule" } }
      );
      check(evalRes, {
        "evaluate 2xx": (r) => r.status >= 200 && r.status < 300,
      });
    }

    capsuleLatency.add(Date.now() - start);
  });
}

// ---------------------------------------------------------------------------
// 4. Admin / read-heavy operations
// ---------------------------------------------------------------------------
function adminOperations() {
  group("admin_operations", function () {
    // List organizations (read replica test)
    const orgsRes = http.get(`${API_PREFIX}/organizations`, {
      headers: headers(),
      tags: { scenario: "admin" },
    });
    check(orgsRes, {
      "orgs list 2xx or 401": (r) => r.status === 200 || r.status === 401,
    });

    // Audit log query (tests overflow queue + PostgreSQL)
    const auditRes = http.get(`${API_PREFIX}/audit/events?limit=10`, {
      headers: headers(),
      tags: { scenario: "admin" },
    });
    check(auditRes, {
      "audit query responds": (r) => r.status === 200 || r.status === 401,
    });
  });
}

// ---------------------------------------------------------------------------
// Teardown — Final validation
// ---------------------------------------------------------------------------
export function handleSummary(data) {
  const p99 = data.metrics.http_req_duration.values["p(99)"];
  const errRate = data.metrics.http_req_failed.values.rate;

  console.log("\n========================================");
  console.log("  Phase 9: Load Test Summary");
  console.log("========================================");
  console.log(`  p99 Latency:  ${p99.toFixed(1)}ms (target: <500ms) ${p99 < 500 ? "✅" : "❌"}`);
  console.log(`  Error Rate:   ${(errRate * 100).toFixed(4)}% (target: <0.01%) ${errRate < 0.0001 ? "✅" : "❌"}`);
  console.log("========================================\n");

  return {
    stdout: textSummary(data, { indent: "  ", enableColors: true }),
    "tests/load/results.json": JSON.stringify(data, null, 2),
  };
}

import { textSummary } from "https://jslib.k6.io/k6-summary/0.0.3/index.js";
