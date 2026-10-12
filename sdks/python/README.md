# authstar

Official Python SDK for the **AuthStar** AI Agent Authorization platform — enabling fine-grained, auditable authorization for agentic AI workloads.

[![PyPI version](https://img.shields.io/pypi/v/authstar.svg)](https://pypi.org/project/authstar/)
[![Python versions](https://img.shields.io/pypi/pyversions/authstar.svg)](https://pypi.org/project/authstar/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Installation

```bash
pip install authstar
```

With LangChain integration:

```bash
pip install "authstar[langchain]"
```

## Quick Start

```python
from authstar import AuthstarClient

client = AuthstarClient(
    base_url="https://api.authstar.io",
    api_key="ask_your_key_here",
    tenant_id="your-tenant-id",
)

# Check if an agent action is allowed
decision = client.authorize(
    action="agent:read_customer_data",
    subject="agent-abc123",
    context={"task_id": "task-xyz", "resource": "customers"},
)

if decision.allowed:
    print(f"Authorized ✓  ref={decision.decision_ref}")
else:
    print(f"Denied ✗  reason={decision.reason}")
```

## API Reference

### `AuthstarClient`

```python
AuthstarClient(
    base_url: str,          # e.g. "https://api.authstar.io"
    api_key: str,           # Bearer token starting with "ask_..."
    tenant_id: str,         # Your tenant/organization UUID
    timeout: float = 10.0,  # HTTP timeout in seconds
)
```

#### `client.authorize(action, subject, context={})`

Evaluates whether `subject` is permitted to perform `action`.

Returns an `AuthzDecision` with fields:
| Field | Type | Description |
|---|---|---|
| `allowed` | `bool` | Whether the action is permitted |
| `decision_ref` | `str` | Unique reference for this decision (use with `verify_decision`) |
| `attestation_sig` | `str \| None` | Ed25519/ES256 attestation signature (base64) |
| `reason` | `str \| None` | Human-readable reason for the decision |

#### `client.revoke(agent_id)`

Immediately invalidates all active tokens for the given agent by writing a Redis blocklist entry. Returns `None` on success; raises `AuthstarError` on failure.

#### `client.get_task_chain(task_id, cursor=None, limit=50)`

Returns a paginated `TaskChainPage` of all EIAA execution records for a task:
| Field | Type | Description |
|---|---|---|
| `items` | `list[TaskChainItem]` | Execution records, oldest-first |
| `next_cursor` | `str \| None` | ISO-8601 timestamp cursor for the next page |

#### `client.verify_decision(decision_ref)`

Re-executes a stored decision and compares it to the original:
| Field | Type | Description |
|---|---|---|
| `verified` | `bool` | True when original and replayed decisions match |
| `original_decision` | `bool` | The original allow/deny outcome |
| `replayed_decision` | `bool` | The replayed allow/deny outcome |
| `decisions_match` | `bool` | Whether they are equal |
| `status` | `str` | `"verified"`, `"discrepancy"`, `"capsule_not_found"`, or `"execution_error"` |

#### `client.health()`

Returns a `HealthStatus` with fields `ok`, `latency_ms`, and `version`.

### Doctor CLI

```bash
authstar doctor --url https://api.authstar.io --api-key ask_... --tenant-id <id>
```

Checks connectivity, liveness, readiness, and prints the authenticated user's email with latency for each check.

## Framework Integrations

Examples are in [`examples/`](examples/):

| File | Framework |
|---|---|
| [`langchain_tool.py`](examples/langchain_tool.py) | LangChain `BaseTool` |
| [`crewai_agent.py`](examples/crewai_agent.py) | CrewAI tool |
| [`openai_agents.py`](examples/openai_agents.py) | OpenAI Agents SDK function tool |

## License

MIT
