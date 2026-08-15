# AuthStar SDK Integration Tests

End-to-end tests that exercise every AI Agent Auth & AuthZ feature through the
actual published SDKs against a running AuthStar backend.

## What is tested

| Feature | Python | Go | TypeScript |
|---|---|---|---|
| Register agent | ✅ | ✅ | ✅ |
| Issue agent token | ✅ | ✅ | ✅ |
| Authorize tool call (allow) | ✅ | ✅ | ✅ |
| Authorize tool call (deny → AgentAuthzDenied) | ✅ | ✅ | ✅ |
| `hashToolArgs` / `HashToolArgs` | ✅ | ✅ | ✅ |
| Record execution | ✅ | ✅ | ✅ |
| Get task chain (cursor pagination) | ✅ | ✅ | ✅ |
| Get agent history | ✅ | ✅ | ✅ |
| Deactivate agent | ✅ | ✅ | — |
| Revoke tokens (Redis blocklist) | ✅ | ✅ | — |
| Delegation depth guard | ✅ | ✅ | — |
| Webhook CRUD | — | — | ✅ |

## Prerequisites

- AuthStar backend running on `http://localhost:3000`
- PostgreSQL + Redis reachable by the backend
- `python3`, `pip`, `go`, `node`, `npm` installed
- Bootstrap admin credentials in `IDAAS_BOOTSTRAP_PASSWORD` env var
  (defaults to `Admin@1234!DevOnly`)

## Run all suites

```bash
cd tests/integration
./run.sh
```

Or run individual suites:

```bash
# Python
cd tests/integration/python
pip install -e ../../../sdks/python requests pytest
pytest -v test_agent_authz.py

# Go
cd tests/integration/go
go test -v ./...

# TypeScript
cd tests/integration/ts
npm install
npm test
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `AUTHSTAR_BASE_URL` | `http://localhost:3000` | Backend API base URL |
| `IDAAS_BOOTSTRAP_PASSWORD` | `Admin@1234!DevOnly` | Bootstrap admin password |
| `ADMIN_EMAIL` | `admin@example.com` | Bootstrap admin email |
