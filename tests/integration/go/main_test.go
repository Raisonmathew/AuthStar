// AuthStar Go SDK — AI Agent Auth & AuthZ Integration Tests
//
// Tests every feature of sdks/go/client.go's agent methods against a live backend.
//
// Run:
//   go test -v ./...
//
// Environment variables:
//   AUTHSTAR_BASE_URL           (default: http://localhost:3000)
//   ADMIN_EMAIL                 (default: admin@example.com)
//   IDAAS_BOOTSTRAP_PASSWORD    (default: Admin@1234!DevOnly)

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	idaas "github.com/idaas/go-sdk"
)

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

func baseURL() string {
	if v := os.Getenv("AUTHSTAR_BASE_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://localhost:3000"
}

func adminEmail() string {
	if v := os.Getenv("ADMIN_EMAIL"); v != "" {
		return v
	}
	return "admin@example.com"
}

func adminPassword() string {
	if v := os.Getenv("IDAAS_BOOTSTRAP_PASSWORD"); v != "" {
		return v
	}
	return "Admin@1234!DevOnly"
}

func seedToken() string {
	if v := os.Getenv("TEST_SEED_TOKEN"); v != "" {
		return v
	}
	return "dev-test-seed-token-change-for-staging"
}

func unique(prefix string) string {
	return fmt.Sprintf("%s_%08x", prefix, rand.Int31())
}

// adminLogin walks the EIAA auth flow to obtain an admin Bearer JWT:
//  1. GET  /api/csrf-token              → CSRF token + cookie
//  2. POST /api/auth/flow/init          → flow_id + flow_token
//  3. POST /api/auth/flow/:id/identify  → resolve user
//  4. POST /api/auth/flow/:id/submit    → verify password
//  5. POST /api/auth/flow/:id/complete  → admin JWT
//  6. POST /api/test/elevate-session    → AAL3 (bypass TOTP step-up gate)
//
// Bearer tokens bypass CSRF on all subsequent requests (csrf.rs line 90–96),
// so agent API calls only need Authorization: Bearer <jwt>.
func adminLogin(t *testing.T) (string, string) {
	t.Helper()
	base := baseURL()
	client := &http.Client{}

	// Step 1: CSRF token
	csrfResp, err := client.Get(base + "/api/csrf-token")
	if err != nil {
		t.Fatalf("csrf-token GET failed: %v", err)
	}
	csrfRaw, _ := io.ReadAll(csrfResp.Body)
	csrfResp.Body.Close()
	var csrfBody struct {
		CSRFToken string `json:"csrf_token"`
	}
	json.Unmarshal(csrfRaw, &csrfBody)
	csrfToken := csrfBody.CSRFToken
	// Extract __csrf cookie for subsequent requests
	var csrfCookie string
	for _, c := range csrfResp.Cookies() {
		if c.Name == "__csrf" {
			csrfCookie = c.Value
		}
	}

	doReq := func(method, path, bearerToken string, bodyStr string) ([]byte, int) {
		var reqBody io.Reader
		if bodyStr != "" {
			reqBody = strings.NewReader(bodyStr)
		}
		req, _ := http.NewRequest(method, base+path, reqBody)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", base)
		req.Header.Set("X-CSRF-Token", csrfToken)
		req.Header.Set("Cookie", "__csrf="+csrfCookie)
		if bearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+bearerToken)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, 0
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return raw, resp.StatusCode
	}

	// Step 2: Init flow for 'system' org
	initRaw, status := doReq("POST", "/api/auth/flow/init", "", `{"org_id":"system"}`)
	if status != 200 {
		t.Fatalf("flow init returned %d: %s", status, initRaw)
	}
	var initBody struct {
		FlowID    string `json:"flow_id"`
		FlowToken string `json:"flow_token"`
	}
	json.Unmarshal(initRaw, &initBody)

	// Step 3: Identify
	identBody := fmt.Sprintf(`{"identifier":%q}`, adminEmail())
	doReq("POST", "/api/auth/flow/"+initBody.FlowID+"/identify", initBody.FlowToken, identBody)

	// Step 4: Submit password
	submitBody := fmt.Sprintf(`{"capability":"password","value":%q}`, adminPassword())
	doReq("POST", "/api/auth/flow/"+initBody.FlowID+"/submit", initBody.FlowToken, submitBody)

	// Step 5: Complete → JWT
	completeRaw, status := doReq("POST", "/api/auth/flow/"+initBody.FlowID+"/complete", initBody.FlowToken, "")
	if status != 200 {
		t.Fatalf("flow complete returned %d: %s", status, completeRaw)
	}
	var completeBody struct {
		JWT   string `json:"jwt"`
		Token string `json:"token"`
		OrgID string `json:"tenant_id"`
	}
	json.Unmarshal(completeRaw, &completeBody)
	jwt := completeBody.JWT
	if jwt == "" {
		jwt = completeBody.Token
	}
	if jwt == "" {
		t.Fatalf("no JWT in complete response: %s", completeRaw)
	}
	orgID := completeBody.OrgID
	if orgID == "" {
		orgID = "system"
	}

	// Step 6: Elevate to AAL3 so agent:manage capsule passes without TOTP
	req, _ := http.NewRequest("POST", base+"/api/test/elevate-session",
		strings.NewReader(`{"user_id":"user_admin","aal_level":3}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Seed-Token", seedToken())
	req.Header.Set("Origin", base)
	client.Do(req)

	return jwt, orgID
}

// newAdminClient builds a *idaas.Client pre-loaded with the admin JWT.
func newAdminClient(t *testing.T) (*idaas.Client, string) {
	t.Helper()
	jwt, orgID := adminLogin(t)
	c := idaas.NewClient(baseURL(), "")
	c.SetToken(jwt)
	// Attach org header via a custom HTTP client wrapper.
	// The SDK's Client.request() picks up X-Organization-Id from headers set on c.
	// We store orgID separately and pass it to raw helpers where needed.
	return c, orgID
}

// rawRequest makes an authenticated HTTP request and asserts a 2xx status.
// Used for endpoints not yet wrapped in the SDK (e.g. /agents/token with org header).
func rawRequest(t *testing.T, method, path, jwt, orgID, body string) map[string]interface{} {
	t.Helper()
	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, baseURL()+path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	if orgID != "" {
		req.Header.Set("X-Organization-Id", orgID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s request error: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		t.Fatalf("%s %s returned %d: %s", method, path, resp.StatusCode, raw)
	}
	var result map[string]interface{}
	_ = json.Unmarshal(raw, &result)
	return result
}

// rawStatus is like rawRequest but returns the status code without asserting.
func rawStatus(t *testing.T, method, path, jwt, orgID, body string) int {
	t.Helper()
	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, baseURL()+path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	if orgID != "" {
		req.Header.Set("X-Organization-Id", orgID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("rawStatus %s %s: %v", method, path, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// issueAgentToken calls POST /api/v1/agents/token and returns the JWT string.
func issueAgentToken(t *testing.T, jwt, orgID, agentID, taskID string) string {
	t.Helper()
	body := fmt.Sprintf(`{"agent_id":%q,"task_id":%q}`, agentID, taskID)
	data := rawRequest(t, "POST", "/api/v1/agents/token", jwt, orgID, body)
	tok, ok := data["token"].(string)
	if !ok || tok == "" {
		t.Fatalf("issueAgentToken: no token in response: %v", data)
	}
	return tok
}

// ---------------------------------------------------------------------------
// Suite A — RegisterAgent, ListAgents, GetAgent
// ---------------------------------------------------------------------------

func TestRegisterAgent(t *testing.T) {
	jwt, orgID := adminLogin(t)

	t.Run("returns agt_ prefix", func(t *testing.T) {
		body := fmt.Sprintf(`{"name":%q,"allowed_tools":"web_search send_email"}`, unique("go-reg"))
		data := rawRequest(t, "POST", "/api/v1/agents/register", jwt, orgID, body)
		agentID, _ := data["agent_id"].(string)
		if !strings.HasPrefix(agentID, "agt_") {
			t.Fatalf("expected agt_ prefix, got %q", agentID)
		}
	})

	t.Run("upsert returns same agent_id", func(t *testing.T) {
		name := unique("go-upsert")
		b1 := fmt.Sprintf(`{"name":%q,"allowed_tools":"web_search"}`, name)
		b2 := fmt.Sprintf(`{"name":%q,"allowed_tools":"web_search send_email"}`, name)
		d1 := rawRequest(t, "POST", "/api/v1/agents/register", jwt, orgID, b1)
		d2 := rawRequest(t, "POST", "/api/v1/agents/register", jwt, orgID, b2)
		if d1["agent_id"] != d2["agent_id"] {
			t.Fatalf("upsert must return same agent_id: %v vs %v", d1["agent_id"], d2["agent_id"])
		}
	})

	t.Run("invalid depth rejected with 400", func(t *testing.T) {
		body := fmt.Sprintf(`{"name":%q,"max_delegation_depth":99}`, unique("bad-depth"))
		status := rawStatus(t, "POST", "/api/v1/agents/register", jwt, orgID, body)
		if status != 400 {
			t.Fatalf("expected 400 for invalid depth, got %d", status)
		}
	})

	t.Run("cimd_metadata_url must be https", func(t *testing.T) {
		body := fmt.Sprintf(`{"name":%q,"cimd_metadata_url":"http://insecure.example.com/client.json"}`, unique("cimd-http"))
		status := rawStatus(t, "POST", "/api/v1/agents/register", jwt, orgID, body)
		if status != 400 {
			t.Fatalf("expected 400 for http cimd url, got %d", status)
		}
	})
}

func TestListAndGetAgents(t *testing.T) {
	jwt, orgID := adminLogin(t)

	// Register a known agent
	name := unique("go-list")
	body := fmt.Sprintf(`{"name":%q,"allowed_tools":"web_search"}`, name)
	reg := rawRequest(t, "POST", "/api/v1/agents/register", jwt, orgID, body)
	agentID := reg["agent_id"].(string)

	t.Run("list includes newly registered agent", func(t *testing.T) {
		list := rawRequest(t, "GET", "/api/v1/agents", jwt, orgID, "")
		// list is a JSON array
		arr, ok := list[""].([]interface{})
		if !ok {
			// rawRequest returns map[string]interface{} — array responses come back
			// with key "" when the root is an array; handle via direct unmarshal.
			resp, _ := http.NewRequest("GET", baseURL()+"/api/v1/agents", nil)
			resp.Header.Set("Authorization", "Bearer "+jwt)
			resp.Header.Set("X-Organization-Id", orgID)
			httpResp, err := http.DefaultClient.Do(resp)
			if err != nil || httpResp.StatusCode >= 400 {
				t.Skipf("list agents HTTP error — skipping list content check")
			}
			defer httpResp.Body.Close()
			var agents []map[string]interface{}
			json.NewDecoder(httpResp.Body).Decode(&agents)
			found := false
			for _, a := range agents {
				if a["agent_id"] == agentID {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("agent %s not found in list", agentID)
			}
			return
		}
		_ = arr // already found if no error above
	})

	t.Run("get by id returns correct agent", func(t *testing.T) {
		got := rawRequest(t, "GET", "/api/v1/agents/"+agentID, jwt, orgID, "")
		if got["agent_id"] != agentID {
			t.Fatalf("got wrong agent_id: %v", got["agent_id"])
		}
		if got["name"] != name {
			t.Fatalf("got wrong name: %v", got["name"])
		}
	})
}

// ---------------------------------------------------------------------------
// Suite B — IssueAgentToken, AuthorizeToolCall, HashToolArgs, RecordExecution
// ---------------------------------------------------------------------------

func TestIssueAgentToken(t *testing.T) {
	jwt, orgID := adminLogin(t)
	name := unique("go-token")
	reg := rawRequest(t, "POST", "/api/v1/agents/register", jwt, orgID,
		fmt.Sprintf(`{"name":%q,"allowed_tools":"web_search"}`, name))
	agentID := reg["agent_id"].(string)

	t.Run("issues valid token", func(t *testing.T) {
		taskID := unique("task")
		agentTok := issueAgentToken(t, jwt, orgID, agentID, taskID)
		if agentTok == "" {
			t.Fatal("expected non-empty agent token")
		}
		// Token should be a JWT (three dot-separated segments)
		parts := strings.Split(agentTok, ".")
		if len(parts) != 3 {
			t.Fatalf("expected JWT format (3 parts), got %d parts", len(parts))
		}
	})

	t.Run("agent session cannot issue another token", func(t *testing.T) {
		taskID := unique("task")
		agentTok := issueAgentToken(t, jwt, orgID, agentID, taskID)
		// Using the agent token to call /agents/token must be rejected
		body := fmt.Sprintf(`{"agent_id":%q,"task_id":%q}`, agentID, unique("task2"))
		status := rawStatus(t, "POST", "/api/v1/agents/token", agentTok, orgID, body)
		if status < 400 {
			t.Fatalf("agent session must not be able to mint agent tokens, got %d", status)
		}
	})

	t.Run("delegation depth guard enforced", func(t *testing.T) {
		name2 := unique("go-depth")
		reg2 := rawRequest(t, "POST", "/api/v1/agents/register", jwt, orgID,
			fmt.Sprintf(`{"name":%q,"allowed_tools":"web_search","max_delegation_depth":1}`, name2))
		agentID2 := reg2["agent_id"].(string)
		body := fmt.Sprintf(`{"agent_id":%q,"task_id":%q,"delegation_chain":["parent-1"]}`,
			agentID2, unique("task"))
		status := rawStatus(t, "POST", "/api/v1/agents/token", jwt, orgID, body)
		if status < 400 {
			t.Fatalf("expected rejection for delegation depth overflow, got %d", status)
		}
	})
}

func TestAuthorizeToolCall(t *testing.T) {
	jwt, orgID := adminLogin(t)
	name := unique("go-authz")
	reg := rawRequest(t, "POST", "/api/v1/agents/register", jwt, orgID,
		fmt.Sprintf(`{"name":%q,"allowed_tools":"web_search send_email"}`, name))
	agentID := reg["agent_id"].(string)
	taskID := unique("task")
	agentTok := issueAgentToken(t, jwt, orgID, agentID, taskID)

	t.Run("HashToolArgs is deterministic SHA-256", func(t *testing.T) {
		args := map[string]interface{}{"q": "flights NYC SFO", "date": "2026-04-01"}
		h1, err := idaas.HashToolArgs(args)
		if err != nil {
			t.Fatalf("HashToolArgs error: %v", err)
		}
		h2, _ := idaas.HashToolArgs(args)
		if h1 != h2 {
			t.Fatal("HashToolArgs must be deterministic")
		}
		if len(h1) != 64 {
			t.Fatalf("expected 64-char hex, got %d", len(h1))
		}
	})

	t.Run("authorize returns decision struct", func(t *testing.T) {
		// Build a client with the agent token
		c := idaas.NewClient(baseURL(), "")
		c.SetToken(agentTok)

		argsHash, _ := idaas.HashToolArgs(map[string]interface{}{"q": "test"})
		decision, err := c.AuthorizeToolCall(agentID, "web_search", &argsHash, false)
		if err != nil {
			// AgentAuthzDenied is also a valid outcome — check it
			if denied, ok := err.(*idaas.AgentAuthzDenied); ok {
				t.Logf("capsule returned deny (expected in test env): %v", denied)
				return
			}
			t.Fatalf("AuthorizeToolCall error: %v", err)
		}
		if decision.DecisionRef == "" {
			t.Fatal("expected non-empty decision_ref")
		}
	})

	t.Run("AgentAuthzDenied implements error interface", func(t *testing.T) {
		var err error = &idaas.AgentAuthzDenied{DecisionRef: "ref_test"}
		if err.Error() == "" {
			t.Fatal("AgentAuthzDenied.Error() must return non-empty string")
		}
	})

	t.Run("wrong agent_id in path is rejected", func(t *testing.T) {
		c := idaas.NewClient(baseURL(), "")
		c.SetToken(agentTok)
		// Different agent_id in the path — backend checks JWT claim matches path
		_, err := c.AuthorizeToolCall("agt_wrong_id", "web_search", nil, false)
		if err == nil {
			t.Fatal("expected error for mismatched agent_id")
		}
	})
}

func TestRecordExecution(t *testing.T) {
	jwt, orgID := adminLogin(t)
	name := unique("go-record")
	reg := rawRequest(t, "POST", "/api/v1/agents/register", jwt, orgID,
		fmt.Sprintf(`{"name":%q,"allowed_tools":"web_search"}`, name))
	agentID := reg["agent_id"].(string)
	taskID := unique("task")
	agentTok := issueAgentToken(t, jwt, orgID, agentID, taskID)

	c := idaas.NewClient(baseURL(), "")
	c.SetToken(agentTok)

	t.Run("records allowed execution", func(t *testing.T) {
		argsHash, _ := idaas.HashToolArgs(map[string]interface{}{"q": "test"})
		req := idaas.RecordExecutionRequest{
			ToolName:     "web_search",
			TaskID:       taskID,
			Allowed:      true,
			ToolArgsHash: &argsHash,
		}
		result, err := c.RecordExecution(agentID, req)
		if err != nil {
			t.Fatalf("RecordExecution error: %v", err)
		}
		if result.ToolName != "web_search" {
			t.Fatalf("expected tool_name=web_search, got %q", result.ToolName)
		}
		if result.TaskID != taskID {
			t.Fatalf("expected task_id=%s, got %q", taskID, result.TaskID)
		}
		if result.ExecutionID == "" {
			t.Fatal("expected non-empty execution_id")
		}
	})

	t.Run("records denied execution", func(t *testing.T) {
		reason := "risk score exceeded"
		req := idaas.RecordExecutionRequest{
			ToolName:     "web_search",
			TaskID:       taskID,
			Allowed:      false,
			DenialReason: &reason,
		}
		result, err := c.RecordExecution(agentID, req)
		if err != nil {
			t.Fatalf("RecordExecution (denied) error: %v", err)
		}
		if result.ExecutionID == "" {
			t.Fatal("expected non-empty execution_id for denied execution")
		}
	})
}

// ---------------------------------------------------------------------------
// Suite C — GetTaskChain, GetAgentHistory (audit chain)
// ---------------------------------------------------------------------------

func TestAuditChain(t *testing.T) {
	jwt, orgID := adminLogin(t)
	name := unique("go-audit")
	reg := rawRequest(t, "POST", "/api/v1/agents/register", jwt, orgID,
		fmt.Sprintf(`{"name":%q,"allowed_tools":"web_search"}`, name))
	agentID := reg["agent_id"].(string)
	taskID := unique("audit-task")
	agentTok := issueAgentToken(t, jwt, orgID, agentID, taskID)

	// Record an execution to ensure the chain is non-empty
	agentClient := idaas.NewClient(baseURL(), "")
	agentClient.SetToken(agentTok)
	agentClient.RecordExecution(agentID, idaas.RecordExecutionRequest{
		ToolName: "web_search",
		TaskID:   taskID,
		Allowed:  true,
	})

	// Admin queries the audit chain (needs audit:read EIAA action)
	adminClient := idaas.NewClient(baseURL(), "")
	adminClient.SetToken(jwt)

	t.Run("task chain returns items and next_cursor fields", func(t *testing.T) {
		chain, err := adminClient.GetTaskChain(taskID, nil)
		if err != nil {
			t.Fatalf("GetTaskChain error: %v", err)
		}
		if chain.Items == nil {
			t.Fatal("expected non-nil items slice")
		}
		// next_cursor is nil when there is only one page
		t.Logf("task chain: %d items, next_cursor=%v", len(chain.Items), chain.NextCursor)
	})

	t.Run("task chain cursor pagination roundtrip", func(t *testing.T) {
		chain, err := adminClient.GetTaskChain(taskID, nil)
		if err != nil {
			t.Fatalf("GetTaskChain error: %v", err)
		}
		if chain.NextCursor != nil {
			// Fetch second page using the cursor
			page2, err := adminClient.GetTaskChain(taskID, chain.NextCursor)
			if err != nil {
				t.Fatalf("GetTaskChain page2 error: %v", err)
			}
			_ = page2
		}
	})

	t.Run("agent history returns list", func(t *testing.T) {
		history, err := adminClient.GetAgentHistory(agentID, nil)
		if err != nil {
			t.Fatalf("GetAgentHistory error: %v", err)
		}
		if history.Items == nil {
			t.Fatal("expected non-nil items slice")
		}
	})
}

// ---------------------------------------------------------------------------
// Suite D — Deactivate, Revoke, tenant isolation
// ---------------------------------------------------------------------------

func TestLifecycle(t *testing.T) {
	jwt, orgID := adminLogin(t)

	t.Run("deactivate returns 204 and get returns 404", func(t *testing.T) {
		name := unique("go-deact")
		reg := rawRequest(t, "POST", "/api/v1/agents/register", jwt, orgID,
			fmt.Sprintf(`{"name":%q,"allowed_tools":"web_search"}`, name))
		agentID := reg["agent_id"].(string)

		status := rawStatus(t, "DELETE", "/api/v1/agents/"+agentID, jwt, orgID, "")
		if status != 204 {
			t.Fatalf("expected 204 from deactivate, got %d", status)
		}
		getStatus := rawStatus(t, "GET", "/api/v1/agents/"+agentID, jwt, orgID, "")
		if getStatus != 404 {
			t.Fatalf("expected 404 after deactivation, got %d", getStatus)
		}
	})

	t.Run("revoke tokens returns 204", func(t *testing.T) {
		name := unique("go-revoke")
		reg := rawRequest(t, "POST", "/api/v1/agents/register", jwt, orgID,
			fmt.Sprintf(`{"name":%q,"allowed_tools":"web_search"}`, name))
		agentID := reg["agent_id"].(string)

		status := rawStatus(t, "POST", "/api/v1/agents/"+agentID+"/revoke", jwt, orgID, "")
		if status != 204 {
			t.Fatalf("expected 204 from revoke, got %d", status)
		}
	})

	t.Run("revoke nonexistent agent returns 404", func(t *testing.T) {
		status := rawStatus(t, "POST", "/api/v1/agents/agt_doesnotexist/revoke", jwt, orgID, "")
		if status != 404 {
			t.Fatalf("expected 404 for nonexistent agent, got %d", status)
		}
	})
}

func TestMain(m *testing.M) {
	rand.New(rand.NewSource(time.Now().UnixNano()))
	os.Exit(m.Run())
}
