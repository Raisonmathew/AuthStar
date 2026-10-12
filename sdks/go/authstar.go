// Package authstar provides a Go client for the AuthStar IDaaS API.
//
// # Quick start
//
//	client := authstar.New("https://auth.example.com", "ask_your_api_key")
//
//	decision, err := client.Authorize(ctx, "billing:read", map[string]any{
//	    "user_id": "usr_123",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if !decision.Allowed {
//	    http.Error(w, "Forbidden", http.StatusForbidden)
//	    return
//	}
package authstar

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AgentAuthzClient is the main client for the AuthStar API.
// Create one with New() and reuse it — it is safe for concurrent use.
type AgentAuthzClient struct {
	baseURL    string
	apiKey     string
	tenantID   string
	httpClient *http.Client
}

// Option configures an AgentAuthzClient.
type Option func(*AgentAuthzClient)

// WithTenantID sets the X-Organization-Id header on every request.
func WithTenantID(id string) Option {
	return func(c *AgentAuthzClient) { c.tenantID = id }
}

// WithTimeout overrides the default 10s HTTP timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *AgentAuthzClient) { c.httpClient.Timeout = d }
}

// WithHTTPClient replaces the underlying *http.Client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *AgentAuthzClient) { c.httpClient = hc }
}

// New creates an AgentAuthzClient.
//
//   - baseURL: base URL of the AuthStar API, e.g. "https://auth.example.com"
//   - apiKey:  API key ("ask_...") or JWT bearer token
func New(baseURL, apiKey string, opts ...Option) *AgentAuthzClient {
	baseURL = strings.TrimRight(baseURL, "/")
	c := &AgentAuthzClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// TaskChainOptions configures GetTaskChain pagination.
type TaskChainOptions struct {
	Cursor string
	Limit  int
}

// Authorize requests an EIAA authorization decision.
//
// action is the EIAA action string (e.g. "billing:read").
// contextData is optional additional context passed to the capsule.
func (c *AgentAuthzClient) Authorize(ctx context.Context, action string, contextData map[string]any) (*AuthzDecision, error) {
	body := map[string]any{"action": action}
	if len(contextData) > 0 {
		body["context"] = contextData
	}
	var out AuthzDecision
	if err := c.do(ctx, http.MethodPost, "/api/v1/decisions", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Revoke revokes an agent's active delegations by agent ID.
func (c *AgentAuthzClient) Revoke(ctx context.Context, agentID string) error {
	path := fmt.Sprintf("/api/v1/agents/%s/revoke", agentID)
	return c.do(ctx, http.MethodPost, path, nil, nil)
}

// GetTaskChain returns the ordered causal chain of EIAA executions for a task.
func (c *AgentAuthzClient) GetTaskChain(ctx context.Context, taskID string, opts *TaskChainOptions) (*TaskChainPage, error) {
	path := fmt.Sprintf("/api/v1/audit/task/%s", taskID)
	params := ""
	if opts != nil {
		parts := []string{}
		if opts.Cursor != "" {
			parts = append(parts, "cursor="+opts.Cursor)
		}
		if opts.Limit > 0 {
			parts = append(parts, fmt.Sprintf("limit=%d", opts.Limit))
		}
		if len(parts) > 0 {
			params = "?" + strings.Join(parts, "&")
		}
	}
	var out TaskChainPage
	if err := c.do(ctx, http.MethodGet, path+params, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyDecision re-executes a stored capsule decision and checks it matches
// the original. Returns cryptographic proof of decision integrity.
func (c *AgentAuthzClient) VerifyDecision(ctx context.Context, decisionRef string) (*VerificationResult, error) {
	path := fmt.Sprintf("/api/v1/audit/reexecution/verify/%s", decisionRef)
	var wrapper struct {
		Result VerificationResult `json:"result"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &wrapper); err != nil {
		return nil, err
	}
	return &wrapper.Result, nil
}

// Health performs a basic connectivity check and returns latency.
func (c *AgentAuthzClient) Health(ctx context.Context) (*HealthStatus, error) {
	start := time.Now()
	var out struct {
		Status string `json:"status"`
	}
	if err := c.do(ctx, http.MethodGet, "/health", nil, &out); err != nil {
		return nil, err
	}
	latency := time.Since(start).Milliseconds()
	return &HealthStatus{
		OK:        out.Status == "ok" || out.Status == "",
		LatencyMs: latency,
	}, nil
}

// ─── internal ────────────────────────────────────────────────────────────────

func (c *AgentAuthzClient) do(ctx context.Context, method, path string, body, out any) error {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("authstar: marshal request: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return fmt.Errorf("authstar: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.tenantID != "" {
		req.Header.Set("X-Organization-Id", c.tenantID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("authstar: http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var errBody struct {
			Code    string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &errBody)
		if errBody.Code == "" {
			errBody.Code = "unknown_error"
		}
		if errBody.Message == "" {
			errBody.Message = string(raw)
		}
		return &AuthstarError{
			StatusCode: resp.StatusCode,
			Code:       errBody.Code,
			Message:    errBody.Message,
		}
	}

	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("authstar: decode response: %w", err)
	}
	return nil
}
