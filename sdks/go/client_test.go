package authstar_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	authstar "github.com/authstar/go-sdk"
)

// ─── Authorize ────────────────────────────────────────────────────────────────

func TestAuthorize_Allow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/decisions" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test_key" {
			t.Errorf("missing auth header")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(authstar.AuthzDecision{
			Allowed:        true,
			DecisionRef:    "dr_abc123",
			AttestationSig: "sig_xyz",
		})
	}))
	defer srv.Close()

	c := authstar.New(srv.URL, "test_key")
	d, err := c.Authorize(context.Background(), "billing:read", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.Allowed {
		t.Error("expected allowed=true")
	}
	if d.DecisionRef != "dr_abc123" {
		t.Errorf("unexpected decision_ref: %s", d.DecisionRef)
	}
}

func TestAuthorize_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "forbidden",
			"message": "EIAA capsule denied",
		})
	}))
	defer srv.Close()

	c := authstar.New(srv.URL, "test_key")
	_, err := c.Authorize(context.Background(), "billing:write", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	ae, ok := err.(*authstar.AuthstarError)
	if !ok {
		t.Fatalf("expected *AuthstarError, got %T", err)
	}
	if ae.StatusCode != 403 {
		t.Errorf("expected 403, got %d", ae.StatusCode)
	}
	if ae.Code != "forbidden" {
		t.Errorf("expected code='forbidden', got %q", ae.Code)
	}
}

// ─── Health ───────────────────────────────────────────────────────────────────

func TestHealth_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	c := authstar.New(srv.URL, "test_key")
	h, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !h.OK {
		t.Error("expected health ok=true")
	}
	if h.LatencyMs < 0 {
		t.Error("latency must be non-negative")
	}
}

// ─── GetTaskChain ─────────────────────────────────────────────────────────────

func TestGetTaskChain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/task/task_123" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(authstar.TaskChainPage{
			Items: []authstar.TaskChainItem{
				{ID: "exec_1", Action: "billing:read", Allowed: true, CreatedAt: "2025-01-01T00:00:00Z"},
			},
			NextCursor: nil,
		})
	}))
	defer srv.Close()

	c := authstar.New(srv.URL, "test_key")
	page, err := c.GetTaskChain(context.Background(), "task_123", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(page.Items) != 1 {
		t.Errorf("expected 1 item, got %d", len(page.Items))
	}
	if page.Items[0].ID != "exec_1" {
		t.Errorf("unexpected item ID: %s", page.Items[0].ID)
	}
}

// ─── WithTenantID ─────────────────────────────────────────────────────────────

func TestWithTenantID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Organization-Id") != "org_abc" {
			t.Errorf("expected X-Organization-Id=org_abc, got %q", r.Header.Get("X-Organization-Id"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	c := authstar.New(srv.URL, "test_key", authstar.WithTenantID("org_abc"))
	_, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
