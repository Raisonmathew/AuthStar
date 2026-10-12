// Example: Using the AuthStar Go SDK in an agent authorization loop.
//
// This simulates an AI agent that checks authorization before every tool call.
// Run with:
//
//	AUTHSTAR_API_KEY=ask_... go run ./examples/agent_loop
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	authstar "github.com/authstar/go-sdk"
)

func main() {
	baseURL := os.Getenv("AUTHSTAR_BASE_URL")
	if baseURL == "" {
		baseURL = "https://auth.example.com"
	}
	apiKey := os.Getenv("AUTHSTAR_API_KEY")
	if apiKey == "" {
		log.Fatal("Set AUTHSTAR_API_KEY")
	}

	client := authstar.New(baseURL, apiKey)
	ctx := context.Background()

	// Check connectivity
	h, err := client.Health(ctx)
	if err != nil {
		log.Fatalf("Health check failed: %v", err)
	}
	fmt.Printf("✓ Connected to AuthStar (%dms)\n\n", h.LatencyMs)

	// Simulate an agent loop: authorize before each tool call
	toolCalls := []struct {
		name   string
		action string
	}{
		{"read_invoice", "billing:read"},
		{"update_billing", "billing:write"},
		{"list_users", "org:read"},
	}

	for _, tool := range toolCalls {
		decision, err := client.Authorize(ctx, tool.action, map[string]any{
			"tool_name": tool.name,
		})
		if err != nil {
			fmt.Printf("✗ %s (%s) — error: %v\n", tool.name, tool.action, err)
			continue
		}

		if decision.Allowed {
			fmt.Printf("✓ %s (%s) — ALLOW [ref: %s]\n", tool.name, tool.action, decision.DecisionRef)
		} else {
			fmt.Printf("✗ %s (%s) — DENY [reason: %s]\n", tool.name, tool.action,
				func() string {
					if decision.Reason != nil {
						return *decision.Reason
					}
					return "capsule denied"
				}())
		}
	}
}
