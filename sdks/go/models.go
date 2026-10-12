package authstar

// AuthzDecision represents the authorization decision returned by Authorize.
type AuthzDecision struct {
	Allowed        bool    `json:"allowed"`
	DecisionRef    string  `json:"decision_ref"`
	AttestationSig string  `json:"attestation_sig"`
	Reason         *string `json:"reason"`
}

// TaskChainItem represents an item in an audit task chain.
type TaskChainItem struct {
	ID                string  `json:"id"`
	Action            string  `json:"action"`
	Allowed           bool    `json:"allowed"`
	AgentID           *string `json:"agent_id"`
	ToolName          *string `json:"tool_name"`
	CreatedAt         string  `json:"created_at"`
	AttestationSigB64 string  `json:"attestation_signature_b64"`
}

// TaskChainPage represents a paginated list of task chain items.
type TaskChainPage struct {
	Items      []TaskChainItem `json:"items"`
	NextCursor *string         `json:"next_cursor"`
}

// TaskChainOptions contains pagination options for GetTaskChain.
type TaskChainOptions struct {
	Cursor *string `json:"cursor,omitempty"`
	Limit  *int    `json:"limit,omitempty"`
}

// VerificationResult represents the result of verifying a past decision.
type VerificationResult struct {
	DecisionRef       string  `json:"decision_ref"`
	OriginalDecision  bool    `json:"original_decision"`
	ReplayedDecision  bool    `json:"replayed_decision"`
	DecisionsMatch    bool    `json:"decisions_match"`
	Status            string  `json:"verification_status"`
	DiscrepancyReason *string `json:"discrepancy_reason"`
}

// HealthStatus represents the health check response with measured round-trip latency.
type HealthStatus struct {
	OK        bool  `json:"ok"`
	LatencyMs int64 `json:"latency_ms"`
}
