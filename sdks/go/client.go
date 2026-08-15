package idaas

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// APIError represents a structured error response from the IDaaS API.
// HIGH-D: All HTTP error responses are decoded into this type so callers
// receive actionable error messages rather than opaque status strings.
type APIError struct {
	StatusCode int
	Status     string
	Message    string `json:"error"`
	Code       string `json:"code,omitempty"`
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("IDaaS API error %d: %s (code: %s)", e.StatusCode, e.Message, e.Code)
	}
	return fmt.Sprintf("IDaaS API error %d: %s", e.StatusCode, e.Status)
}

// Client represents the IDaaS API client
type Client struct {
	BaseURL    string
	APIKey     string
	JWT        string
	HTTPClient *http.Client
}

// User represents a user in the system
type User struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	FirstName     string `json:"firstName,omitempty"`
	LastName      string `json:"lastName,omitempty"`
	EmailVerified bool   `json:"emailVerified"`
	MFAEnabled    bool   `json:"mfaEnabled"`
}

// Organization represents an organization
type Organization struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	CreatedAt string `json:"createdAt"`
}

// ─── Agent Auth types ─────────────────────────────────────────────────────────

// AgentPrincipal represents a registered AI agent principal.
type AgentPrincipal struct {
	ID                 string  `json:"id"`
	AgentID            string  `json:"agent_id"`
	Name               string  `json:"name"`
	ModelID            *string `json:"model_id"`
	AllowedTools       string  `json:"allowed_tools"`
	MaxDelegationDepth int16   `json:"max_delegation_depth"`
	TokenTTLSeconds    int32   `json:"token_ttl_seconds"`
	PrincipalSource    string  `json:"principal_source"`
	CIMDMetadataURL    *string `json:"cimd_metadata_url"`
	Active             bool    `json:"active"`
	CreatedAt          string  `json:"created_at"`
	UpdatedAt          string  `json:"updated_at"`
}

// RegisterAgentRequest is the payload for POST /api/v1/agents/register.
type RegisterAgentRequest struct {
	Name               string  `json:"name"`
	ModelID            *string `json:"model_id,omitempty"`
	AllowedTools       *string `json:"allowed_tools,omitempty"`
	MaxDelegationDepth *int16  `json:"max_delegation_depth,omitempty"`
	TokenTTLSeconds    *int32  `json:"token_ttl_seconds,omitempty"`
	CIMDMetadataURL    *string `json:"cimd_metadata_url,omitempty"`
}

// RegisterAgentResponse is the response from POST /api/v1/agents/register.
type RegisterAgentResponse struct {
	AgentID            string  `json:"agent_id"`
	Name               string  `json:"name"`
	ModelID            *string `json:"model_id"`
	AllowedTools       string  `json:"allowed_tools"`
	MaxDelegationDepth int16   `json:"max_delegation_depth"`
	TokenTTLSeconds    int32   `json:"token_ttl_seconds"`
	PrincipalSource    string  `json:"principal_source"`
	CreatedAt          string  `json:"created_at"`
}

// IssueAgentTokenRequest is the payload for POST /api/v1/agents/token.
type IssueAgentTokenRequest struct {
	AgentID         string   `json:"agent_id"`
	TaskID          string   `json:"task_id"`
	DelegationChain []string `json:"delegation_chain,omitempty"`
	AllowedTools    []string `json:"allowed_tools,omitempty"`
}

// IssueAgentTokenResponse is the response from POST /api/v1/agents/token.
type IssueAgentTokenResponse struct {
	Token     string `json:"token"`
	AgentID   string `json:"agent_id"`
	TaskID    string `json:"task_id"`
	ExpiresIn int64  `json:"expires_in"`
}

// AgentDecision is the result of an EIAA tool-call authorization check.
type AgentDecision struct {
	Allowed        bool    `json:"allowed"`
	Reason         *string `json:"reason"`
	DecisionRef    string  `json:"decision_ref"`
	AttestationRef *string `json:"attestation_ref"`
	RiskScore      *int    `json:"risk_score"`
}

// RecordExecutionRequest is the payload for POST /api/v1/agents/:id/executions.
type RecordExecutionRequest struct {
	ToolName        string  `json:"tool_name"`
	TaskID          string  `json:"task_id"`
	Allowed         bool    `json:"allowed"`
	ToolArgsHash    *string `json:"tool_args_hash,omitempty"`
	DenialReason    *string `json:"denial_reason,omitempty"`
	EiaaExecutionID *string `json:"eiaa_execution_id,omitempty"`
}

// RecordExecutionResponse is the response from POST /api/v1/agents/:id/executions.
type RecordExecutionResponse struct {
	ExecutionID string `json:"execution_id"`
	ToolName    string `json:"tool_name"`
	TaskID      string `json:"task_id"`
	RecordedAt  string `json:"recorded_at"`
}

// AgentTaskChainItem is a single EIAA execution row from the task chain.
type AgentTaskChainItem struct {
	ID                      string  `json:"id"`
	DecisionRef             string  `json:"decision_ref"`
	Action                  string  `json:"action"`
	CapsuleHashB64          string  `json:"capsule_hash_b64"`
	Decision                any     `json:"decision"`
	AttestationSignatureB64 string  `json:"attestation_signature_b64"`
	AttestationTimestamp    string  `json:"attestation_timestamp"`
	CreatedAt               string  `json:"created_at"`
	TaskID                  *string `json:"task_id"`
	ParentActionID          *string `json:"parent_action_id"`
	DelegationDepth         int     `json:"delegation_depth"`
	PrincipalType           string  `json:"principal_type"`
	AgentID                 *string `json:"agent_id"`
	ModelID                 *string `json:"model_id"`
	ToolName                *string `json:"tool_name"`
	ToolArgsHash            *string `json:"tool_args_hash"`
}

// AgentChainResponse is the response from the task chain and agent history endpoints.
type AgentChainResponse struct {
	Items      []AgentTaskChainItem `json:"items"`
	NextCursor *string              `json:"next_cursor"`
}

// AgentAuthzDenied is returned (as an error) when the EIAA capsule denies a tool call.
type AgentAuthzDenied struct {
	Reason         *string
	AttestationRef *string
	DecisionRef    string
}

func (e *AgentAuthzDenied) Error() string {
	if e.Reason != nil {
		return fmt.Sprintf("agent tool call denied by EIAA capsule: %s", *e.Reason)
	}
	return "agent tool call denied by EIAA capsule"
}

// ─── SDK Manifest types ───────────────────────────────────────────────────────
// These mirror the Rust SdkManifest structs in sdk_manifest.rs.
// They never contain OAuth secrets.

// OAuthDescriptor describes an OAuth provider shown in the sign-in UI.
type OAuthDescriptor struct {
	Provider string `json:"provider"`
	Label    string `json:"label"`
	Enabled  bool   `json:"enabled"`
}

// FieldDescriptor describes a single sign-up form field.
type FieldDescriptor struct {
	Name      string `json:"name"`
	FieldType string `json:"field_type"`
	Label     string `json:"label"`
	Required  bool   `json:"required"`
	Order     uint32 `json:"order"`
}

// BrandingSafeFields holds tenant branding colors and font.
type BrandingSafeFields struct {
	LogoURL         *string `json:"logo_url,omitempty"`
	PrimaryColor    string  `json:"primary_color"`
	BackgroundColor string  `json:"background_color"`
	TextColor       string  `json:"text_color"`
	FontFamily      string  `json:"font_family"`
}

// SignInManifest describes the sign-in flow configuration.
type SignInManifest struct {
	OAuthProviders       []OAuthDescriptor `json:"oauth_providers"`
	PasskeyEnabled       bool              `json:"passkey_enabled"`
	EmailPasswordEnabled bool              `json:"email_password_enabled"`
}

// SignUpManifest describes the sign-up form fields.
type SignUpManifest struct {
	Fields []FieldDescriptor `json:"fields"`
}

// FlowsManifest holds sign-in and sign-up configurations.
type FlowsManifest struct {
	SignIn SignInManifest `json:"sign_in"`
	SignUp SignUpManifest `json:"sign_up"`
}

// SdkManifest is the full tenant manifest returned by GET /api/v1/sdk/manifest.
type SdkManifest struct {
	OrgID    string             `json:"org_id"`
	OrgName  string             `json:"org_name"`
	Slug     string             `json:"slug"`
	Version  uint64             `json:"version"`
	Branding BrandingSafeFields `json:"branding"`
	Flows    FlowsManifest      `json:"flows"`
}

// SignUpRequest represents sign up request data
type SignUpRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
}

// SignInRequest represents sign in request data
type SignInRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

// NewClient creates a new IDaaS client
func NewClient(baseURL string, apiKey string) *Client {
	return &Client{
		BaseURL:    baseURL,
		APIKey:     apiKey,
		HTTPClient: &http.Client{},
	}
}

// request makes an HTTP request to the API
func (c *Client) request(method, endpoint string, body interface{}) (*http.Response, error) {
	url := c.BaseURL + endpoint

	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("X-API-Key", c.APIKey)
	}
	if c.JWT != "" {
		req.Header.Set("Authorization", "Bearer "+c.JWT)
	}

	return c.HTTPClient.Do(req)
}

// checkResponse reads the response body and returns an *APIError if the status
// code indicates failure (>= 400). The body is always drained and closed.
//
// HIGH-D: Without this helper, callers that forget to check resp.StatusCode
// silently succeed on 4xx/5xx responses, masking authentication failures,
// rate-limit errors, and server faults.
func checkResponse(resp *http.Response) error {
	if resp.StatusCode < 400 {
		return nil
	}
	defer resp.Body.Close()

	apiErr := &APIError{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
	}

	// Attempt to decode a structured error body; ignore decode errors
	// (the status code alone is sufficient for the error message).
	_ = json.NewDecoder(resp.Body).Decode(apiErr)
	return apiErr
}

// SignUp creates a new user account
func (c *Client) SignUp(req SignUpRequest) (map[string]interface{}, error) {
	resp, err := c.request("POST", "/api/v1/auth/signup", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sign up failed: %s", resp.Status)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// SignIn authenticates a user
func (c *Client) SignIn(req SignInRequest) (map[string]interface{}, error) {
	resp, err := c.request("POST", "/api/v1/auth/login", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sign in failed: %s", resp.Status)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// Store JWT
	if jwt, ok := result["jwt"].(string); ok {
		c.JWT = jwt
	}

	return result, nil
}

// SignOut signs out the current user.
//
// HIGH-D: Previously did not check the HTTP status code, so a 401/500 response
// would silently succeed and clear the local JWT, masking server-side errors.
func (c *Client) SignOut() error {
	resp, err := c.request("POST", "/api/v1/auth/logout", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := checkResponse(resp); err != nil {
		return err
	}

	c.JWT = ""
	return nil
}

// GetCurrentUser retrieves the current user's profile
func (c *Client) GetCurrentUser() (*User, error) {
	resp, err := c.request("GET", "/api/v1/user", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get user failed: %s", resp.Status)
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return &user, nil
}

// UpdateUser updates the current user's profile
func (c *Client) UpdateUser(updates map[string]interface{}) (*User, error) {
	resp, err := c.request("PATCH", "/api/v1/user", updates)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update user failed: %s", resp.Status)
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return &user, nil
}

// CreateOrganization creates a new organization
func (c *Client) CreateOrganization(name, slug string) (*Organization, error) {
	body := map[string]string{"name": name}
	if slug != "" {
		body["slug"] = slug
	}

	resp, err := c.request("POST", "/api/v1/organizations", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("create organization failed: %s", resp.Status)
	}

	var org Organization
	if err := json.NewDecoder(resp.Body).Decode(&org); err != nil {
		return nil, err
	}

	return &org, nil
}

// ListOrganizations lists all organizations for the current user
func (c *Client) ListOrganizations() ([]Organization, error) {
	resp, err := c.request("GET", "/api/v1/organizations", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list organizations failed: %s", resp.Status)
	}

	var orgs []Organization
	if err := json.NewDecoder(resp.Body).Decode(&orgs); err != nil {
		return nil, err
	}

	return orgs, nil
}

// SetupTOTP sets up TOTP MFA for the current user
func (c *Client) SetupTOTP() (map[string]interface{}, error) {
	resp, err := c.request("POST", "/api/mfa/totp/setup", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("setup TOTP failed: %s", resp.Status)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// VerifyTOTP verifies a TOTP code
func (c *Client) VerifyTOTP(code string) (map[string]interface{}, error) {
	body := map[string]string{"code": code}
	resp, err := c.request("POST", "/api/mfa/totp/verify", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("verify TOTP failed: %s", resp.Status)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// ─── Agent Auth methods ───────────────────────────────────────────────────────

// RegisterAgent upserts a pre-registered agent principal.
// POST /api/v1/agents/register
func (c *Client) RegisterAgent(req RegisterAgentRequest) (*RegisterAgentResponse, error) {
	resp, err := c.request("POST", "/api/v1/agents/register", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkResponse(resp); err != nil {
		return nil, err
	}
	var result RegisterAgentResponse
	return &result, json.NewDecoder(resp.Body).Decode(&result)
}

// ListAgents lists all active agent principals for the tenant.
// GET /api/v1/agents
func (c *Client) ListAgents() ([]AgentPrincipal, error) {
	resp, err := c.request("GET", "/api/v1/agents", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkResponse(resp); err != nil {
		return nil, err
	}
	var result []AgentPrincipal
	return result, json.NewDecoder(resp.Body).Decode(&result)
}

// GetAgent retrieves a single agent principal by ID.
// GET /api/v1/agents/:agent_id
func (c *Client) GetAgent(agentID string) (*AgentPrincipal, error) {
	resp, err := c.request("GET", "/api/v1/agents/"+agentID, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkResponse(resp); err != nil {
		return nil, err
	}
	var result AgentPrincipal
	return &result, json.NewDecoder(resp.Body).Decode(&result)
}

// DeactivateAgent soft-deletes an agent principal (sets active=false).
// DELETE /api/v1/agents/:agent_id
func (c *Client) DeactivateAgent(agentID string) error {
	resp, err := c.request("DELETE", "/api/v1/agents/"+agentID, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return checkResponse(resp)
}

// RevokeAgentTokens immediately invalidates all active tokens for an agent
// by writing a Redis blocklist key.
// POST /api/v1/agents/:agent_id/revoke
func (c *Client) RevokeAgentTokens(agentID string) error {
	resp, err := c.request("POST", "/api/v1/agents/"+agentID+"/revoke", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return checkResponse(resp)
}

// IssueAgentToken issues a short-lived agent JWT for a specific task.
// The caller must hold an admin or service session JWT (not an agent JWT).
// POST /api/v1/agents/token
func (c *Client) IssueAgentToken(req IssueAgentTokenRequest) (*IssueAgentTokenResponse, error) {
	resp, err := c.request("POST", "/api/v1/agents/token", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkResponse(resp); err != nil {
		return nil, err
	}
	var result IssueAgentTokenResponse
	return &result, json.NewDecoder(resp.Body).Decode(&result)
}

// AuthorizeToolCall evaluates an EIAA capsule for the given tool name.
// The client must hold an agent JWT (session_type = "agent").
//
// When raiseOnDeny is true and the capsule returns Deny, an *AgentAuthzDenied
// error is returned instead of a decision with Allowed=false.
//
// POST /api/v1/agents/:agent_id/authorize
func (c *Client) AuthorizeToolCall(agentID, toolName string, argsHash *string, raiseOnDeny bool) (*AgentDecision, error) {
	body := map[string]interface{}{
		"tool_name": toolName,
	}
	if argsHash != nil {
		body["tool_args_hash"] = *argsHash
	}

	resp, err := c.request("POST", "/api/v1/agents/"+agentID+"/authorize", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkResponse(resp); err != nil {
		return nil, err
	}

	var decision AgentDecision
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		return nil, err
	}

	if !decision.Allowed && raiseOnDeny {
		return nil, &AgentAuthzDenied{
			Reason:         decision.Reason,
			AttestationRef: decision.AttestationRef,
			DecisionRef:    decision.DecisionRef,
		}
	}

	return &decision, nil
}

// HashToolArgs returns the hex-encoded SHA-256 of the canonical JSON
// serialisation of args. Pass the result as argsHash to AuthorizeToolCall
// so raw argument values never leave the caller's process.
func HashToolArgs(args map[string]interface{}) (string, error) {
	data, err := json.Marshal(args)
	if err != nil {
		return "", fmt.Errorf("HashToolArgs: marshal failed: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// RecordExecution records the completion of a tool call in the audit trail.
// POST /api/v1/agents/:agent_id/executions
func (c *Client) RecordExecution(agentID string, req RecordExecutionRequest) (*RecordExecutionResponse, error) {
	resp, err := c.request("POST", "/api/v1/agents/"+agentID+"/executions", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkResponse(resp); err != nil {
		return nil, err
	}
	var result RecordExecutionResponse
	return &result, json.NewDecoder(resp.Body).Decode(&result)
}

// GetTaskChain fetches the full causal audit chain for a task.
// GET /api/v1/audit/task/:task_id
func (c *Client) GetTaskChain(taskID string, cursor *string) (*AgentChainResponse, error) {
	endpoint := "/api/v1/audit/task/" + taskID
	if cursor != nil {
		endpoint += "?cursor=" + *cursor
	}
	resp, err := c.request("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkResponse(resp); err != nil {
		return nil, err
	}
	var result AgentChainResponse
	return &result, json.NewDecoder(resp.Body).Decode(&result)
}

// GetAgentHistory fetches all EIAA executions for an agent across all tasks.
// GET /api/v1/audit/agent/:agent_id
func (c *Client) GetAgentHistory(agentID string, cursor *string) (*AgentChainResponse, error) {
	endpoint := "/api/v1/audit/agent/" + agentID
	if cursor != nil {
		endpoint += "?cursor=" + *cursor
	}
	resp, err := c.request("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkResponse(resp); err != nil {
		return nil, err
	}
	var result AgentChainResponse
	return &result, json.NewDecoder(resp.Body).Decode(&result)
}

// SetToken sets the JWT token manually
func (c *Client) SetToken(jwt string) {
	c.JWT = jwt
}

// GetToken returns the current JWT token
func (c *Client) GetToken() string {
	return c.JWT
}

// GetManifest fetches the tenant manifest for the given organisation ID or slug.
//
// GET /api/v1/sdk/manifest?org_id=<orgId>
//
// The manifest contains branding, enabled OAuth providers, and sign-up field
// definitions needed to render auth UI dynamically.  No secrets are included.
func (c *Client) GetManifest(orgId string) (*SdkManifest, error) {
	url := fmt.Sprintf("%s/api/v1/sdk/manifest?org_id=%s", c.BaseURL, orgId)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.APIKey != "" {
		req.Header.Set("X-API-Key", c.APIKey)
	}
	if c.JWT != "" {
		req.Header.Set("Authorization", "Bearer "+c.JWT)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := checkResponse(resp); err != nil {
		return nil, err
	}

	var manifest SdkManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, err
	}

	return &manifest, nil
}
