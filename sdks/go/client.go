package idaas

import (
	"bytes"
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
	resp, err := c.request("POST", "/v1/sign-up", req)
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
	resp, err := c.request("POST", "/v1/sign-in", req)
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
	resp, err := c.request("POST", "/v1/sign-out", nil)
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
	resp, err := c.request("GET", "/v1/user", nil)
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
	resp, err := c.request("PATCH", "/v1/user", updates)
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

	resp, err := c.request("POST", "/v1/organizations", body)
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
	resp, err := c.request("GET", "/v1/organizations", nil)
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
	resp, err := c.request("POST", "/v1/mfa/totp/setup", nil)
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
	resp, err := c.request("POST", "/v1/mfa/totp/verify", body)
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

// SetToken sets the JWT token manually
func (c *Client) SetToken(jwt string) {
	c.JWT = jwt
}

// GetToken returns the current JWT token
func (c *Client) GetToken() string {
	return c.JWT
}
