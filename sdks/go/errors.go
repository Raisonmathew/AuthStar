package authstar

import "fmt"

// AuthstarError represents an error response from the AuthStar API.
type AuthstarError struct {
	StatusCode int    `json:"status_code"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}

func (e *AuthstarError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("authstar error (status %d, code %s): %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("authstar error (status %d): %s", e.StatusCode, e.Message)
}
