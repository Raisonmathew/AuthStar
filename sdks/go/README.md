# IDaaS Go SDK

Official Go SDK for integrating with the IDaaS Platform.

## Installation

```bash
go get github.com/idaas/go-sdk
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/idaas/go-sdk"
)

func main() {
    // Initialize client
    client := idaas.NewClient("https://api.idaas.example.com", "")
    
    // Sign up
    _, err := client.SignUp(idaas.SignUpRequest{
        Email:     "user@example.com",
        Password:  "SecurePass123!",
        FirstName: "John",
        LastName:  "Doe",
    })
    if err != nil {
        log.Fatal(err)
    }
    
    // Sign in
    result, err := client.SignIn(idaas.SignInRequest{
        Identifier: "user@example.com",
        Password:   "SecurePass123!",
    })
    if err != nil {
        log.Fatal(err)
    }
    
    // Get current user
    user, err := client.GetCurrentUser()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Welcome %s!\n", user.FirstName)
    
    // Create organization
    org, err := client.CreateOrganization("My Company", "")
    if err != nil {
        log.Fatal(err)
    }
    
    // List organizations
    orgs, err := client.ListOrganizations()
    if err != nil {
        log.Fatal(err)
    }
}
```

## API Reference

### Client

```go
client := idaas.NewClient(baseURL, apiKey)
```

### Authentication

- `SignUp(req SignUpRequest) (map[string]interface{}, error)` - Create account
- `SignIn(req SignInRequest) (map[string]interface{}, error)` - Authenticate user
- `SignOut() error` - Sign out current user

### Users

- `GetCurrentUser() (*User, error)` - Get current user profile
- `UpdateUser(updates map[string]interface{}) (*User, error)` - Update user profile

### Organizations

- `CreateOrganization(name, slug string) (*Organization, error)` - Create organization
- `ListOrganizations() ([]Organization, error)` - List user's organizations

### MFA

- `SetupTOTP() (map[string]interface{}, error)` - Setup TOTP MFA
- `VerifyTOTP(code string) (map[string]interface{}, error)` - Verify TOTP code

### Token Management

- `SetToken(jwt string)` - Set JWT token manually
- `GetToken() string` - Get current JWT token

## Types

### User

```go
type User struct {
    ID            string `json:"id"`
    Email         string `json:"email"`
    FirstName     string `json:"firstName,omitempty"`
    LastName      string `json:"lastName,omitempty"`
    EmailVerified bool   `json:"emailVerified"`
    MFAEnabled    bool   `json:"mfaEnabled"`
}
```

### Organization

```go
type Organization struct {
    ID        string `json:"id"`
    Name      string `json:"name"`
    Slug      string `json:"slug"`
    CreatedAt string `json:"createdAt"`
}
```

## License

MIT
