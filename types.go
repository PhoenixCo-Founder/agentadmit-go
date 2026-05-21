// Package agentadmit provides the official Go SDK for AgentAdmit —
// user-mediated AI agent authorization.
//
// Quick start:
//
//	client, err := agentadmit.New(agentadmit.Config{
//	    APIKey: os.Getenv("AGENTADMIT_API_KEY"),
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	info, err := client.Validate(token, []string{"read:workouts"})
//	if err != nil {
//	    // handle error
//	}
//	// info.AppID, info.Scopes, info.ExpiresAt
package agentadmit

import "time"

// Config holds the configuration for an AgentAdmit client.
type Config struct {
	// APIKey is your AgentAdmit API key (aa_test_... or aa_live_...).
	// Required.
	APIKey string

	// VerifyURL is the AgentAdmit introspection endpoint.
	// Defaults to "https://api.agentadmit.com/v1/verify".
	VerifyURL string

	// Timeout is the maximum duration for introspection HTTP calls.
	// Defaults to 5 seconds.
	Timeout time.Duration

	// MaxRetries is the maximum number of retry attempts on HTTP 429 responses.
	// Each retry uses exponential backoff with jitter (start 1s, cap 30s, +0–500ms jitter).
	// Defaults to 3. Set to 0 to disable retries.
	MaxRetries int
}

// TokenInfo contains validated token metadata returned by AgentAdmit
// after a successful introspection.
type TokenInfo struct {
	// Valid indicates whether the token was accepted by AgentAdmit.
	// Maps to the "active" field in the RFC 7662 introspection response.
	Valid bool `json:"active"`

	// Scopes is the list of scopes granted by the user for this token.
	Scopes []string `json:"scopes"`

	// AppID is the AgentAdmit application identifier.
	AppID string `json:"app_id"`

	// ExpiresAt is the token expiry time in RFC 3339 format.
	ExpiresAt string `json:"expires_at"`
}

// ValidationResult is the full response envelope from the AgentAdmit
// introspection API.
type ValidationResult struct {
	TokenInfo
	// RawResponse holds the full JSON map returned by the API, in case
	// callers need fields not captured in TokenInfo.
	RawResponse map[string]interface{}
}

// verifyRequest is the JSON body sent to the AgentAdmit verify endpoint.
type verifyRequest struct {
	Token  string   `json:"token"`
	Scopes []string `json:"scopes,omitempty"`
}

// contextKey is the unexported type used to store TokenInfo in a
// context.Context, preventing collisions with other packages.
type contextKey struct{}

// tokenContextKey is the singleton key used to store/retrieve TokenInfo
// from a context.
var tokenContextKey = contextKey{}
