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
//	// info.Active, info.AppID, info.Scopes, info.ExpiresAt
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

	// APIURL is the AgentAdmit management API base URL.
	// Defaults to "https://api.agentadmit.com".
	APIURL string
}

// TokenInfo contains validated token metadata returned by AgentAdmit
// after a successful introspection.
type TokenInfo struct {
	// Active indicates whether the token is currently active — valid signature,
	// not expired, not revoked, and the connection is still active.
	// Maps to the "active" field in the RFC 7662 introspection response.
	Active bool `json:"active"`

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

// ---------------------------------------------------------------------------
// Alerts types
// ---------------------------------------------------------------------------

// AlertType enumerates the supported alert types.
type AlertType = string

const (
	AlertTypeVolumeSpike              AlertType = "volume_spike"
	AlertTypeFailedScopeAttempts      AlertType = "failed_scope_attempts"
	AlertTypeBurstPattern             AlertType = "burst_pattern"
	AlertTypeStaleReactivation        AlertType = "stale_reactivation"
	AlertTypeNewScopeUsage            AlertType = "new_scope_usage"
	AlertTypeRevokedConnectionAttempt AlertType = "revoked_connection_attempt"
)

// ConfigureAlertsRequest is the body for POST /api/v1/alerts.
type ConfigureAlertsRequest struct {
	AppID                             string   `json:"app_id"`
	AlertType                         string   `json:"alert_type"`
	ConnectionID                      *string  `json:"connection_id,omitempty"`
	Enabled                           *bool    `json:"enabled,omitempty"`
	ThresholdValue                    *float64 `json:"threshold_value,omitempty"`
	ThresholdWindowMinutes            *int     `json:"threshold_window_minutes,omitempty"`
	ThresholdRatePerMinute            *float64 `json:"threshold_rate_per_minute,omitempty"`
	StaleDays                         *int     `json:"stale_days,omitempty"`
	KillSwitchEnabled                 *bool    `json:"kill_switch_enabled,omitempty"`
	KillSwitchThresholdValue          *float64 `json:"kill_switch_threshold_value,omitempty"`
	KillSwitchThresholdWindowMinutes  *int     `json:"kill_switch_threshold_window_minutes,omitempty"`
}

// ConfigureAlertsResponse is returned by POST /api/v1/alerts.
type ConfigureAlertsResponse struct {
	OK     bool                   `json:"ok"`
	Config map[string]interface{} `json:"config"`
}

// AlertEvent represents a single alert event from GET /api/v1/alerts.
type AlertEvent struct {
	ID           string                 `json:"id,omitempty"`
	AppID        string                 `json:"app_id"`
	ConnectionID string                 `json:"connection_id,omitempty"`
	AlertType    string                 `json:"alert_type"`
	TriggeredAt  string                 `json:"triggered_at"`
	Details      map[string]interface{} `json:"details,omitempty"`
}

// ListAlertsResponse is returned by GET /api/v1/alerts.
type ListAlertsResponse struct {
	Events []AlertEvent `json:"events"`
	Total  int          `json:"total"`
	Limit  int          `json:"limit"`
	Offset int          `json:"offset"`
}

// AlertConfigResponse is returned by GET /api/v1/alerts/config.
type AlertConfigResponse struct {
	AppID                string                            `json:"app_id"`
	AppLevel             map[string]interface{}            `json:"app_level"`
	ConnectionOverrides  map[string]map[string]interface{} `json:"connection_overrides"`
	AlertTypes           []string                          `json:"alert_types"`
}
