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
	// Defaults to "https://api.agentadmit.com/api/v1/verify".
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

// Verify error codes — returned by /api/v1/verify with HTTP 200 and
// active: false. Unknown codes pass through unchanged.
const (
	VerifyErrorInvalidToken        = "invalid_token"
	VerifyErrorTokenExpired        = "token_expired"
	VerifyErrorTokenRevoked        = "token_revoked"
	VerifyErrorConnectionRevoked   = "connection_revoked"
	VerifyErrorConnectionExpired   = "connection_expired"
	VerifyErrorEnvironmentMismatch = "environment_mismatch"
	VerifyErrorInsufficientScope   = "insufficient_scope"

	// VerifyErrorBoundExceeded is returned by the hosted service on an
	// otherwise-active token whose bounded capability (e.g. a spend or
	// call bound) is exhausted for this call. The SDK treats any error
	// on an active response as a denial — see ErrCodeCallRefused.
	VerifyErrorBoundExceeded = "bound_exceeded"
)

// TokenInfo contains validated token metadata returned by AgentAdmit
// after a successful introspection.
type TokenInfo struct {
	// Active indicates whether the token is currently active — valid signature,
	// not expired, not revoked, and the connection is still active.
	// Maps to the "active" field in the RFC 7662 introspection response.
	Active bool `json:"active"`

	// Sub is the token subject.
	Sub string `json:"sub,omitempty"`

	// UserID is the app-side user the connection belongs to.
	UserID string `json:"user_id,omitempty"`

	// ConnectionID identifies the agent connection the token was minted for.
	ConnectionID string `json:"connection_id,omitempty"`

	// Scopes is the list of scopes granted by the user for this token.
	Scopes []string `json:"scopes"`

	// Role is the user's role granted on the connection.
	Role string `json:"role,omitempty"`

	// Purpose is the declared purpose: the user-facing reason recorded on
	// the grant at the consent moment. Empty when none was declared (the
	// hosted service returns it as nullable). It is a review-time record
	// only, never an enforcement input; authorization decisions ride
	// scopes, connection status, and consent.
	Purpose string `json:"purpose,omitempty"`

	// UserIntent is the user-declared intent: the user's own words, typed
	// at the consent moment (distinct from Purpose, which is the app's
	// words). Empty when none was declared (the hosted service returns it
	// as nullable). It is a review-time record only, never an enforcement
	// input; authorization decisions ride scopes, connection status, and
	// consent.
	UserIntent string `json:"user_intent,omitempty"`

	// AppID is the AgentAdmit application identifier.
	AppID string `json:"app_id"`

	// JTI is the unique JWT ID of the access token.
	JTI string `json:"jti,omitempty"`

	// Exp is the token expiry as a Unix timestamp (RFC 7662 `exp`).
	Exp int64 `json:"exp,omitempty"`

	// ExpiresAt is the token expiry time in RFC 3339 format, derived from Exp.
	ExpiresAt string `json:"expires_at,omitempty"`

	// Error is set when Active is false — one of the VerifyError* constants
	// (e.g. token_expired, connection_expired, environment_mismatch).
	Error string `json:"error,omitempty"`

	// Consent is the Consent Ledger verdict for the external-agent path.
	// Additive; nil when the platform did not return one.
	Consent *ConsentVerdict `json:"consent,omitempty"`

	// Presence is the human-presence fact for the connection (WebAuthn
	// step-up). Additive; nil when the platform did not return one.
	Presence *Presence `json:"presence,omitempty"`
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
// The telemetry fields (scope_used, endpoint, method) are optional and
// omitted entirely when unknown — never sent as null or empty strings.
type verifyRequest struct {
	Token     string   `json:"token"`
	Scopes    []string `json:"scopes,omitempty"`
	ScopeUsed string   `json:"scope_used,omitempty"`
	Endpoint  string   `json:"endpoint,omitempty"`
	Method    string   `json:"method,omitempty"`
}

// VerifyTelemetry carries optional per-call audit fields sent with the
// introspection request so the hosted audit log can record which scope,
// endpoint, and method each verified call exercised. Every field is
// optional: leave a field empty ("") to omit it from the request.
//
// The SDK sanitizes each field before sending:
//   - ScopeUsed: the single scope being enforced for this call. Never a
//     joined list — leave empty when no single scope is known. Capped at
//     120 characters.
//   - Endpoint: the inbound request path, path only. Anything from the
//     first "?" or "#" on is stripped (query strings can carry PII), then
//     the result is truncated to 500 characters.
//   - Method: the HTTP method, uppercased and capped at 20 characters.
//
// Middleware populates this automatically via RequestTelemetry. Direct
// callers can pass their own values to ValidateWithTelemetry /
// ValidateContextWithTelemetry, or nil to send no telemetry.
type VerifyTelemetry struct {
	ScopeUsed string
	Endpoint  string
	Method    string
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
	AppID                            string   `json:"app_id"`
	AlertType                        string   `json:"alert_type"`
	ConnectionID                     *string  `json:"connection_id,omitempty"`
	Enabled                          *bool    `json:"enabled,omitempty"`
	ThresholdValue                   *float64 `json:"threshold_value,omitempty"`
	ThresholdWindowMinutes           *int     `json:"threshold_window_minutes,omitempty"`
	ThresholdRatePerMinute           *float64 `json:"threshold_rate_per_minute,omitempty"`
	StaleDays                        *int     `json:"stale_days,omitempty"`
	KillSwitchEnabled                *bool    `json:"kill_switch_enabled,omitempty"`
	KillSwitchThresholdValue         *float64 `json:"kill_switch_threshold_value,omitempty"`
	KillSwitchThresholdWindowMinutes *int     `json:"kill_switch_threshold_window_minutes,omitempty"`
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
	AppID               string                            `json:"app_id"`
	AppLevel            map[string]interface{}            `json:"app_level"`
	ConnectionOverrides map[string]map[string]interface{} `json:"connection_overrides"`
	AlertTypes          []string                          `json:"alert_types"`
}
