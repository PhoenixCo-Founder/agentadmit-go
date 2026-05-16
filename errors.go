package agentadmit

import (
	"errors"
	"fmt"
)

// ErrorCode classifies AgentAdmit errors so callers can respond appropriately.
type ErrorCode string

const (
	// ErrCodeInvalidToken is returned when the token does not exist, has
	// expired, or has been revoked.
	ErrCodeInvalidToken ErrorCode = "invalid_token"

	// ErrCodeInsufficientScopes is returned when the token is valid but
	// lacks one or more of the required scopes.
	ErrCodeInsufficientScopes ErrorCode = "insufficient_scopes"

	// ErrCodeServiceUnavailable is returned when the AgentAdmit introspection
	// endpoint is unreachable or returns a 5xx response.
	ErrCodeServiceUnavailable ErrorCode = "service_unavailable"

	// ErrCodeConfig is returned when the SDK is misconfigured (e.g., missing
	// API key or invalid URL).
	ErrCodeConfig ErrorCode = "config_error"

	// ErrCodeRateLimit is returned when the AgentAdmit introspection endpoint
	// returns HTTP 429 and all retry attempts are exhausted.
	ErrCodeRateLimit ErrorCode = "rate_limit_exceeded"
)

// AgentAdmitError is the structured error type returned by all SDK methods.
// Use errors.As to extract it:
//
//	var aaErr *agentadmit.AgentAdmitError
//	if errors.As(err, &aaErr) {
//	    switch aaErr.Code {
//	    case agentadmit.ErrCodeInvalidToken:
//	        // return 401
//	    case agentadmit.ErrCodeInsufficientScopes:
//	        // return 403
//	    }
//	}
type AgentAdmitError struct {
	// Code classifies the error.
	Code ErrorCode

	// Message is a human-readable description of the error.
	Message string

	// Cause is the underlying error, if any.
	Cause error
}

// Error implements the error interface.
func (e *AgentAdmitError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("agentadmit [%s]: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("agentadmit [%s]: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause, enabling errors.Is / errors.As chains.
func (e *AgentAdmitError) Unwrap() error {
	return e.Cause
}

// newError creates an AgentAdmitError with the given code, message, and cause.
func newError(code ErrorCode, message string, cause error) *AgentAdmitError {
	return &AgentAdmitError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// IsInvalidToken returns true if err represents a token validation failure.
func IsInvalidToken(err error) bool {
	var aaErr *AgentAdmitError
	return errors.As(err, &aaErr) && aaErr.Code == ErrCodeInvalidToken
}

// IsInsufficientScopes returns true if err represents a scope enforcement
// failure (token is valid but lacks required scopes).
func IsInsufficientScopes(err error) bool {
	var aaErr *AgentAdmitError
	return errors.As(err, &aaErr) && aaErr.Code == ErrCodeInsufficientScopes
}

// IsServiceUnavailable returns true if err represents a failure to reach
// the AgentAdmit introspection service.
func IsServiceUnavailable(err error) bool {
	var aaErr *AgentAdmitError
	return errors.As(err, &aaErr) && aaErr.Code == ErrCodeServiceUnavailable
}

// RateLimitError is returned when the AgentAdmit introspection endpoint
// responds with HTTP 429 and all retry attempts have been exhausted.
//
// Use errors.As to extract it and inspect the rate-limit headers:
//
//	var rlErr *agentadmit.RateLimitError
//	if errors.As(err, &rlErr) {
//	    // rlErr.RetryAfter, rlErr.Limit, rlErr.Remaining, rlErr.Reset
//	}
type RateLimitError struct {
	// RetryAfter is the value of the Retry-After header in seconds, or -1 if absent.
	RetryAfter float64
	// Limit is the X-RateLimit-Limit header value, or -1 if absent.
	Limit int
	// Remaining is the X-RateLimit-Remaining header value, or -1 if absent.
	Remaining int
	// Reset is the X-RateLimit-Reset header value (Unix timestamp), or -1 if absent.
	Reset int64
	// MaxRetries is the number of retry attempts that were made before giving up.
	MaxRetries int
}

// Error implements the error interface.
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("agentadmit [%s]: rate limit exceeded after %d retries (retry_after=%.0fs)",
		ErrCodeRateLimit, e.MaxRetries, e.RetryAfter)
}

// IsRateLimit returns true if err is a *RateLimitError.
func IsRateLimit(err error) bool {
	var rlErr *RateLimitError
	return errors.As(err, &rlErr)
}
