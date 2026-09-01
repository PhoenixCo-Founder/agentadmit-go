// Package agecho provides AgentAdmit middleware for the Echo web framework.
//
// Import this subpackage only if you are using Echo. It has a dependency on
// github.com/labstack/echo/v4 that the core agentadmit package does not.
//
// Usage:
//
//	import (
//	    "github.com/PhoenixCo-Founder/agentadmit-go"
//	    agecho "github.com/PhoenixCo-Founder/agentadmit-go/echo"
//	)
//
//	client, _ := agentadmit.New(agentadmit.Config{APIKey: "aa_test_..."})
//
//	e := echo.New()
//	e.GET("/api/workouts", workoutsHandler, agecho.Middleware(client, "read:workouts"))
package agecho

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/PhoenixCo-Founder/agentadmit-go"
	"github.com/labstack/echo/v4"
)

// TokenInfoKey is the key used to store *agentadmit.TokenInfo in the Echo context.
const TokenInfoKey = "agentadmit_token"

// Middleware returns an Echo MiddlewareFunc that validates AgentAdmit tokens.
//
// If the request carries a Bearer token it is validated and the required
// scopes are enforced. On success, *agentadmit.TokenInfo is stored under
// TokenInfoKey in the Echo context. On failure, the handler chain is
// stopped with an appropriate HTTP error.
//
// If no Authorization header is present, the request passes through
// unchanged, allowing regular user requests to work alongside agent requests.
func Middleware(client *agentadmit.Client, requiredScopes ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			token := bearerToken(c)
			if token == "" {
				return next(c)
			}

			info, err := client.ValidateContextWithTelemetry(c.Request().Context(), token, requiredScopes,
				agentadmit.RequestTelemetry(c.Request(), requiredScopes...))
			if err != nil {
				return toEchoError(err)
			}

			c.Set(TokenInfoKey, info)
			return next(c)
		}
	}
}

// RequireAgent returns an Echo MiddlewareFunc that REQUIRES a valid
// AgentAdmit token. Requests without a Bearer token are rejected with 401.
func RequireAgent(client *agentadmit.Client, requiredScopes ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			token := bearerToken(c)
			if token == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, map[string]string{
					"error":   "missing_token",
					"message": "AgentAdmit token required",
				})
			}

			info, err := client.ValidateContextWithTelemetry(c.Request().Context(), token, requiredScopes,
				agentadmit.RequestTelemetry(c.Request(), requiredScopes...))
			if err != nil {
				return toEchoError(err)
			}

			c.Set(TokenInfoKey, info)
			return next(c)
		}
	}
}

// GetTokenInfo retrieves the validated *agentadmit.TokenInfo from the Echo
// context. Returns nil if no token was stored.
func GetTokenInfo(c echo.Context) *agentadmit.TokenInfo {
	if v := c.Get(TokenInfoKey); v != nil {
		if info, ok := v.(*agentadmit.TokenInfo); ok {
			return info
		}
	}
	return nil
}

// insufficientScopePayload builds the spec §6.4 403 body for a scope
// enforcement failure. It names the unmet scope (required_scope) and the
// scopes the token actually carries (granted_scopes) so the agent can relay
// a precise step-up request to the user, who can grant the additional scope
// through a new user-mediated connection flow.
func insufficientScopePayload(aaErr *agentadmit.AgentAdmitError) map[string]interface{} {
	granted := aaErr.GrantedScopes
	if granted == nil {
		granted = []string{}
	}
	payload := map[string]interface{}{
		"error":          "insufficient_scope",
		"granted_scopes": granted,
		"message":        "Token lacks required scopes. The user can grant additional scopes through the AgentAdmit connection settings.",
	}
	if len(aaErr.RequiredScopes) > 0 {
		rs := strings.Join(aaErr.RequiredScopes, " ")
		payload["required_scope"] = rs
		payload["message"] = fmt.Sprintf("This action requires %s scope. The user can grant additional scopes through the AgentAdmit connection settings.", rs)
	}
	return payload
}

func toEchoError(err error) error {
	var aaErr *agentadmit.AgentAdmitError
	if errors.As(err, &aaErr) {
		switch aaErr.Code {
		case agentadmit.ErrCodeInvalidToken:
			return echo.NewHTTPError(http.StatusUnauthorized, map[string]string{
				"error": "invalid_token", "message": "Token is invalid or revoked",
			})
		case agentadmit.ErrCodeInsufficientScopes:
			return echo.NewHTTPError(http.StatusForbidden, insufficientScopePayload(aaErr))
		case agentadmit.ErrCodeCallRefused:
			// Active-response refusal (e.g. bound_exceeded): the semantics and
			// body shape live in the core package.
			return echo.NewHTTPError(http.StatusForbidden, agentadmit.CallRefusedPayload(aaErr))
		case agentadmit.ErrCodeServiceUnavailable:
			return echo.NewHTTPError(http.StatusServiceUnavailable, map[string]string{
				"error": "service_unavailable", "message": "AgentAdmit service unavailable",
			})
		}
	}
	return echo.NewHTTPError(http.StatusInternalServerError, map[string]string{
		"error": "internal_error", "message": "Token validation failed",
	})
}

// bearerToken extracts the Bearer token from the Authorization header.
// The scheme match is case-insensitive per RFC 7235.
func bearerToken(c echo.Context) string {
	auth := c.Request().Header.Get("Authorization")
	if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		return auth[7:]
	}
	return ""
}
