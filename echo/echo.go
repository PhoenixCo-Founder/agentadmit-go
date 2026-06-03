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

			info, err := client.ValidateContext(c.Request().Context(), token, requiredScopes)
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

			info, err := client.ValidateContext(c.Request().Context(), token, requiredScopes)
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

func toEchoError(err error) error {
	var aaErr *agentadmit.AgentAdmitError
	if errors.As(err, &aaErr) {
		switch aaErr.Code {
		case agentadmit.ErrCodeInvalidToken:
			return echo.NewHTTPError(http.StatusUnauthorized, map[string]string{
				"error": "invalid_token", "message": "Token is invalid or revoked",
			})
		case agentadmit.ErrCodeInsufficientScopes:
			return echo.NewHTTPError(http.StatusForbidden, map[string]string{
				"error": "insufficient_scope", "message": "Token lacks required scopes",
			})
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

func bearerToken(c echo.Context) string {
	auth := c.Request().Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}
