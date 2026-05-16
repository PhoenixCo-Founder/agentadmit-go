// Package aggin provides AgentAdmit middleware for the Gin web framework.
//
// Import this subpackage only if you are using Gin. It has a dependency on
// github.com/gin-gonic/gin that the core agentadmit package does not.
//
// Usage:
//
//	import (
//	    "github.com/agentadmit/agentadmit-go"
//	    aggin "github.com/agentadmit/agentadmit-go/gin"
//	)
//
//	client, _ := agentadmit.New(agentadmit.Config{APIKey: "aa_test_..."})
//
//	r := gin.Default()
//	r.GET("/api/workouts", agin.Middleware(client, "read:workouts"), workoutsHandler)
package aggin

import (
	"errors"
	"strings"

	"github.com/agentadmit/agentadmit-go"
	"github.com/gin-gonic/gin"
)

// TokenInfoKey is the key used to store *agentadmit.TokenInfo in the Gin context.
const TokenInfoKey = "agentadmit_token"

// Middleware returns a Gin HandlerFunc that validates AgentAdmit tokens.
//
// If the request carries a Bearer token it is validated and the required
// scopes are enforced. On success, *agentadmit.TokenInfo is stored under
// TokenInfoKey in the Gin context. On failure, the handler chain is aborted
// with an appropriate HTTP status.
//
// If no Authorization header is present, the request passes through
// unchanged, allowing regular user requests to work alongside agent requests.
func Middleware(client *agentadmit.Client, requiredScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := bearerToken(c)
		if token == "" {
			c.Next()
			return
		}

		info, err := client.ValidateContext(c.Request.Context(), token, requiredScopes)
		if err != nil {
			abortWithError(c, err)
			return
		}

		c.Set(TokenInfoKey, info)
		c.Next()
	}
}

// RequireAgent returns a Gin HandlerFunc that REQUIRES a valid AgentAdmit
// token. Requests without a Bearer token are rejected with 401.
func RequireAgent(client *agentadmit.Client, requiredScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := bearerToken(c)
		if token == "" {
			c.AbortWithStatusJSON(401, gin.H{
				"error":   "missing_token",
				"message": "AgentAdmit token required",
			})
			return
		}

		info, err := client.ValidateContext(c.Request.Context(), token, requiredScopes)
		if err != nil {
			abortWithError(c, err)
			return
		}

		c.Set(TokenInfoKey, info)
		c.Next()
	}
}

// GetTokenInfo retrieves the validated *agentadmit.TokenInfo from the Gin
// context. Returns nil if no token was stored (request was not agent-originated).
func GetTokenInfo(c *gin.Context) *agentadmit.TokenInfo {
	if v, exists := c.Get(TokenInfoKey); exists {
		if info, ok := v.(*agentadmit.TokenInfo); ok {
			return info
		}
	}
	return nil
}

func abortWithError(c *gin.Context, err error) {
	var aaErr *agentadmit.AgentAdmitError
	if errors.As(err, &aaErr) {
		switch aaErr.Code {
		case agentadmit.ErrCodeInvalidToken:
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid_token", "message": "Token is invalid or revoked"})
		case agentadmit.ErrCodeInsufficientScopes:
			c.AbortWithStatusJSON(403, gin.H{"error": "insufficient_scope", "message": "Token lacks required scopes"})
		case agentadmit.ErrCodeServiceUnavailable:
			c.AbortWithStatusJSON(503, gin.H{"error": "service_unavailable", "message": "AgentAdmit service unavailable"})
		default:
			c.AbortWithStatusJSON(500, gin.H{"error": "internal_error", "message": "Token validation failed"})
		}
		return
	}
	c.AbortWithStatusJSON(500, gin.H{"error": "internal_error", "message": "Token validation failed"})
}

func bearerToken(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}
