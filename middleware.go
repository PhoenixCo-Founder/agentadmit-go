package agentadmit

import (
	"errors"
	"net/http"
	"strings"
)

// ---------------------------------------------------------------------------
// net/http middleware (no external dependencies)
// ---------------------------------------------------------------------------

// Middleware returns a net/http middleware that validates AgentAdmit tokens
// on every request that carries a Bearer token.
//
// If the Authorization header contains a Bearer token:
//   - The token is validated via AgentAdmit's introspection API.
//   - Required scopes (if any) are enforced.
//   - On success, TokenInfo is stored in the request context and the next
//     handler is called.
//   - On failure, the handler is NOT called and an appropriate HTTP error is
//     written (401 or 403).
//
// If no Authorization header is present, the request passes through
// unchanged. This allows regular user requests (with your existing auth) to
// work alongside agent requests.
//
// Usage:
//
//	client, _ := agentadmit.New(agentadmit.Config{APIKey: "aa_test_..."})
//	mux.Handle("/api/workouts",
//	    client.Middleware("read:workouts")(yourHandler),
//	)
func (c *Client) Middleware(requiredScopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearerToken(r)
			if token == "" {
				// No AgentAdmit token — pass through to existing auth.
				next.ServeHTTP(w, r)
				return
			}

			info, err := c.ValidateContext(r.Context(), token, requiredScopes)
			if err != nil {
				writeMiddlewareError(w, err)
				return
			}

			// Attach TokenInfo to context for downstream handlers.
			ctx := contextWithToken(r.Context(), info)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAgentMiddleware returns a net/http middleware that REQUIRES a valid
// AgentAdmit token. Unlike Middleware, this rejects requests that have no
// Bearer token at all (returns 401).
//
// Use this for endpoints that should ONLY be accessible by AI agents, not
// regular users.
func (c *Client) RequireAgentMiddleware(requiredScopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearerToken(r)
			if token == "" {
				http.Error(w, `{"error":"missing_token","message":"AgentAdmit token required"}`,
					http.StatusUnauthorized)
				return
			}

			info, err := c.ValidateContext(r.Context(), token, requiredScopes)
			if err != nil {
				writeMiddlewareError(w, err)
				return
			}

			ctx := contextWithToken(r.Context(), info)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// writeMiddlewareError writes an appropriate HTTP error response based on the
// AgentAdmitError code.
func writeMiddlewareError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")

	var aaErr *AgentAdmitError
	if errors.As(err, &aaErr) {
		switch aaErr.Code {
		case ErrCodeInvalidToken:
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid_token","message":"Token is invalid or revoked"}`))
		case ErrCodeInsufficientScopes:
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"insufficient_scope","message":"Token lacks required scopes"}`))
		case ErrCodeServiceUnavailable:
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"error":"service_unavailable","message":"AgentAdmit service unavailable"}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"internal_error","message":"Token validation failed"}`))
		}
		return
	}

	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(`{"error":"internal_error","message":"Token validation failed"}`))
}

// bearerToken extracts the Bearer token from the Authorization header.
// Returns "" if none is present.
func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}
