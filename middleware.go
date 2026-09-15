package agentadmit

import (
	"encoding/json"
	"errors"
	"fmt"
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
	return c.MiddlewareWithOptions(ScopeOptions{}, requiredScopes...)
}

// MiddlewareWithOptions is Middleware plus confirm-each-time options.
//
// With opts.ActionSummary set, the middleware describes THIS action for the
// human and sends a sha256 digest of the raw request body with the verify
// call, so the hosted service can stage (and later match) a confirmation for
// exactly this action. The body is re-buffered, so the handler still reads it
// in full. When the hosted service refuses with confirmation_required the
// handler is never invoked and the agent receives 403 with the confirmation
// link; the agent's retry carrying X-AgentAdmit-Action-Attestation is
// forwarded automatically (that header is forwarded on every route, with or
// without options).
//
//	mux.Handle("/api/payments", client.MiddlewareWithOptions(
//	    agentadmit.ScopeOptions{
//	        ActionSummary: func(r *http.Request, body []byte) string {
//	            return "Pay Alex $50"
//	        },
//	    },
//	    "write:payments",
//	)(payHandler))
func (c *Client) MiddlewareWithOptions(opts ScopeOptions, requiredScopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearerToken(r)
			if token == "" {
				// No AgentAdmit token — pass through to existing auth.
				next.ServeHTTP(w, r)
				return
			}

			info, err := c.ValidateContextWithTelemetry(r.Context(), token, requiredScopes,
				RequestTelemetryWithOptions(r, opts, requiredScopes...))
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
	return c.RequireAgentMiddlewareWithOptions(ScopeOptions{}, requiredScopes...)
}

// RequireAgentMiddlewareWithOptions is RequireAgentMiddleware plus
// confirm-each-time options. See MiddlewareWithOptions for the semantics.
func (c *Client) RequireAgentMiddlewareWithOptions(opts ScopeOptions, requiredScopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearerToken(r)
			if token == "" {
				http.Error(w, `{"error":"missing_token","message":"AgentAdmit token required"}`,
					http.StatusUnauthorized)
				return
			}

			info, err := c.ValidateContextWithTelemetry(r.Context(), token, requiredScopes,
				RequestTelemetryWithOptions(r, opts, requiredScopes...))
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
			w.Write(insufficientScopeBody(aaErr))
		case ErrCodeCallRefused:
			w.WriteHeader(http.StatusForbidden)
			w.Write(callRefusedBody(aaErr))
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

// insufficientScopeBody builds the spec §6.4 403 body for a scope-enforcement
// failure. It names the unmet scope (required_scope) and the scopes the token
// actually carries (granted_scopes) so the agent can relay a precise step-up
// request to the user, who can grant the additional scope through a new
// user-mediated connection flow.
func insufficientScopeBody(aaErr *AgentAdmitError) []byte {
	granted := aaErr.GrantedScopes
	if granted == nil {
		granted = []string{}
	}
	body := struct {
		Error         string   `json:"error"`
		RequiredScope string   `json:"required_scope,omitempty"`
		GrantedScopes []string `json:"granted_scopes"`
		Message       string   `json:"message"`
	}{
		Error:         "insufficient_scope",
		GrantedScopes: granted,
		Message:       "Token lacks required scopes. The user can grant additional scopes through the AgentAdmit connection settings.",
	}
	if len(aaErr.RequiredScopes) > 0 {
		body.RequiredScope = strings.Join(aaErr.RequiredScopes, " ")
		body.Message = fmt.Sprintf("This action requires %s scope. The user can grant additional scopes through the AgentAdmit connection settings.", body.RequiredScope)
	}
	b, err := json.Marshal(body)
	if err != nil {
		return []byte(`{"error":"insufficient_scope","message":"Token lacks required scopes"}`)
	}
	return b
}

// CallRefusedPayload builds the 403 response body for an active-response
// refusal (Code == ErrCodeCallRefused). For a bound_exceeded refusal the
// hosted error_description/bound/renewal fields are passed through verbatim;
// for a confirmation_required refusal it carries the strictly typed
// confirmation block (plus attestation_status/attestation_description when
// present) so the agent can hand the link to the human;
// for unknown refusal codes the body is the generic fail-closed shape
// {error, error_description}. Exported so the gin and echo adapters share
// the exact same body semantics as the net/http middleware.
func CallRefusedPayload(aaErr *AgentAdmitError) map[string]interface{} {
	code := aaErr.VerifyError
	if code == "" {
		code = string(ErrCodeCallRefused)
	}
	payload := map[string]interface{}{"error": code}
	if aaErr.ErrorDescription != "" {
		payload["error_description"] = aaErr.ErrorDescription
	}
	if len(aaErr.Bound) > 0 {
		payload["bound"] = aaErr.Bound
	}
	// Confirm-each-time: the staged ceremony the agent needs to get a human
	// to complete, plus why a presented attestation was not accepted.
	if aaErr.Confirmation != nil {
		payload["confirmation"] = aaErr.Confirmation
	}
	if aaErr.AttestationStatus != "" {
		payload["attestation_status"] = aaErr.AttestationStatus
	}
	if aaErr.AttestationDescription != "" {
		payload["attestation_description"] = aaErr.AttestationDescription
	}
	if len(aaErr.Renewal) > 0 {
		payload["renewal"] = aaErr.Renewal
	}
	return payload
}

// callRefusedBody marshals CallRefusedPayload for the net/http middleware.
func callRefusedBody(aaErr *AgentAdmitError) []byte {
	b, err := json.Marshal(CallRefusedPayload(aaErr))
	if err != nil {
		return []byte(`{"error":"call_refused","error_description":"Call refused by the authorization service."}`)
	}
	return b
}

// bearerToken extracts the Bearer token from the Authorization header.
// The scheme match is case-insensitive per RFC 7235 §2.1 ("token68" scheme
// names are case-insensitive). Returns "" if none is present.
func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	// Use a case-insensitive prefix check: accept "bearer ", "Bearer ", etc.
	if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		return auth[7:]
	}
	return ""
}
