package agecho

import (
	"net/http"

	"github.com/PhoenixCo-Founder/agentadmit-go"
	"github.com/labstack/echo/v4"
)

// CallerConsent returns an Echo MiddlewareFunc enforcing caller-identity
// consent at a single endpoint — the Echo adapter for
// (*agentadmit.Client).CallerConsentMiddleware.
//
// It is a thin wrapper around the core net/http middleware rather than a
// reimplementation, so the security-ordering semantics (consent verdict
// BEFORE scope check; absent/malformed verdict resolved through the Consent
// Ledger, fail closed) live in exactly one place and cannot drift per
// framework.
//
// On a permitted request the caller class and any resolved consent verdict
// are available via agentadmit.CallerClassFromContext /
// agentadmit.ConsentVerdictFromContext on the request context, and for the
// external-agent path the validated *agentadmit.TokenInfo is additionally
// stored under TokenInfoKey (readable with GetTokenInfo). On a denied request
// the core middleware has already written the JSON error response.
//
// Usage:
//
//	e.GET("/api/records", recordsHandler, agecho.CallerConsent(client, agentadmit.CallerConsentOptions{
//	    ResolveDataOwnerID: func(req *http.Request) string { return req.URL.Query().Get("owner_id") },
//	    RequiredScope:      "read:records",
//	}))
func CallerConsent(client *agentadmit.Client, opts agentadmit.CallerConsentOptions) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			permitted := false
			var nextErr error
			inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				permitted = true
				// The core middleware attached caller class, consent verdict,
				// and (external-agent path) TokenInfo to the request context —
				// carry them into the rest of the Echo chain.
				c.SetRequest(r)
				if info := agentadmit.TokenFromContext(r.Context()); info != nil {
					c.Set(TokenInfoKey, info)
				}
				nextErr = next(c)
			})
			client.CallerConsentMiddleware(opts)(inner).ServeHTTP(c.Response(), c.Request())
			if !permitted {
				// The core middleware wrote the denial (401/403/503) directly
				// to the response; nothing further for Echo to handle.
				return nil
			}
			return nextErr
		}
	}
}
