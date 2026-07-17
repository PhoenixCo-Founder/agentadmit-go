package aggin

import (
	"net/http"

	"github.com/PhoenixCo-Founder/agentadmit-go"
	"github.com/gin-gonic/gin"
)

// CallerConsent returns a Gin HandlerFunc enforcing caller-identity consent
// at a single endpoint — the Gin adapter for
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
// the core middleware has already written the JSON error response and the
// Gin chain is aborted.
//
// Usage:
//
//	r.GET("/api/records", aggin.CallerConsent(client, agentadmit.CallerConsentOptions{
//	    ResolveDataOwnerID: func(req *http.Request) string { return req.URL.Query().Get("owner_id") },
//	    RequiredScope:      "read:records",
//	}), recordsHandler)
func CallerConsent(client *agentadmit.Client, opts agentadmit.CallerConsentOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		permitted := false
		inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			permitted = true
			// The core middleware attached caller class, consent verdict, and
			// (external-agent path) TokenInfo to the request context — carry
			// them into the rest of the Gin chain.
			c.Request = r
			if info := agentadmit.TokenFromContext(r.Context()); info != nil {
				c.Set(TokenInfoKey, info)
			}
		})
		client.CallerConsentMiddleware(opts)(inner).ServeHTTP(c.Writer, c.Request)
		if !permitted {
			// The core middleware wrote the denial (401/403/503) to c.Writer.
			c.Abort()
			return
		}
		c.Next()
	}
}
