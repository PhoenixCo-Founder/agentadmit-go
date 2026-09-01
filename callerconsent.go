package agentadmit

// Caller-Identity Consent middleware: the "classify caller, then gate the
// right independent path" recipe as one net/http middleware, so an app owner
// does not have to hand-roll it.
//
// One endpoint serves every caller class. On each request the middleware:
//
//  1. classifies the caller from the STRUCTURE of the credential (a class the
//     caller cannot self-select), before any consent check;
//  2. routes to that class's ISOLATED consent path; no path reads or inherits
//     another class's preference;
//  3. permits or denies, and stores the resolved caller class (and verdict)
//     in the request context.
//
// external_agent: an ag_at_ access token -> hosted introspection, which
// returns the external-agent consent verdict inline plus the granted scopes.
// The owner's consent verdict is evaluated BEFORE any scope check; an absent
// or malformed verdict is resolved through the Consent Ledger, fail closed.
//
// in_app_ai: your application's own server-side AI code path -> the Consent
// Ledger /consent/check for the in-app-AI class.
//
// human_session: your application's own permission model (sharing, roles,
// grants). Deferred to your existing authorization by default; opt in to a
// stored human-session switch with GateHuman.
//
// The three decisions are independent: granting one never grants another.
//
// SECURITY: this is a consent gate, not an authenticator. It classifies the
// caller and enforces the per-class CONSENT decision; it does not by itself
// authenticate a human session. Mount it AFTER your own authentication. On
// the human_session path it defers to your application's permission model and
// calls the next handler without re-authenticating, so a request carrying no
// agent token reaches your handler as a human session for your own
// authorization to judge. The external_agent path is always authenticated
// (hosted introspection); the in_app_ai path always evaluates the ledger.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// accessTokenPrefix marks an AgentAdmit access token issued through the
// user-mediated flow. Structural: the caller cannot self-select its class.
const accessTokenPrefix = "ag_at_"

// CallerConsentOptions configures CallerConsentMiddleware. The zero value
// enforces the external-agent path and defers the human path.
type CallerConsentOptions struct {
	// ResolveDataOwnerID returns your app's identifier for the data owner
	// whose resource is being accessed. Required for the in_app_ai path, and
	// for human_session when GateHuman is set. The external-agent owner comes
	// from the token, so it is not consulted there.
	ResolveDataOwnerID func(*http.Request) string

	// ClassifyNonAgent distinguishes your application's own internal-AI code
	// path from an ordinary human session, deterministically, from the
	// STRUCTURE of the credential or request context (for example an internal
	// service token), never a value the caller can set. Must return
	// CallerClassInAppAI or CallerClassHumanSession. Nil treats every
	// non-agent caller as a human session.
	ClassifyNonAgent func(*http.Request) string

	// RequiredScope, when non-empty, is enforced on the external-agent path
	// (403 insufficient_scope if the token does not carry it).
	RequiredScope string

	// ScopeGroup is an optional finer-than-class consent group for ledger
	// checks. Nil means the class-wide verdict.
	ScopeGroup *string

	// GateHuman also gates the human_session class against a stored
	// human-session consent switch. Off by default: the human path belongs to
	// your own permission model.
	GateHuman bool
}

type callerClassContextKey struct{}
type consentVerdictContextKey struct{}

// CallerClassFromContext returns the caller class CallerConsentMiddleware
// stored for this request, or "" when the middleware did not run.
func CallerClassFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(callerClassContextKey{}).(string); ok {
		return v
	}
	return ""
}

// ConsentVerdictFromContext returns the ledger verdict stored for this
// request (in_app_ai or gated-human paths), or nil.
func ConsentVerdictFromContext(ctx context.Context) *ConsentVerdict {
	if v, ok := ctx.Value(consentVerdictContextKey{}).(*ConsentVerdict); ok {
		return v
	}
	return nil
}

// ClassifyCaller classifies the caller from credential structure, before any
// consent check. An ag_at_ bearer token is an external agent; anything else
// is resolved by opts.ClassifyNonAgent (default: human_session). The class is
// derived, never self-selected by the caller.
func ClassifyCaller(r *http.Request, opts CallerConsentOptions) string {
	if strings.HasPrefix(bearerToken(r), accessTokenPrefix) {
		return CallerClassExternalAgent
	}
	if opts.ClassifyNonAgent != nil && opts.ClassifyNonAgent(r) == CallerClassInAppAI {
		return CallerClassInAppAI
	}
	return CallerClassHumanSession
}

// CallerConsentMiddleware returns a net/http middleware enforcing
// caller-identity consent at a single endpoint.
//
// Usage:
//
//	mux.Handle("/api/records",
//	    client.CallerConsentMiddleware(agentadmit.CallerConsentOptions{
//	        ClassifyNonAgent: func(r *http.Request) string {
//	            if r.Header.Get("X-Internal-AI") == internalSecret {
//	                return agentadmit.CallerClassInAppAI
//	            }
//	            return agentadmit.CallerClassHumanSession
//	        },
//	        ResolveDataOwnerID: func(r *http.Request) string { return r.URL.Query().Get("owner_id") },
//	        RequiredScope:      "read:records",
//	    })(yourHandler),
//	)
func (c *Client) CallerConsentMiddleware(opts CallerConsentOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callerClass := ClassifyCaller(r, opts)
			ctx := context.WithValue(r.Context(), callerClassContextKey{}, callerClass)
			r = r.WithContext(ctx)

			switch callerClass {
			case CallerClassExternalAgent:
				c.serveExternalAgent(w, r, next, opts)
			case CallerClassInAppAI:
				c.serveLedgerGated(w, r, next, opts, CallerClassInAppAI,
					`{"error":"consent_not_granted","caller_class":"in_app_ai","message":"The data owner has not enabled in-app AI analysis."}`)
			default:
				if opts.GateHuman {
					c.serveLedgerGated(w, r, next, opts, CallerClassHumanSession,
						`{"error":"consent_not_granted","caller_class":"human_session","message":"The data owner has not enabled this access."}`)
					return
				}
				// Defer the human path to the app's existing authorization.
				next.ServeHTTP(w, r)
			}
		})
	}
}

// serveExternalAgent enforces the external-agent path in patent FIG. 3 stage
// order: hosted introspection authenticates the token, then the owner's
// consent verdict is evaluated, and only then is the required scope checked.
// Consent comes first so a caller whose class the owner denied learns nothing
// about scope state (no granted_scopes, no step-up guidance).
//
// The hosted service deliberately omits the consent block when its
// consent-store read fails (designed degraded mode), so an absent or
// malformed verdict is NEVER a grant: it is resolved through the Consent
// Ledger for the token's owner, and an erroring ledger or unresolvable owner
// fails closed (503 consent_unavailable). Access requires a resolved verdict
// whose Granted is exactly true.
func (c *Client) serveExternalAgent(w http.ResponseWriter, r *http.Request, next http.Handler, opts CallerConsentOptions) {
	// Declare the exact exercised scope in the same hosted round trip. The
	// consent-first flag guarantees a denied caller class cannot learn scope
	// state before this middleware returns its consent 403.
	telemetry := RequestTelemetry(r, opts.RequiredScope)
	telemetry.ConsentFirst = true
	info, err := c.ValidateContextWithTelemetry(r.Context(), bearerToken(r), nil, telemetry)
	if err != nil {
		writeMiddlewareError(w, err)
		return
	}

	// Resolve the consent verdict. decodeVerifyResponse drops a malformed
	// consent block, so nil covers both absent and malformed.
	verdict := info.Consent
	if verdict == nil {
		owner := info.UserID
		if owner == "" {
			writeJSONError(w, http.StatusServiceUnavailable,
				`{"error":"consent_unavailable","message":"Introspection carried no consent verdict and no resolvable data owner"}`)
			return
		}
		verdict, err = c.CheckConsentContext(r.Context(), owner, CallerClassExternalAgent, opts.ScopeGroup)
		if err != nil {
			// Fail closed: an unreachable or erroring ledger denies, never allows.
			writeJSONError(w, http.StatusServiceUnavailable,
				`{"error":"consent_unavailable","message":"Consent check failed"}`)
			return
		}
	}
	if !verdict.Granted {
		writeJSONError(w, http.StatusForbidden,
			`{"error":"consent_not_granted","caller_class":"external_agent","message":"The data owner has not enabled external agent access."}`)
		return
	}

	// Scope check — after the consent gate, producing the same spec §6.4
	// step-up body as before (error, required_scope, granted_scopes).
	if opts.RequiredScope != "" {
		if missing := missingScopes(info.Scopes, []string{opts.RequiredScope}); len(missing) > 0 {
			scopeErr := newError(ErrCodeInsufficientScopes,
				fmt.Sprintf("token missing required scopes: %v", missing), nil)
			scopeErr.RequiredScopes = missing
			scopeErr.GrantedScopes = info.Scopes
			writeMiddlewareError(w, scopeErr)
			return
		}
	}

	// The resolved verdict travels with the TokenInfo on the request context,
	// exactly as an inline verdict does.
	info.Consent = verdict
	next.ServeHTTP(w, r.WithContext(contextWithToken(r.Context(), info)))
}

// serveLedgerGated enforces a token-less caller class (in_app_ai, or
// human_session under GateHuman) against the Consent Ledger. Fail closed: an
// unreachable or erroring ledger denies, never allows.
func (c *Client) serveLedgerGated(w http.ResponseWriter, r *http.Request, next http.Handler, opts CallerConsentOptions, callerClass, deniedBody string) {
	owner := ""
	if opts.ResolveDataOwnerID != nil {
		owner = opts.ResolveDataOwnerID(r)
	}
	if owner == "" {
		writeJSONError(w, http.StatusInternalServerError,
			`{"error":"server_error","message":"ResolveDataOwnerID is required for this caller class"}`)
		return
	}

	verdict, err := c.CheckConsentContext(r.Context(), owner, callerClass, opts.ScopeGroup)
	if err != nil {
		// Fail closed: an unreachable or erroring ledger denies, never allows.
		writeJSONError(w, http.StatusServiceUnavailable,
			`{"error":"consent_unavailable","message":"Consent check failed"}`)
		return
	}
	if !verdict.Granted {
		writeJSONError(w, http.StatusForbidden, deniedBody)
		return
	}

	ctx := context.WithValue(r.Context(), consentVerdictContextKey{}, verdict)
	next.ServeHTTP(w, r.WithContext(ctx))
}

// writeJSONError writes a JSON error body with the given status.
func writeJSONError(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write([]byte(body))
}
