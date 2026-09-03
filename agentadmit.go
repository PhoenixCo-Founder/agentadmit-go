package agentadmit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultVerifyURL is the AgentAdmit introspection endpoint.
	DefaultVerifyURL = "https://api.agentadmit.com/api/v1/verify"

	// DefaultTimeout is the default HTTP timeout for introspection calls.
	DefaultTimeout = 5 * time.Second
)

// DefaultMaxRetries is the default number of retry attempts on HTTP 429.
const DefaultMaxRetries = 3

const (
	// maxRetryWaitMs caps any single retry wait — including a
	// server-supplied Retry-After, which is untrusted input.
	maxRetryWaitMs = 30_000.0

	// maxRetryBudgetMs caps cumulative wait across all retries of a
	// single verify call.
	maxRetryBudgetMs = 120_000.0
)

// Client is the AgentAdmit SDK client. Create one via New() and reuse it
// across requests. It is safe for concurrent use.
type Client struct {
	apiKey     string
	verifyURL  string
	apiURLStr  string
	http       *http.Client
	maxRetries int

	// sleep waits for d or until ctx is cancelled. Overridable in tests so
	// retry behavior can be asserted without real waits.
	sleep func(ctx context.Context, d time.Duration) error
}

// requireHTTPS returns an error if rawURL does not use https, unless the host
// is localhost, 127.0.0.1, or [::1] (in which case plain http is also
// accepted to support local development and tests). An empty string is allowed
// so callers can omit optional URL fields.
func requireHTTPS(rawURL, fieldName string) error {
	if rawURL == "" {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return newError(ErrCodeConfig, fmt.Sprintf("%s is not a valid URL: %v", fieldName, err), err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
	}
	return newError(ErrCodeConfig,
		fmt.Sprintf("%s must use https (got %q); http is only allowed for localhost/127.0.0.1/[::1]", fieldName, u.Scheme), nil)
}

// New creates a new AgentAdmit Client with the provided Config.
// Returns ErrCodeConfig if the API key is empty or doesn't carry an
// aa_test_/aa_live_ prefix, or if any URL is not https (except
// http on localhost / 127.0.0.1 / [::1]).
func New(cfg Config) (*Client, error) {
	if cfg.APIKey == "" {
		return nil, newError(ErrCodeConfig, "APIKey is required", nil)
	}
	// Validate the prefix without ever echoing the key itself.
	if !strings.HasPrefix(cfg.APIKey, "aa_test_") && !strings.HasPrefix(cfg.APIKey, "aa_live_") {
		return nil, newError(ErrCodeConfig, "APIKey must start with 'aa_test_' or 'aa_live_'", nil)
	}

	apiURLStr := cfg.APIURL
	if apiURLStr == "" {
		apiURLStr = DefaultAPIURL
	}
	if err := requireHTTPS(apiURLStr, "APIURL"); err != nil {
		return nil, err
	}

	// One hosted-service origin, not two. An operator who points APIURL
	// somewhere else (staging, a local rig) and leaves VerifyURL unset
	// expects verify to follow — otherwise management calls go to one
	// service while every per-call verify silently goes to production
	// (caught on the TrainerTracer dogfood rig, Sep 3, 2026). An explicitly
	// set VerifyURL always wins.
	verifyURL := cfg.VerifyURL
	if verifyURL == "" {
		verifyURL = DefaultVerifyURL
		if base := strings.TrimRight(apiURLStr, "/"); base != strings.TrimRight(DefaultAPIURL, "/") {
			verifyURL = base + "/api/v1/verify"
		}
	}
	if err := requireHTTPS(verifyURL, "VerifyURL"); err != nil {
		return nil, err
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	maxRetries := cfg.MaxRetries
	if maxRetries == 0 {
		maxRetries = DefaultMaxRetries
	}

	return &Client{
		apiKey:     cfg.APIKey,
		verifyURL:  verifyURL,
		apiURLStr:  apiURLStr,
		http:       &http.Client{Timeout: timeout},
		maxRetries: maxRetries,
		sleep: func(ctx context.Context, d time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d):
				return nil
			}
		},
	}, nil
}

// Validate sends the agent token to AgentAdmit's introspection endpoint and
// verifies it has the required scopes.
//
//   - token: the AgentAdmit access token presented by the AI agent
//     (typically extracted from the Authorization header).
//   - requiredScopes: scopes that must be present on the token.
//     Pass nil or an empty slice to skip scope enforcement (token valid = pass).
//
// Returns *TokenInfo on success, or an *AgentAdmitError on failure.
// The error Code distinguishes between ErrCodeInvalidToken,
// ErrCodeInsufficientScopes, and ErrCodeServiceUnavailable.
func (c *Client) Validate(token string, requiredScopes []string) (*TokenInfo, error) {
	return c.ValidateContext(context.Background(), token, requiredScopes)
}

// ValidateContext is the context-aware variant of Validate. Prefer this in
// HTTP handlers so the introspection call respects request cancellation.
func (c *Client) ValidateContext(ctx context.Context, token string, requiredScopes []string) (*TokenInfo, error) {
	return c.ValidateContextWithTelemetry(ctx, token, requiredScopes, nil)
}

// ValidateWithTelemetry is Validate plus optional per-call audit telemetry
// (scope_used, endpoint, method) sent with the introspection request so the
// hosted audit log records what each verified call exercised. Pass nil to
// send no telemetry. See VerifyTelemetry for field semantics.
func (c *Client) ValidateWithTelemetry(token string, requiredScopes []string, tel *VerifyTelemetry) (*TokenInfo, error) {
	return c.ValidateContextWithTelemetry(context.Background(), token, requiredScopes, tel)
}

// ValidateContextWithTelemetry is the context-aware variant of
// ValidateWithTelemetry. The middleware in this package and the gin/echo
// subpackages call it with telemetry derived from the inbound request via
// RequestTelemetry.
func (c *Client) ValidateContextWithTelemetry(ctx context.Context, token string, requiredScopes []string, tel *VerifyTelemetry) (*TokenInfo, error) {
	if token == "" {
		return nil, newError(ErrCodeInvalidToken, "token is empty", nil)
	}

	// Build request body — telemetry fields are sanitized and omitted when
	// unknown (omitempty; never null / empty string).
	reqBody := verifyRequest{
		Token:  token,
		Scopes: requiredScopes,
	}
	applyTelemetry(&reqBody, tel)
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, newError(ErrCodeConfig, "failed to marshal verify request", err)
	}

	// Retry loop — handles 429 with exponential backoff + jitter.
	delayMs := 1000.0 // initial backoff: 1 second (in ms)
	waitedMs := 0.0   // cumulative wait across retries

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.verifyURL, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, newError(ErrCodeConfig, "failed to build HTTP request", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("User-Agent", userAgent)

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, newError(ErrCodeServiceUnavailable, "introspection request failed", err)
		}

		if resp.StatusCode == 429 {
			// Parse rate-limit headers
			retryAfter := parseFloatHeader(resp, "Retry-After")
			rlLimit := parseIntHeader(resp, "X-RateLimit-Limit")
			rlRemaining := parseIntHeader(resp, "X-RateLimit-Remaining")
			rlReset := parseInt64Header(resp, "X-RateLimit-Reset")
			resp.Body.Close()

			if attempt >= c.maxRetries {
				return nil, &RateLimitError{
					RetryAfter: retryAfter,
					Limit:      rlLimit,
					Remaining:  rlRemaining,
					Reset:      rlReset,
					MaxRetries: c.maxRetries,
				}
			}

			// Compute wait: Retry-After beats exponential backoff, but both
			// are capped — Retry-After is untrusted server input and must
			// not pin the caller.
			requestedMs := delayMs
			if retryAfter >= 0 {
				requestedMs = retryAfter * 1000
			}
			waitMs := math.Min(math.Max(requestedMs, 0), maxRetryWaitMs)
			jitterMs := rand.Float64() * 500 // 0–500 ms

			if waitedMs+waitMs+jitterMs > maxRetryBudgetMs {
				return nil, &RateLimitError{
					RetryAfter: retryAfter,
					Limit:      rlLimit,
					Remaining:  rlRemaining,
					Reset:      rlReset,
					MaxRetries: attempt,
				}
			}
			waitedMs += waitMs + jitterMs
			totalWait := time.Duration((waitMs + jitterMs) * float64(time.Millisecond))

			if err := c.sleep(ctx, totalWait); err != nil {
				return nil, newError(ErrCodeServiceUnavailable, "context cancelled during rate-limit retry", err)
			}

			delayMs = math.Min(delayMs*2, 30_000)
			continue
		}

		// Non-429 response — read and process
		respBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, newError(ErrCodeServiceUnavailable, "failed to read introspection response", err)
		}

		if resp.StatusCode >= 500 {
			return nil, newError(ErrCodeServiceUnavailable,
				fmt.Sprintf("AgentAdmit service returned %d", resp.StatusCode), nil)
		}

		// Only treat a response as valid when the HTTP status is 2xx.
		// A 4xx response (e.g. 400 {"active":true}) must never be honored —
		// it indicates the request was malformed or the token was rejected
		// at the transport level.
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, newError(ErrCodeInvalidToken,
				fmt.Sprintf("introspection returned non-2xx status %d", resp.StatusCode), nil)
		}

		info, err := decodeVerifyResponse(respBytes)
		if err != nil {
			return nil, newError(ErrCodeServiceUnavailable, "failed to decode introspection response", err)
		}

		// Derive ExpiresAt from the RFC 7662 `exp` claim for back-compat.
		if info.ExpiresAt == "" && info.Exp > 0 {
			info.ExpiresAt = time.Unix(info.Exp, 0).UTC().Format(time.RFC3339)
		}

		if !info.Active {
			// info.Error is one of the Verify* constants (e.g. token_expired,
			// connection_expired, environment_mismatch); unknown codes pass
			// through. insufficient_scope maps to the scopes error class.
			reason := info.Error
			if reason == "" {
				reason = VerifyErrorInvalidToken
			}
			if reason == VerifyErrorInsufficientScope {
				scopeErr := newError(ErrCodeInsufficientScopes, "token is not active: "+reason, nil)
				scopeErr.GrantedScopes = info.Scopes
				return nil, scopeErr
			}
			return nil, newError(ErrCodeInvalidToken, "token is not active: "+reason, nil)
		}

		// Active-error fail-closed: an introspection response with
		// active: true AND an error field is a DENIAL of this specific call,
		// never a pass-through. The hosted service refuses calls this way
		// (e.g. bound_exceeded on bounded capabilities); honoring only
		// `active` would allow refused calls through.
		if info.Error != "" {
			denial := activeErrorDenial(info, respBytes, requiredScopes)
			// Confirm-each-time: when the hosted service staged a ceremony
			// for this exact action, type the refusal so a custom gate can
			// relay the link. A malformed block stays a plain refusal.
			if denial.Confirmation != nil {
				return nil, &ConfirmationRequiredError{AgentAdmitError: denial}
			}
			return nil, denial
		}

		// Scope enforcement (AgentAdmit also enforces server-side, but this gives
		// a clear local error for logging and fast-fail before sending data).
		if len(requiredScopes) > 0 {
			missing := missingScopes(info.Scopes, requiredScopes)
			if len(missing) > 0 {
				scopeErr := newError(ErrCodeInsufficientScopes,
					fmt.Sprintf("token missing required scopes: %v", missing), nil)
				scopeErr.RequiredScopes = missing
				scopeErr.GrantedScopes = info.Scopes
				return nil, scopeErr
			}
		}

		return info, nil
	}

	// Should never be reached
	return nil, newError(ErrCodeServiceUnavailable, "unexpected exit from retry loop", nil)
}

// decodeVerifyResponse decodes the introspection payload. The token fields
// are validated strictly, exactly as before. The consent and presence
// blocks are decoded leniently in a second pass: they are additive
// metadata, so a type-malformed block must not take down an otherwise
// valid verify. When a block fails to unmarshal it is dropped and the
// corresponding field is left nil.
//
// This does not weaken consent or presence semantics: nil Consent means
// "no verdict" and nil Presence means "not verified"; gated callers must
// treat a missing or dropped block as not granted / not verified (fail
// closed), the same as when the platform returns none.
func decodeVerifyResponse(data []byte) (*TokenInfo, error) {
	// envelope shadows TokenInfo.Consent and TokenInfo.Presence with
	// json.RawMessage fields at a shallower depth. encoding/json resolves
	// each key to the shallowest field, so the raw bytes land in
	// RawConsent/RawPresence and the embedded TokenInfo fields are never
	// populated during this pass.
	var envelope struct {
		TokenInfo
		RawConsent            json.RawMessage `json:"consent"`
		RawPresence           json.RawMessage `json:"presence"`
		RawActionConfirmation json.RawMessage `json:"action_confirmation"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}

	info := envelope.TokenInfo
	info.Consent = nil
	if len(envelope.RawConsent) > 0 && string(envelope.RawConsent) != "null" {
		var verdict ConsentVerdict
		if err := json.Unmarshal(envelope.RawConsent, &verdict); err == nil {
			info.Consent = &verdict
		}
		// On unmarshal failure the malformed consent block is dropped and
		// verification proceeds without a verdict.
	}
	info.Presence = nil
	if len(envelope.RawPresence) > 0 && string(envelope.RawPresence) != "null" {
		var presence Presence
		if err := json.Unmarshal(envelope.RawPresence, &presence); err == nil {
			info.Presence = &presence
		}
		// On unmarshal failure the malformed presence block is dropped and
		// verification proceeds without a presence fact (not verified).
	}
	// Confirm-each-time (1.11.0): only a strict {string id, consumed: true}
	// block reaches the context; anything else is absent, never a claim that
	// a human confirmed.
	info.ActionConfirmation = parseActionConfirmationConsumed(envelope.RawActionConfirmation)
	return &info, nil
}

// ---------------------------------------------------------------------------
// Per-call audit telemetry
// ---------------------------------------------------------------------------

// telemetry field caps, mirroring the hosted verify contract.
const (
	maxScopeUsedChars = 120
	maxEndpointChars  = 500
	maxMethodChars    = 20
)

// RequestTelemetry derives per-call audit telemetry from an inbound HTTP
// request: the request path (path only — the query string never leaves the
// process) and the HTTP method. When exactly one required scope is being
// enforced it becomes ScopeUsed; with zero or multiple scopes, ScopeUsed is
// omitted (it is never a joined list). Returns nil for a nil request.
//
// The agent's X-AgentAdmit-Action-Attestation header is always forwarded when
// present, so a confirm-each-time retry is accepted on any route. The body
// digest and action summary ride RequestTelemetryWithOptions instead.
func RequestTelemetry(r *http.Request, requiredScopes ...string) *VerifyTelemetry {
	if r == nil {
		return nil
	}
	tel := &VerifyTelemetry{
		Endpoint:            r.URL.Path,
		Method:              r.Method,
		ActionAttestationID: ActionAttestation(r),
	}
	if len(requiredScopes) == 1 {
		tel.ScopeUsed = requiredScopes[0]
	}
	return tel
}

// applyTelemetry sanitizes tel and copies it onto the verify request body.
// Fields left empty after sanitization stay unset and are omitted from the
// JSON entirely (omitempty) — never sent as null or "".
func applyTelemetry(body *verifyRequest, tel *VerifyTelemetry) {
	if tel == nil {
		return
	}
	body.ScopeUsed = truncateRunes(tel.ScopeUsed, maxScopeUsedChars)
	if endpoint := tel.Endpoint; endpoint != "" {
		// Strip everything from the first "?" or "#": query strings and
		// fragments can carry PII and must never reach the audit log.
		if i := strings.IndexAny(endpoint, "?#"); i >= 0 {
			endpoint = endpoint[:i]
		}
		body.Endpoint = truncateRunes(endpoint, maxEndpointChars)
	}
	body.Method = truncateRunes(strings.ToUpper(strings.TrimSpace(tel.Method)), maxMethodChars)
	body.ConsentFirst = tel.ConsentFirst
	// Confirm-each-time fields: trimmed, capped, omitted when empty.
	body.ActionAttestationID = truncateRunes(strings.TrimSpace(tel.ActionAttestationID), maxActionAttestationChars)
	body.RequestDigest = truncateRunes(strings.TrimSpace(tel.RequestDigest), maxRequestDigestChars)
	body.ActionSummary = truncateRunes(strings.TrimSpace(tel.ActionSummary), maxActionSummaryChars)
}

// truncateRunes returns s truncated to at most max runes.
func truncateRunes(s string, max int) string {
	if len(s) <= max {
		return s // fast path: byte length bounds rune length
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max])
}

// activeErrorDenial maps an introspection response that reports active: true
// AND a string error field to a denial. This is the single place the
// active-error semantics live; middleware (net/http, gin, echo) only maps
// the returned error codes to HTTP responses.
//
//   - insufficient_scope → ErrCodeInsufficientScopes with the hosted
//     required_scope/granted_scopes when present (local context otherwise),
//     so middleware writes the spec §6.4 step-up shape.
//   - bound_exceeded → ErrCodeCallRefused with the hosted
//     error_description/bound/renewal passed through verbatim.
//   - confirmation_required → ErrCodeCallRefused carrying the staged
//     confirm-each-time ceremony (strictly parsed) plus any
//     attestation_status/attestation_description, so the agent can hand the
//     link to the human and retry. A malformed ceremony is dropped and the
//     refusal stands with no link.
//   - any other error string → ErrCodeCallRefused with a generic
//     description: forward-compatible fail-closed.
func activeErrorDenial(info *TokenInfo, respBytes []byte, requiredScopes []string) *AgentAdmitError {
	// Second lenient pass over the raw response for refusal-only fields not
	// captured on TokenInfo. A malformed extra field must not soften the
	// denial, so the unmarshal error is deliberately ignored.
	var hosted struct {
		RequiredScope    string          `json:"required_scope"`
		GrantedScopes    []string        `json:"granted_scopes"`
		ErrorDescription string          `json:"error_description"`
		Bound            json.RawMessage `json:"bound"`
		Renewal          json.RawMessage `json:"renewal"`
	}
	_ = json.Unmarshal(respBytes, &hosted)

	switch info.Error {
	case VerifyErrorInsufficientScope:
		scopeErr := newError(ErrCodeInsufficientScopes,
			"call refused by the authorization service: insufficient_scope", nil)
		if hosted.RequiredScope != "" {
			scopeErr.RequiredScopes = []string{hosted.RequiredScope}
		} else {
			scopeErr.RequiredScopes = requiredScopes
		}
		if hosted.GrantedScopes != nil {
			scopeErr.GrantedScopes = hosted.GrantedScopes
		} else {
			scopeErr.GrantedScopes = info.Scopes
		}
		return scopeErr

	case VerifyErrorBoundExceeded:
		refusal := newError(ErrCodeCallRefused,
			"call refused by the authorization service: bound_exceeded", nil)
		refusal.VerifyError = VerifyErrorBoundExceeded
		refusal.ErrorDescription = hosted.ErrorDescription
		refusal.Bound = hosted.Bound
		refusal.Renewal = hosted.Renewal
		return refusal

	case VerifyErrorConfirmationRequired:
		// Third pass, key by key: a type-malformed sibling field (say a
		// numeric attestation_status) must not cost the agent the
		// confirmation link, and the ceremony itself is parsed strictly.
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(respBytes, &fields)

		refusal := newError(ErrCodeCallRefused,
			"call refused by the authorization service: confirmation_required", nil)
		refusal.VerifyError = VerifyErrorConfirmationRequired
		refusal.ErrorDescription = confirmationRequiredDescription
		if description, ok := rawString(fields["error_description"]); ok && description != "" {
			refusal.ErrorDescription = description
		}
		refusal.Confirmation = parseActionConfirmation(fields["confirmation"])
		if status, ok := rawString(fields["attestation_status"]); ok {
			refusal.AttestationStatus = status
		}
		if description, ok := rawString(fields["attestation_description"]); ok {
			refusal.AttestationDescription = description
		}
		if renewal := fields["renewal"]; len(renewal) > 0 && string(renewal) != "null" {
			refusal.Renewal = renewal
		}
		return refusal

	default:
		refusal := newError(ErrCodeCallRefused,
			"call refused by the authorization service: "+info.Error, nil)
		refusal.VerifyError = info.Error
		refusal.ErrorDescription = "Call refused by the authorization service."
		return refusal
	}
}

// ---------------------------------------------------------------------------
// Rate-limit header parsing helpers
// ---------------------------------------------------------------------------

// parseFloatHeader reads a float64 from a response header. Returns -1 if absent or invalid.
func parseFloatHeader(resp *http.Response, name string) float64 {
	v := resp.Header.Get(name)
	if v == "" {
		return -1
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return -1
	}
	return f
}

// parseIntHeader reads an int from a response header. Returns -1 if absent or invalid.
func parseIntHeader(resp *http.Response, name string) int {
	v := resp.Header.Get(name)
	if v == "" {
		return -1
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return -1
	}
	return n
}

// parseInt64Header reads an int64 from a response header. Returns -1 if absent or invalid.
func parseInt64Header(resp *http.Response, name string) int64 {
	v := resp.Header.Get(name)
	if v == "" {
		return -1
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return -1
	}
	return n
}

// TokenFromContext retrieves a previously validated *TokenInfo from a
// context.Context. Returns nil if no token was stored.
//
// This is used by middleware to propagate token metadata to downstream
// handlers without re-validating.
func TokenFromContext(ctx context.Context) *TokenInfo {
	if v := ctx.Value(tokenContextKey); v != nil {
		if info, ok := v.(*TokenInfo); ok {
			return info
		}
	}
	return nil
}

// contextWithToken returns a new context with the given *TokenInfo attached.
// Used internally by middleware.
func contextWithToken(ctx context.Context, info *TokenInfo) context.Context {
	return context.WithValue(ctx, tokenContextKey, info)
}

// missingScopes returns scopes from required that are absent from granted.
func missingScopes(granted, required []string) []string {
	grantedSet := make(map[string]struct{}, len(granted))
	for _, s := range granted {
		grantedSet[s] = struct{}{}
	}
	var missing []string
	for _, s := range required {
		if _, ok := grantedSet[s]; !ok {
			missing = append(missing, s)
		}
	}
	return missing
}
