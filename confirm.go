package agentadmit

// Confirm-each-time (1.11.0): exercise-time human confirmation.
//
// Some actions should never run on a standing grant alone: moving money,
// sending or publishing on the user's behalf, deleting data, touching
// production. Scopes registered with confirm_each_time require a FRESH human
// confirmation for every call that exercises them, even inside a valid
// connection.
//
// The SDK's part of the contract:
//
//  1. Every verify carries the agent's X-AgentAdmit-Action-Attestation header
//     when the inbound request has one (always forwarded, with or without a
//     summary).
//  2. A confirm-each-time route additionally carries a sha256 digest of the
//     raw request body and the app's plain-language action summary, so the
//     confirmation covers the exact payload and the human sees what they are
//     approving (see ScopeOptions).
//  3. The hosted service answers active: true with error
//     "confirmation_required" and a staged ceremony. The middleware turns
//     that into 403 with the confirmation block so the agent can hand
//     confirmation.action_session_url to the human, then retry the same
//     request with X-AgentAdmit-Action-Attestation: <action_session_id>.
//  4. When the retry is accepted, TokenInfo.ActionConfirmation names the
//     confirmation that was consumed.
//
// AgentAdmit does not verify the summary against the request; it proves what
// the human was shown.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// ActionAttestationHeader is the request header an agent sets on its retry
// after the human completed the hosted confirmation ceremony. Its value is
// the action_session_id from the confirmation_required refusal. Header
// lookups are case-insensitive.
const ActionAttestationHeader = "X-AgentAdmit-Action-Attestation"

// Hosted verify BodySchema caps for the confirm-each-time fields.
const (
	maxActionAttestationChars = 120
	maxRequestDigestChars     = 128
	maxActionSummaryChars     = 200
)

// confirmationRequiredDescription is the fixed fallback description written
// when the hosted service does not supply its own.
const confirmationRequiredDescription = "This action requires a fresh human confirmation. " +
	"Give the confirmation link to the user, then retry with the X-AgentAdmit-Action-Attestation header."

// ActionConfirmation is the hosted confirm-each-time ceremony staged for one
// exact action, carried on a confirmation_required refusal. The agent hands
// ActionSessionURL to the human; only a user-verified passkey on that page
// produces an attestation, so the agent cannot complete it. The agent then
// retries the same request with the ActionAttestationHeader set to
// ActionSessionID.
//
// Method, Endpoint, RequestDigest, and Summary are nullable on the wire and
// are marshalled back out as JSON null when absent, so the 403 body an agent
// receives has the same shape across every AgentAdmit SDK.
type ActionConfirmation struct {
	ActionSessionID  string  `json:"action_session_id"`
	ActionSessionURL string  `json:"action_session_url"`
	ExpiresAt        string  `json:"expires_at"`
	Scope            string  `json:"scope"`
	Method           *string `json:"method"`
	Endpoint         *string `json:"endpoint"`
	RequestDigest    *string `json:"request_digest"`
	Summary          *string `json:"summary"`
}

// ActionConfirmationConsumed reports that THIS call was accepted because the
// hosted service consumed a human confirmation for exactly this action. It is
// present on TokenInfo only when the wire block is strictly a string session
// id with consumed: true; anything else is dropped. Apps that run their own
// transaction step-up can treat it as that confirmation instead of asking the
// human twice.
type ActionConfirmationConsumed struct {
	ActionSessionID string `json:"action_session_id"`
	Consumed        bool   `json:"consumed"`
}

// ConfirmationRequiredError is the typed refusal for confirmation_required:
// the scope is granted, but this call needs a fresh human confirmation. It
// wraps the standard *AgentAdmitError (Code ErrCodeCallRefused, VerifyError
// "confirmation_required"), so errors.As still finds *AgentAdmitError and
// existing middleware keeps mapping it to 403; custom gates can match this
// type directly to relay the link:
//
//	var confErr *agentadmit.ConfirmationRequiredError
//	if errors.As(err, &confErr) {
//	    link := confErr.Confirmation.ActionSessionURL
//	}
//
// Confirmation and AttestationStatus are promoted from the embedded error.
// It is only returned when the hosted confirmation block parsed strictly; a
// malformed block fails closed as a plain refusal with no link.
type ConfirmationRequiredError struct {
	*AgentAdmitError
}

// Unwrap exposes the embedded *AgentAdmitError to errors.As / errors.Is.
func (e *ConfirmationRequiredError) Unwrap() error { return e.AgentAdmitError }

// IsConfirmationRequired reports whether err is a confirm-each-time refusal
// carrying a staged confirmation ceremony.
func IsConfirmationRequired(err error) bool {
	var confErr *ConfirmationRequiredError
	return errors.As(err, &confErr)
}

// ScopeOptions configures a confirm-each-time route. The zero value behaves
// exactly like the plain middleware: the attestation header is still
// forwarded, but no body digest or summary is computed.
type ScopeOptions struct {
	// ActionSummary returns the plain-language description of THIS action for
	// the human ("Pay Alex $50"), given the inbound request and its raw body
	// bytes (nil when there is no body). Return "" to omit the summary.
	//
	// Setting it opts the route into confirm-each-time telemetry: the
	// middleware reads the request body once (re-buffering it so the handler
	// still reads it in full), sends "sha256:<hex>" over those exact bytes as
	// the request digest, and sends the summary, trimmed and capped at 200
	// characters. The summary is shown as the headline of the hosted
	// confirmation page and committed into the passkey signature; AgentAdmit
	// does not verify it against the request.
	ActionSummary func(r *http.Request, body []byte) string
}

// RequestDigest returns "sha256:<hex>" over the raw request body bytes, or ""
// for an empty body (the digest is then omitted from the verify call). The
// agent's retry re-sends the same bytes, so the confirmation covers the exact
// payload and not merely the route.
func RequestDigest(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ActionAttestation returns the trimmed X-AgentAdmit-Action-Attestation
// header value from an inbound request (first value when repeated, capped at
// 120 characters), or "" when absent. Middleware forwards it automatically.
func ActionAttestation(r *http.Request) string {
	if r == nil || r.Header == nil {
		return ""
	}
	values := r.Header.Values(ActionAttestationHeader)
	if len(values) == 0 {
		return ""
	}
	value := strings.TrimSpace(values[0])
	if value == "" {
		return ""
	}
	return truncateRunes(value, maxActionAttestationChars)
}

// RequestTelemetryWithOptions is RequestTelemetry plus the confirm-each-time
// fields from opts. When opts.ActionSummary is set it reads r.Body, restores
// it so the downstream handler reads the same bytes, and carries the request
// digest and the summary on the verify call. The attestation header is
// forwarded either way (RequestTelemetry already does that). Returns nil for
// a nil request.
func RequestTelemetryWithOptions(r *http.Request, opts ScopeOptions, requiredScopes ...string) *VerifyTelemetry {
	tel := RequestTelemetry(r, requiredScopes...)
	if tel == nil || opts.ActionSummary == nil {
		return tel
	}
	body := readAndRestoreBody(r)
	tel.RequestDigest = RequestDigest(body)
	if summary := strings.TrimSpace(safeActionSummary(opts.ActionSummary, r, body)); summary != "" {
		tel.ActionSummary = truncateRunes(summary, maxActionSummaryChars)
	}
	return tel
}

// safeActionSummary keeps app-supplied display telemetry from taking the
// endpoint down. The hosted service still enforces the scope and confirmation
// policy without a summary, so omitting a callback that panicked weakens
// nothing. This matches the Node, Python, Java, PHP, and Ruby adapters.
func safeActionSummary(summary func(*http.Request, []byte) string, r *http.Request, body []byte) (value string) {
	defer func() {
		if recover() != nil {
			value = ""
		}
	}()
	return summary(r, body)
}

// readAndRestoreBody reads the whole request body and puts it back on the
// request, so computing the digest never costs the handler its body. Returns
// nil when there is no body or it could not be read (no digest is then sent —
// the hosted service refuses the call rather than confirming a payload the
// SDK could not see).
func readAndRestoreBody(r *http.Request) []byte {
	if r == nil || r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	raw, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil {
		return nil
	}
	return raw
}

// ActionConfirmationFromContext returns the confirmation the hosted service
// consumed for this call, as stored by middleware, or nil when this call did
// not consume one.
func ActionConfirmationFromContext(ctx context.Context) *ActionConfirmationConsumed {
	if info := TokenFromContext(ctx); info != nil {
		return info.ActionConfirmation
	}
	return nil
}

// ---------------------------------------------------------------------------
// Wire parsing (strict)
// ---------------------------------------------------------------------------

// parseActionConfirmation returns a strictly typed copy of the wire
// confirmation block, or nil. The four identity fields must be strings;
// method/endpoint/request_digest/summary are nullable strings and anything
// else becomes nil. A block that does not parse is dropped entirely, and the
// refusal falls back to the generic fail-closed 403 with no link.
func parseActionConfirmation(raw json.RawMessage) *ActionConfirmation {
	if len(raw) == 0 {
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil
	}
	id, okID := rawString(fields["action_session_id"])
	url, okURL := rawString(fields["action_session_url"])
	expires, okExpires := rawString(fields["expires_at"])
	scope, okScope := rawString(fields["scope"])
	if !okID || !okURL || !okExpires || !okScope {
		return nil
	}
	return &ActionConfirmation{
		ActionSessionID:  id,
		ActionSessionURL: url,
		ExpiresAt:        expires,
		Scope:            scope,
		Method:           nullableString(fields["method"]),
		Endpoint:         nullableString(fields["endpoint"]),
		RequestDigest:    nullableString(fields["request_digest"]),
		Summary:          nullableString(fields["summary"]),
	}
}

// parseActionConfirmationConsumed returns the consumed-confirmation block
// from an ACCEPTED verify response, or nil. Strict: a string session id and
// consumed exactly true, else absent.
func parseActionConfirmationConsumed(raw json.RawMessage) *ActionConfirmationConsumed {
	if len(raw) == 0 {
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil
	}
	id, ok := rawString(fields["action_session_id"])
	if !ok || id == "" {
		return nil
	}
	var consumed bool
	if err := json.Unmarshal(fields["consumed"], &consumed); err != nil || !consumed {
		return nil
	}
	return &ActionConfirmationConsumed{ActionSessionID: id, Consumed: true}
}

// rawString decodes a JSON string, reporting whether the value was present
// and actually a string.
func rawString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	// Unmarshalling JSON null directly into a string succeeds and leaves the
	// zero value, which would incorrectly turn a nullable wire field into an
	// empty string. Decode generically first so only an actual JSON string is
	// accepted.
	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	s, ok := value.(string)
	return s, ok
}

// nullableString decodes a nullable JSON string; anything else is nil.
func nullableString(raw json.RawMessage) *string {
	s, ok := rawString(raw)
	if !ok {
		return nil
	}
	return &s
}
