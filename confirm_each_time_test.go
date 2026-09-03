package agentadmit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Confirm-each-time (1.11.0). The hosted service refuses a designated scope
// with confirmation_required and stages a ceremony for the exact action. The
// SDK must (1) pass the confirmation block through to the agent as a 403,
// typed on the error, (2) forward the agent's attestation header on the
// retry, (3) compute the request digest and carry the app's action summary on
// a confirming route without costing the handler its body, (4) surface a
// consumed confirmation only when it is strictly typed, and (5) keep failing
// closed on every other refusal class.

const confirmationRefusalResponse = `{
  "active": true,
  "error": "confirmation_required",
  "confirmation": {
    "action_session_id": "asess_abc",
    "action_session_url": "https://agentadmit.com/confirm/action/asess_abc",
    "expires_at": "2026-09-02T18:30:00.000Z",
    "scope": "write:payments",
    "method": "POST",
    "endpoint": "/api/payments",
    "request_digest": "sha256:deadbeef",
    "summary": "Pay Alex $50"
  },
  "attestation_status": "action_mismatch",
  "attestation_description": "That confirmation was for a different action.",
  "renewal": "The human confirms on the hosted page with their passkey.",
  "scopes": ["leak"],
  "user_id": "user_leak"
}`

// paySummary is the app's plain-language description of the action, built
// from the raw body the SDK read.
func paySummary(_ *http.Request, body []byte) string {
	var parsed struct {
		Trainer string `json:"trainer"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "Pay someone"
	}
	return "Pay " + parsed.Trainer + " $50"
}

// echoBodyHandler records that it ran AND what body it could still read,
// proving the digest never costs the handler its body.
func echoBodyHandler(invoked *bool, seen *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*invoked = true
		raw, _ := io.ReadAll(r.Body)
		*seen = string(raw)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func payOptions() ScopeOptions {
	return ScopeOptions{ActionSummary: paySummary}
}

func sha256Of(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// §2: confirmation_required is a 403 carrying the staged ceremony
// ---------------------------------------------------------------------------

func TestConfirmationRequired_403CarriesTheCeremony(t *testing.T) {
	var captured []map[string]interface{}
	client := newTelemetryClient(t, confirmationRefusalResponse, &captured)

	var invoked bool
	var seen string
	handler := client.MiddlewareWithOptions(payOptions(), "write:payments")(echoBodyHandler(&invoked, &seen))

	req := httptest.NewRequest(http.MethodPost, "/api/payments", strings.NewReader(`{"trainer":"alex"}`))
	req.Header.Set("Authorization", "Bearer ag_at_tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if invoked {
		t.Fatal("handler ran on a refused call — fail-closed broken")
	}

	var body struct {
		Error            string              `json:"error"`
		ErrorDescription string              `json:"error_description"`
		Confirmation     *ActionConfirmation `json:"confirmation"`
		AttestationStat  string              `json:"attestation_status"`
		AttestationDesc  string              `json:"attestation_description"`
		Renewal          string              `json:"renewal"`
		Scopes           []string            `json:"scopes"`
		UserID           string              `json:"user_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("403 body is not valid JSON: %v (%s)", err, rec.Body.String())
	}
	if body.Error != "confirmation_required" {
		t.Errorf("error = %q, want confirmation_required", body.Error)
	}
	if body.Confirmation == nil {
		t.Fatal("confirmation block missing from the 403 body")
	}
	if body.Confirmation.ActionSessionURL != "https://agentadmit.com/confirm/action/asess_abc" {
		t.Errorf("action_session_url = %q", body.Confirmation.ActionSessionURL)
	}
	if body.Confirmation.ActionSessionID != "asess_abc" || body.Confirmation.Scope != "write:payments" {
		t.Errorf("confirmation identity fields = %+v", body.Confirmation)
	}
	if body.Confirmation.Method == nil || *body.Confirmation.Method != "POST" {
		t.Errorf("confirmation.method = %v, want POST", body.Confirmation.Method)
	}
	if body.Confirmation.Summary == nil || *body.Confirmation.Summary != "Pay Alex $50" {
		t.Errorf("confirmation.summary = %v", body.Confirmation.Summary)
	}
	if body.AttestationStat != "action_mismatch" {
		t.Errorf("attestation_status = %q", body.AttestationStat)
	}
	if !strings.Contains(body.AttestationDesc, "different action") {
		t.Errorf("attestation_description = %q", body.AttestationDesc)
	}
	if !strings.Contains(body.Renewal, "passkey") {
		t.Errorf("renewal = %q", body.Renewal)
	}
	// Nothing else from the wire: a refusal must not leak identity or scope
	// state to the agent.
	if len(body.Scopes) != 0 || body.UserID != "" {
		t.Errorf("refusal leaked wire fields: scopes=%v user_id=%q", body.Scopes, body.UserID)
	}
}

// A nullable field the hosted service sent as null must survive as JSON null,
// so the 403 body has the same shape across every AgentAdmit SDK.
func TestConfirmationRequired_NullableFieldsStayNull(t *testing.T) {
	var captured []map[string]interface{}
	client := newTelemetryClient(t, `{"active":true,"error":"confirmation_required","confirmation":{
		"action_session_id":"asess_abc","action_session_url":"https://x/y","expires_at":"e","scope":"write:payments",
		"method":null,"endpoint":null,"request_digest":null,"summary":null}}`, &captured)

	var invoked bool
	var seen string
	handler := client.Middleware("write:payments")(echoBodyHandler(&invoked, &seen))
	req := httptest.NewRequest(http.MethodPost, "/api/payments", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer ag_at_tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("403 body is not valid JSON: %v", err)
	}
	var conf map[string]json.RawMessage
	if err := json.Unmarshal(raw["confirmation"], &conf); err != nil {
		t.Fatalf("confirmation is not an object: %v", err)
	}
	for _, key := range []string{"method", "endpoint", "request_digest", "summary"} {
		if string(conf[key]) != "null" {
			t.Errorf("confirmation.%s = %s, want null", key, string(conf[key]))
		}
	}
}

// ---------------------------------------------------------------------------
// §2: a malformed ceremony fails closed — 403, no link, no typed error
// ---------------------------------------------------------------------------

func TestConfirmationRequired_MalformedBlockFailsClosed(t *testing.T) {
	cases := []struct {
		name     string
		response string
	}{
		{"missing required fields", `{"active":true,"error":"confirmation_required","confirmation":{"x":1}}`},
		{"non-string id", `{"active":true,"error":"confirmation_required","confirmation":{"action_session_id":123,"action_session_url":"u","expires_at":"e","scope":"s"}}`},
		{"not an object", `{"active":true,"error":"confirmation_required","confirmation":"asess_abc"}`},
		{"absent block", `{"active":true,"error":"confirmation_required"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var captured []map[string]interface{}
			client := newTelemetryClient(t, tc.response, &captured)

			var invoked bool
			var seen string
			handler := client.MiddlewareWithOptions(payOptions(), "write:payments")(echoBodyHandler(&invoked, &seen))
			req := httptest.NewRequest(http.MethodPost, "/api/payments", strings.NewReader(`{"trainer":"alex"}`))
			req.Header.Set("Authorization", "Bearer ag_at_tok")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
			if invoked {
				t.Fatal("handler ran on a refused call — fail-closed broken")
			}
			var body map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("403 body is not valid JSON: %v", err)
			}
			if body["error"] != "confirmation_required" {
				t.Errorf("error = %v, want confirmation_required", body["error"])
			}
			if _, present := body["confirmation"]; present {
				t.Error("a malformed ceremony must not reach the agent")
			}
			if body["error_description"] != confirmationRequiredDescription {
				t.Errorf("error_description = %v, want the fixed fallback", body["error_description"])
			}

			// Direct callers see a plain refusal, not the typed one.
			_, err := client.Validate("ag_at_tok", []string{"write:payments"})
			if IsConfirmationRequired(err) {
				t.Error("a malformed ceremony must not produce a ConfirmationRequiredError")
			}
			if !IsCallRefused(err) {
				t.Errorf("err = %v, want a call-refused denial", err)
			}
		})
	}
}

// Every other refusal class keeps the 1.10.x fail-closed behavior.
func TestOtherRefusalClassesUnchanged(t *testing.T) {
	var captured []map[string]interface{}
	client := newTelemetryClient(t, `{"active":true,"error":"confirmation_policy_unavailable"}`, &captured)

	_, err := client.Validate("ag_at_tok", nil)
	if !IsCallRefused(err) || IsConfirmationRequired(err) {
		t.Fatalf("err = %v, want a generic call-refused denial", err)
	}
	var aaErr *AgentAdmitError
	if !errors.As(err, &aaErr) {
		t.Fatal("refusal is not an *AgentAdmitError")
	}
	if aaErr.ErrorDescription != "Call refused by the authorization service." {
		t.Errorf("error_description = %q, want the generic fail-closed text", aaErr.ErrorDescription)
	}
	if aaErr.Confirmation != nil {
		t.Error("a non-confirmation refusal must carry no ceremony")
	}
}

// ---------------------------------------------------------------------------
// §5: typed refusal for custom gates
// ---------------------------------------------------------------------------

func TestConfirmationRequiredError_TypedForCustomGates(t *testing.T) {
	var captured []map[string]interface{}
	client := newTelemetryClient(t, confirmationRefusalResponse, &captured)

	_, err := client.Validate("ag_at_tok", []string{"write:payments"})
	var confErr *ConfirmationRequiredError
	if !errors.As(err, &confErr) {
		t.Fatalf("err = %v (%T), want *ConfirmationRequiredError", err, err)
	}
	if confErr.Confirmation == nil || confErr.Confirmation.ActionSessionID != "asess_abc" {
		t.Fatalf("confirmation = %+v", confErr.Confirmation)
	}
	if confErr.AttestationStatus != "action_mismatch" {
		t.Errorf("attestation_status = %q", confErr.AttestationStatus)
	}
	if !IsConfirmationRequired(err) {
		t.Error("IsConfirmationRequired = false")
	}
	// The existing error-handling contract still holds: middleware matches
	// *AgentAdmitError with ErrCodeCallRefused and writes 403.
	var aaErr *AgentAdmitError
	if !errors.As(err, &aaErr) {
		t.Fatal("typed refusal is not reachable as *AgentAdmitError")
	}
	if aaErr.Code != ErrCodeCallRefused || aaErr.VerifyError != VerifyErrorConfirmationRequired {
		t.Errorf("code = %s, verify_error = %s", aaErr.Code, aaErr.VerifyError)
	}
	if !IsCallRefused(err) {
		t.Error("IsCallRefused = false on a confirmation refusal")
	}
	if !strings.Contains(err.Error(), "confirmation_required") {
		t.Errorf("Error() = %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// §1/§3: the verify request additions
// ---------------------------------------------------------------------------

func TestAttestationHeaderForwarded(t *testing.T) {
	longID := strings.Repeat("a", 200)
	cases := []struct {
		name    string
		set     func(r *http.Request)
		want    interface{}
		present bool
	}{
		{"absent", func(r *http.Request) {}, nil, false},
		{"trimmed", func(r *http.Request) { r.Header.Set(ActionAttestationHeader, "  asess_abc  ") }, "asess_abc", true},
		{"lowercase header name", func(r *http.Request) { r.Header.Set("x-agentadmit-action-attestation", "asess_abc") }, "asess_abc", true},
		{"first value wins", func(r *http.Request) {
			r.Header.Add(ActionAttestationHeader, "asess_first")
			r.Header.Add(ActionAttestationHeader, "asess_second")
		}, "asess_first", true},
		{"whitespace only", func(r *http.Request) { r.Header.Set(ActionAttestationHeader, "   ") }, nil, false},
		{"capped at 120", func(r *http.Request) { r.Header.Set(ActionAttestationHeader, longID) }, longID[:120], true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var captured []map[string]interface{}
			client := newTelemetryClient(t, `{"active":true,"scopes":["write:payments"],"app_id":"app_1","user_id":"user_1"}`, &captured)

			var invoked bool
			// No options: the attestation header rides every route.
			handler := client.Middleware("write:payments")(okHandler(&invoked))
			req := httptest.NewRequest(http.MethodPost, "/api/payments", strings.NewReader(`{"trainer":"alex"}`))
			req.Header.Set("Authorization", "Bearer ag_at_tok")
			tc.set(req)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK || !invoked {
				t.Fatalf("status = %d, invoked = %v", rec.Code, invoked)
			}
			if len(captured) != 1 {
				t.Fatalf("expected 1 verify call, got %d", len(captured))
			}
			got, present := captured[0]["action_attestation_id"]
			if present != tc.present {
				t.Fatalf("action_attestation_id present = %v, want %v (value %v)", present, tc.present, got)
			}
			if tc.present && got != tc.want {
				t.Errorf("action_attestation_id = %v, want %v", got, tc.want)
			}
			// Without options, no digest and no summary are sent.
			if _, present := captured[0]["request_digest"]; present {
				t.Error("request_digest sent without a summary option")
			}
			if _, present := captured[0]["action_summary"]; present {
				t.Error("action_summary sent without a summary option")
			}
			// Success responses must not carry refusal headers.
			if rec.Header().Get(ActionAttestationHeader) != "" {
				t.Error("attestation header leaked onto the success response")
			}
		})
	}
}

func TestConfirmingRoute_SendsDigestAndSummaryAndKeepsTheBody(t *testing.T) {
	var captured []map[string]interface{}
	client := newTelemetryClient(t, `{"active":true,"scopes":["write:payments"],"app_id":"app_1","user_id":"user_1"}`, &captured)

	var invoked bool
	var seen string
	handler := client.MiddlewareWithOptions(payOptions(), "write:payments")(echoBodyHandler(&invoked, &seen))

	payload := `{"trainer":"alex","amount":50}`
	req := httptest.NewRequest(http.MethodPost, "/api/payments?debug=1", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer ag_at_tok")
	req.Header.Set(ActionAttestationHeader, "asess_abc")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !invoked {
		t.Fatalf("status = %d, invoked = %v: %s", rec.Code, invoked, rec.Body.String())
	}
	if seen != payload {
		t.Errorf("handler read body %q, want the original %q", seen, payload)
	}
	body := captured[0]
	if body["scope_used"] != "write:payments" || body["method"] != "POST" || body["endpoint"] != "/api/payments" {
		t.Errorf("1.10 telemetry regressed: %v", body)
	}
	if body["action_attestation_id"] != "asess_abc" {
		t.Errorf("action_attestation_id = %v", body["action_attestation_id"])
	}
	if body["action_summary"] != "Pay alex $50" {
		t.Errorf("action_summary = %v, want the app's summary", body["action_summary"])
	}
	digest, _ := body["request_digest"].(string)
	if digest != sha256Of(payload) {
		t.Errorf("request_digest = %q, want the sha256 of the raw body %q", digest, sha256Of(payload))
	}
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
		t.Errorf("request_digest = %q, want sha256:<64 hex>", digest)
	}
}

func TestConfirmingRoute_SummaryCappedAndOmittedWhenEmpty(t *testing.T) {
	long := strings.Repeat("é", 400) // multi-byte: the cap is in runes
	cases := []struct {
		name    string
		summary func(*http.Request, []byte) string
		want    interface{}
		present bool
	}{
		{"capped at 200", func(*http.Request, []byte) string { return long }, strings.Repeat("é", 200), true},
		{"trimmed", func(*http.Request, []byte) string { return "  Pay Alex $50  " }, "Pay Alex $50", true},
		{"empty omitted", func(*http.Request, []byte) string { return "   " }, nil, false},
		{"panic omitted", func(*http.Request, []byte) string { panic("broken summary") }, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var captured []map[string]interface{}
			client := newTelemetryClient(t, `{"active":true,"scopes":["write:payments"],"app_id":"app_1","user_id":"user_1"}`, &captured)

			var invoked bool
			var seen string
			handler := client.MiddlewareWithOptions(ScopeOptions{ActionSummary: tc.summary}, "write:payments")(echoBodyHandler(&invoked, &seen))
			req := httptest.NewRequest(http.MethodPost, "/api/payments", strings.NewReader(`{"trainer":"alex"}`))
			req.Header.Set("Authorization", "Bearer ag_at_tok")
			handler.ServeHTTP(httptest.NewRecorder(), req)

			got, present := captured[0]["action_summary"]
			if present != tc.present {
				t.Fatalf("action_summary present = %v, want %v", present, tc.present)
			}
			if tc.present && got != tc.want {
				t.Errorf("action_summary = %q", got)
			}
			// The digest rides the summary option even when the summary is empty.
			if _, present := captured[0]["request_digest"]; !present {
				t.Error("request_digest missing on a confirming route")
			}
		})
	}
}

// An empty body digests to nothing: the field is omitted rather than sent as
// the digest of zero bytes.
func TestConfirmingRoute_EmptyBodyOmitsTheDigest(t *testing.T) {
	var captured []map[string]interface{}
	client := newTelemetryClient(t, `{"active":true,"scopes":["write:payments"],"app_id":"app_1","user_id":"user_1"}`, &captured)

	var invoked bool
	handler := client.MiddlewareWithOptions(payOptions(), "write:payments")(okHandler(&invoked))
	req := httptest.NewRequest(http.MethodGet, "/api/payments", nil)
	req.Header.Set("Authorization", "Bearer ag_at_tok")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if _, present := captured[0]["request_digest"]; present {
		t.Errorf("request_digest sent for an empty body: %v", captured[0]["request_digest"])
	}
	if RequestDigest(nil) != "" || RequestDigest([]byte{}) != "" {
		t.Error("RequestDigest must return \"\" for an empty body")
	}
	if RequestDigest([]byte("x")) != sha256Of("x") {
		t.Error("RequestDigest does not match sha256 of the raw bytes")
	}
}

// ---------------------------------------------------------------------------
// §4: a consumed confirmation reaches the context only when strictly typed
// ---------------------------------------------------------------------------

func TestConsumedActionConfirmationIsStrict(t *testing.T) {
	cases := []struct {
		name  string
		block string
		want  bool
	}{
		{"strict", `{"action_session_id":"asess_abc","consumed":true}`, true},
		{"consumed as string", `{"action_session_id":"asess_abc","consumed":"yes"}`, false},
		{"consumed false", `{"action_session_id":"asess_abc","consumed":false}`, false},
		{"consumed missing", `{"action_session_id":"asess_abc"}`, false},
		{"id missing", `{"consumed":true}`, false},
		{"id empty", `{"action_session_id":"","consumed":true}`, false},
		{"id not a string", `{"action_session_id":123,"consumed":true}`, false},
		{"not an object", `"asess_abc"`, false},
		{"null", `null`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var captured []map[string]interface{}
			response := `{"active":true,"scopes":["write:payments"],"app_id":"app_1","user_id":"user_1","action_confirmation":` + tc.block + `}`
			client := newTelemetryClient(t, response, &captured)

			var got *ActionConfirmationConsumed
			var reached bool
			handler := client.Middleware("write:payments")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				got = ActionConfirmationFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodPost, "/api/payments", strings.NewReader(`{}`))
			req.Header.Set("Authorization", "Bearer ag_at_tok")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			// A malformed additive block must never fail an otherwise valid
			// verify — it is dropped, exactly like consent and presence.
			if rec.Code != http.StatusOK || !reached {
				t.Fatalf("status = %d, handler reached = %v: %s", rec.Code, reached, rec.Body.String())
			}
			if tc.want {
				if got == nil || got.ActionSessionID != "asess_abc" || !got.Consumed {
					t.Fatalf("action confirmation = %+v, want the consumed ceremony", got)
				}
				if info := TokenFromContext(req.Context()); info != nil {
					t.Error("context accessor should read the middleware's context, not the original")
				}
			} else if got != nil {
				t.Fatalf("action confirmation = %+v, want absent", got)
			}
		})
	}
}

func TestActionConfirmationFromContext_EmptyContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if ActionConfirmationFromContext(req.Context()) != nil {
		t.Error("an unauthenticated request must carry no confirmation")
	}
}

// ---------------------------------------------------------------------------
// §6(a): a non-default APIURL derives the verify URL
// ---------------------------------------------------------------------------

func TestVerifyURLFollowsNonDefaultAPIURL(t *testing.T) {
	cases := []struct {
		name      string
		apiURL    string
		verifyURL string
		want      string
	}{
		{"defaults", "", "", DefaultVerifyURL},
		{"local rig", "http://127.0.0.1:3003", "", "http://127.0.0.1:3003/api/v1/verify"},
		{"trailing slash", "https://staging.agentadmit.example/", "", "https://staging.agentadmit.example/api/v1/verify"},
		{"explicit default api url", DefaultAPIURL, "", DefaultVerifyURL},
		{"explicit verify url wins", "http://localhost:9000", "http://localhost:9000/verify", "http://localhost:9000/verify"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := New(Config{APIKey: "aa_test_x", APIURL: tc.apiURL, VerifyURL: tc.verifyURL})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if client.verifyURL != tc.want {
				t.Errorf("verifyURL = %q, want %q", client.verifyURL, tc.want)
			}
		})
	}
}
