package agentadmit

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTelemetryClient builds a client whose verify endpoint is an httptest
// server that records every request body it receives and answers with the
// given JSON response. Both VerifyURL and APIURL point at the test server.
func newTelemetryClient(t *testing.T, response string, captured *[]map[string]interface{}) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading verify request body: %v", err)
		}
		var body map[string]interface{}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("verify request body is not valid JSON: %v", err)
		}
		*captured = append(*captured, body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(server.Close)
	client, err := New(Config{
		APIKey:     "aa_test_dummy",
		VerifyURL:  server.URL, // http://127.0.0.1:PORT -- allowed
		APIURL:     server.URL,
		MaxRetries: 0,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

const activeOKResponse = `{"active":true,"scopes":["read:workouts"],"app_id":"app_1","user_id":"user_1"}`

// okHandler returns a handler that records whether it was invoked.
func okHandler(invoked *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*invoked = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// ---------------------------------------------------------------------------
// §1/§6(a): scope-enforcing middleware sends scope_used + endpoint + method
// ---------------------------------------------------------------------------

func TestMiddlewareTelemetry_SendsScopeEndpointMethod(t *testing.T) {
	var captured []map[string]interface{}
	client := newTelemetryClient(t, activeOKResponse, &captured)

	var invoked bool
	handler := client.Middleware("read:workouts")(okHandler(&invoked))

	req := httptest.NewRequest(http.MethodGet, "/api/workouts?user=42&ssn=secret", nil)
	req.Header.Set("Authorization", "Bearer ag_at_tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !invoked {
		t.Fatal("handler was not invoked on a valid token")
	}
	if len(captured) != 1 {
		t.Fatalf("expected 1 verify call, got %d", len(captured))
	}
	body := captured[0]
	if body["token"] != "ag_at_tok" {
		t.Errorf("token = %v, want ag_at_tok", body["token"])
	}
	if body["scope_used"] != "read:workouts" {
		t.Errorf("scope_used = %v, want read:workouts", body["scope_used"])
	}
	if body["endpoint"] != "/api/workouts" {
		t.Errorf("endpoint = %v, want /api/workouts (query stripped)", body["endpoint"])
	}
	if body["method"] != "GET" {
		t.Errorf("method = %v, want GET", body["method"])
	}
}

func TestRequireAgentMiddlewareTelemetry_SendsScopeEndpointMethod(t *testing.T) {
	var captured []map[string]interface{}
	client := newTelemetryClient(t, activeOKResponse, &captured)

	var invoked bool
	handler := client.RequireAgentMiddleware("read:workouts")(okHandler(&invoked))

	req := httptest.NewRequest(http.MethodPost, "/api/workouts", nil)
	req.Header.Set("Authorization", "Bearer ag_at_tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !invoked {
		t.Fatalf("status = %d invoked = %v, want 200/true", rec.Code, invoked)
	}
	body := captured[0]
	if body["scope_used"] != "read:workouts" || body["endpoint"] != "/api/workouts" || body["method"] != "POST" {
		t.Errorf("telemetry = scope_used:%v endpoint:%v method:%v", body["scope_used"], body["endpoint"], body["method"])
	}
}

// ---------------------------------------------------------------------------
// §1/§6(b): scope_used omitted when no single scope is known; endpoint +
// method still sent
// ---------------------------------------------------------------------------

func TestMiddlewareTelemetry_OmitsScopeUsedWhenUnknown(t *testing.T) {
	cases := map[string][]string{
		"no scopes (presence-only gate)": nil,
		"multiple scopes (never joined)": {"read:workouts", "write:workouts"},
	}
	for name, scopes := range cases {
		scopes := scopes
		t.Run(name, func(t *testing.T) {
			var captured []map[string]interface{}
			client := newTelemetryClient(t, activeOKResponse, &captured)

			var invoked bool
			handler := client.Middleware(scopes...)(okHandler(&invoked))

			req := httptest.NewRequest(http.MethodDelete, "/api/workouts/7", nil)
			req.Header.Set("Authorization", "Bearer ag_at_tok")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if len(captured) != 1 {
				t.Fatalf("expected 1 verify call, got %d", len(captured))
			}
			body := captured[0]
			if _, present := body["scope_used"]; present {
				t.Errorf("scope_used must be omitted when no single scope is known, got %v", body["scope_used"])
			}
			if body["endpoint"] != "/api/workouts/7" {
				t.Errorf("endpoint = %v, want /api/workouts/7", body["endpoint"])
			}
			if body["method"] != "DELETE" {
				t.Errorf("method = %v, want DELETE", body["method"])
			}
		})
	}
}

// Direct client calls without telemetry must omit all three fields — the
// pre-1.10 body shape is unchanged (§5: no behavior change without error).
func TestValidate_NoTelemetryOmitsAllFields(t *testing.T) {
	var captured []map[string]interface{}
	client := newTelemetryClient(t, activeOKResponse, &captured)

	if _, err := client.Validate("ag_at_tok", []string{"read:workouts"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	body := captured[0]
	for _, field := range []string{"scope_used", "endpoint", "method"} {
		if _, present := body[field]; present {
			t.Errorf("%s must be omitted when no telemetry is provided, got %v", field, body[field])
		}
	}
}

// ---------------------------------------------------------------------------
// §1/§6(c): query-string strip + truncation caps (sanitization lives in the
// core, so direct caller-provided telemetry is sanitized too)
// ---------------------------------------------------------------------------

func TestTelemetry_SanitizationCaps(t *testing.T) {
	longPath := "/" + strings.Repeat("a", 600)

	var captured []map[string]interface{}
	client := newTelemetryClient(t, activeOKResponse, &captured)

	tel := &VerifyTelemetry{
		ScopeUsed: strings.Repeat("s", 150),
		Endpoint:  longPath + "?token=leaky&ssn=123-45-6789",
		Method:    "delete" + strings.Repeat("x", 30),
	}
	if _, err := client.ValidateWithTelemetry("ag_at_tok", nil, tel); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body := captured[0]
	endpoint, _ := body["endpoint"].(string)
	if strings.Contains(endpoint, "?") || strings.Contains(endpoint, "ssn") {
		t.Errorf("endpoint must have the query string stripped, got %q", endpoint)
	}
	if len(endpoint) != 500 {
		t.Errorf("endpoint length = %d, want truncation to 500", len(endpoint))
	}
	if !strings.HasPrefix(longPath, endpoint) {
		t.Errorf("endpoint is not a prefix of the original path: %q", endpoint)
	}
	scopeUsed, _ := body["scope_used"].(string)
	if len(scopeUsed) != 120 {
		t.Errorf("scope_used length = %d, want truncation to 120", len(scopeUsed))
	}
	method, _ := body["method"].(string)
	if len(method) != 20 || !strings.HasPrefix(method, "DELETE") {
		t.Errorf("method = %q, want uppercased and truncated to 20", method)
	}
}

func TestTelemetry_QueryOnlyEndpointOmitted(t *testing.T) {
	var captured []map[string]interface{}
	client := newTelemetryClient(t, activeOKResponse, &captured)

	// An endpoint that is nothing but a query string sanitizes to empty and
	// must be omitted, not sent as "".
	tel := &VerifyTelemetry{Endpoint: "?a=b", Method: "GET"}
	if _, err := client.ValidateWithTelemetry("ag_at_tok", nil, tel); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	body := captured[0]
	if _, present := body["endpoint"]; present {
		t.Errorf("endpoint should be omitted when it sanitizes to empty, got %v", body["endpoint"])
	}
	if body["method"] != "GET" {
		t.Errorf("method = %v, want GET", body["method"])
	}
}

// ---------------------------------------------------------------------------
// §4/§6(d): active + bound_exceeded is a denial — 403, handler NOT invoked,
// hosted fields passed through verbatim
// ---------------------------------------------------------------------------

func TestMiddleware_ActiveBoundExceededDenied(t *testing.T) {
	var captured []map[string]interface{}
	client := newTelemetryClient(t, `{
		"active": true,
		"scopes": ["pay:invoices"],
		"app_id": "app_1",
		"error": "bound_exceeded",
		"error_description": "Spending bound exhausted for this period.",
		"bound": {"kind": "spend", "limit": 100, "used": 100},
		"renewal": {"renews_at": "2026-10-01T00:00:00Z"}
	}`, &captured)

	var invoked bool
	handler := client.Middleware("pay:invoices")(okHandler(&invoked))

	req := httptest.NewRequest(http.MethodPost, "/api/invoices/pay", nil)
	req.Header.Set("Authorization", "Bearer ag_at_tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if invoked {
		t.Fatal("handler must NOT be invoked on an active+error refusal")
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("403 body is not valid JSON: %v", err)
	}
	if body["error"] != "bound_exceeded" {
		t.Errorf("error = %v, want bound_exceeded", body["error"])
	}
	if body["error_description"] != "Spending bound exhausted for this period." {
		t.Errorf("error_description not passed through verbatim: %v", body["error_description"])
	}
	bound, ok := body["bound"].(map[string]interface{})
	if !ok || bound["kind"] != "spend" || bound["limit"] != float64(100) {
		t.Errorf("bound not passed through verbatim: %v", body["bound"])
	}
	renewal, ok := body["renewal"].(map[string]interface{})
	if !ok || renewal["renews_at"] != "2026-10-01T00:00:00Z" {
		t.Errorf("renewal not passed through verbatim: %v", body["renewal"])
	}
	if !IsCallRefused(activeErrorDenial(&TokenInfo{Active: true, Error: "bound_exceeded"}, nil, nil)) {
		t.Error("IsCallRefused should classify a bound_exceeded denial")
	}
}

// ---------------------------------------------------------------------------
// §4/§6(e): active + insufficient_scope → 403 step-up shape (§6.4)
// ---------------------------------------------------------------------------

func TestMiddleware_ActiveInsufficientScopeStepUpShape(t *testing.T) {
	var captured []map[string]interface{}
	client := newTelemetryClient(t, `{
		"active": true,
		"scopes": ["read:workouts"],
		"app_id": "app_1",
		"error": "insufficient_scope",
		"required_scope": "write:workouts"
	}`, &captured)

	var invoked bool
	handler := client.Middleware("write:workouts")(okHandler(&invoked))

	req := httptest.NewRequest(http.MethodPost, "/api/workouts", nil)
	req.Header.Set("Authorization", "Bearer ag_at_tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if invoked {
		t.Fatal("handler must NOT be invoked on an active insufficient_scope refusal")
	}

	var body struct {
		Error         string   `json:"error"`
		RequiredScope string   `json:"required_scope"`
		GrantedScopes []string `json:"granted_scopes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("403 body is not valid JSON: %v", err)
	}
	if body.Error != "insufficient_scope" {
		t.Errorf("error = %q, want insufficient_scope", body.Error)
	}
	if body.RequiredScope != "write:workouts" {
		t.Errorf("required_scope = %q, want write:workouts (hosted value)", body.RequiredScope)
	}
	if len(body.GrantedScopes) != 1 || body.GrantedScopes[0] != "read:workouts" {
		t.Errorf("granted_scopes = %v, want [read:workouts]", body.GrantedScopes)
	}
}

// ---------------------------------------------------------------------------
// §4/§6(f): unknown error string on an active response → 403 fail-closed
// ---------------------------------------------------------------------------

func TestMiddleware_ActiveUnknownErrorFailsClosed(t *testing.T) {
	var captured []map[string]interface{}
	client := newTelemetryClient(t, `{
		"active": true,
		"scopes": ["read:workouts"],
		"app_id": "app_1",
		"error": "quota_wave_refusal_v3",
		"surprise_field": {"do": "not leak"}
	}`, &captured)

	var invoked bool
	handler := client.Middleware("read:workouts")(okHandler(&invoked))

	req := httptest.NewRequest(http.MethodGet, "/api/workouts", nil)
	req.Header.Set("Authorization", "Bearer ag_at_tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if invoked {
		t.Fatal("handler must NOT be invoked on an unknown active-error refusal")
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("403 body is not valid JSON: %v", err)
	}
	if body["error"] != "quota_wave_refusal_v3" {
		t.Errorf("error = %v, want the hosted code echoed", body["error"])
	}
	if body["error_description"] != "Call refused by the authorization service." {
		t.Errorf("error_description = %v, want the generic fail-closed message", body["error_description"])
	}
	if _, present := body["surprise_field"]; present {
		t.Error("unknown hosted fields must not be forwarded on an unknown refusal")
	}
}

// §5: an active response WITHOUT an error field behaves exactly as before.
func TestValidate_ActiveNoErrorUnchanged(t *testing.T) {
	var captured []map[string]interface{}
	client := newTelemetryClient(t, activeOKResponse, &captured)

	info, err := client.Validate("ag_at_tok", []string{"read:workouts"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.Active || info.AppID != "app_1" {
		t.Fatalf("unexpected TokenInfo: %+v", info)
	}
}
