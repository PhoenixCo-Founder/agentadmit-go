package agentadmit

// CallerConsentMiddleware tests: classify the caller from credential
// structure before any consent check; route each class to its OWN isolated
// path; fail closed on a denied verdict or an unreachable ledger; and never
// let one class inherit another's decision.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newCallerConsentClient builds a client whose verify AND management API both
// point at the same test server (127.0.0.1, so http is allowed).
func newCallerConsentClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := New(Config{
		APIKey:     "aa_test_dummy",
		VerifyURL:  server.URL,
		APIURL:     server.URL,
		MaxRetries: 0,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	client.sleep = func(_ context.Context, _ time.Duration) error { return nil }
	return client
}

func nextRecorder() (*atomic.Bool, http.Handler) {
	called := &atomic.Bool{}
	return called, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusOK)
	})
}

func agentReq() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/records", nil)
	r.Header.Set("Authorization", "Bearer ag_at_dummy")
	return r
}

func humanReq() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/records", nil)
	r.Header.Set("Authorization", "Bearer session_jwt")
	return r
}

const activeBody = `{"active":true,"user_id":"user_1","connection_id":"conn_1","scopes":["read:things"],"app_id":"app_1"}`

// activeGrantedBody carries an inline granted external-agent verdict, so
// tests exercising post-consent behavior (e.g. the scope check) do not
// depend on the Consent Ledger fallback.
const activeGrantedBody = `{"active":true,"user_id":"user_1","connection_id":"conn_1","scopes":["read:things"],"app_id":"app_1","consent":{"caller_class":"external_agent","granted":true,"source":"setting","evaluated_at":"x"}}`

// externalPathHandler serves BOTH endpoints of the external-agent path from
// one test server: the Consent Ledger fallback (/api/v1/consent/check, which
// answers consentStatus/consentBody and records each hit plus the raw request
// body) and hosted verify (every other path, which answers verifyBody).
func externalPathHandler(verifyBody string, consentStatus int, consentBody string, consentHits *atomic.Int32, lastConsentReq *atomic.Value) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/consent/check") {
			if consentHits != nil {
				consentHits.Add(1)
			}
			if lastConsentReq != nil {
				b, _ := io.ReadAll(r.Body)
				lastConsentReq.Store(string(b))
			}
			w.WriteHeader(consentStatus)
			_, _ = w.Write([]byte(consentBody))
			return
		}
		_, _ = w.Write([]byte(verifyBody))
	}
}

// ---------------------------------------------------------------------------
// ClassifyCaller
// ---------------------------------------------------------------------------

func TestClassifyCaller_AgentToken(t *testing.T) {
	if got := ClassifyCaller(agentReq(), CallerConsentOptions{}); got != CallerClassExternalAgent {
		t.Fatalf("expected external_agent, got %q", got)
	}
}

func TestClassifyCaller_DefaultsToHuman(t *testing.T) {
	if got := ClassifyCaller(humanReq(), CallerConsentOptions{}); got != CallerClassHumanSession {
		t.Fatalf("expected human_session, got %q", got)
	}
}

func TestClassifyCaller_HonorsNonAgentClassifier(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/records", nil)
	r.Header.Set("X-Internal-AI", "secret")
	opts := CallerConsentOptions{
		ClassifyNonAgent: func(r *http.Request) string {
			if r.Header.Get("X-Internal-AI") == "secret" {
				return CallerClassInAppAI
			}
			return CallerClassHumanSession
		},
	}
	if got := ClassifyCaller(r, opts); got != CallerClassInAppAI {
		t.Fatalf("expected in_app_ai, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// external_agent path
// ---------------------------------------------------------------------------

func TestCallerConsent_ExternalAllowsWithScope(t *testing.T) {
	var verifyBody map[string]interface{}
	client := newCallerConsentClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&verifyBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(activeGrantedBody))
	})
	called, next := nextRecorder()
	rec := httptest.NewRecorder()

	req := agentReq()
	client.CallerConsentMiddleware(CallerConsentOptions{RequiredScope: "read:things"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := CallerClassFromContext(r.Context()); got != CallerClassExternalAgent {
			t.Errorf("expected external_agent in context, got %q", got)
		}
		if TokenFromContext(r.Context()) == nil {
			t.Error("expected TokenInfo in context")
		}
		next.ServeHTTP(w, r)
	})).ServeHTTP(rec, req)

	if !called.Load() {
		t.Fatalf("next handler must run; status=%d body=%s", rec.Code, rec.Body.String())
	}
	if verifyBody["scope_used"] != "read:things" || verifyBody["consent_first"] != true {
		t.Fatalf("caller-consent telemetry = %#v, want scope_used + consent_first", verifyBody)
	}
	if verifyBody["endpoint"] != "/api/records" || verifyBody["method"] != "GET" {
		t.Fatalf("request telemetry = %#v, want path-only endpoint + method", verifyBody)
	}
}

func TestCallerConsent_ExternalDeniedMissingScope(t *testing.T) {
	client := newCallerConsentClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(activeGrantedBody))
	})
	called, next := nextRecorder()
	rec := httptest.NewRecorder()

	client.CallerConsentMiddleware(CallerConsentOptions{RequiredScope: "write:things"})(next).ServeHTTP(rec, agentReq())

	if called.Load() {
		t.Fatal("next handler must NOT run")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	// The spec §6.4 step-up body (v1.4.1 format) must be preserved exactly:
	// error, required_scope, granted_scopes.
	body := rec.Body.String()
	if !strings.Contains(body, "insufficient_scope") {
		t.Fatalf("expected insufficient_scope body, got %s", body)
	}
	if !strings.Contains(body, `"required_scope":"write:things"`) {
		t.Fatalf("expected required_scope in body, got %s", body)
	}
	if !strings.Contains(body, `"granted_scopes":["read:things"]`) {
		t.Fatalf("expected granted_scopes in body, got %s", body)
	}
}

func TestCallerConsent_ExternalDeniedWhenConsentDenied(t *testing.T) {
	body := `{"active":true,"user_id":"user_1","connection_id":"conn_1","scopes":["read:things"],"app_id":"app_1","consent":{"caller_class":"external_agent","granted":false,"source":"setting"}}`
	client := newCallerConsentClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	called, next := nextRecorder()
	rec := httptest.NewRecorder()

	client.CallerConsentMiddleware(CallerConsentOptions{})(next).ServeHTTP(rec, agentReq())

	if called.Load() {
		t.Fatal("next handler must NOT run")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "consent_not_granted") {
		t.Fatalf("expected consent_not_granted body, got %s", rec.Body.String())
	}
}

// Rewritten from TestCallerConsent_ExternalAllowsWithoutConsentBlock, which
// pinned the old fail-open behavior (absent verdict = platform default =
// allow). That assumption is disproven: the hosted service deliberately
// omits the consent block when its consent-store read fails, so an absent
// verdict must be resolved through the Consent Ledger instead.
func TestCallerConsent_ExternalAbsentVerdictFallsBackToLedgerAllow(t *testing.T) {
	consentHits := &atomic.Int32{}
	lastConsentReq := &atomic.Value{}
	client := newCallerConsentClient(t, externalPathHandler(
		activeBody, // no consent block on the verify response
		http.StatusOK,
		`{"caller_class":"external_agent","granted":true,"source":"app_default","evaluated_at":"x"}`,
		consentHits, lastConsentReq,
	))
	called, next := nextRecorder()
	rec := httptest.NewRecorder()

	client.CallerConsentMiddleware(CallerConsentOptions{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := TokenFromContext(r.Context())
		if info == nil || info.Consent == nil || !info.Consent.Granted {
			t.Error("expected the ledger-resolved granted verdict on the context TokenInfo")
		}
		next.ServeHTTP(w, r)
	})).ServeHTTP(rec, agentReq())

	if !called.Load() {
		t.Fatalf("next handler must run; status=%d body=%s", rec.Code, rec.Body.String())
	}
	if consentHits.Load() != 1 {
		t.Fatalf("expected exactly 1 /consent/check call, got %d", consentHits.Load())
	}
	var got struct {
		AppUserID   string `json:"app_user_id"`
		CallerClass string `json:"caller_class"`
	}
	raw, _ := lastConsentReq.Load().(string)
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode /consent/check request: %v (raw=%s)", err, raw)
	}
	if got.CallerClass != CallerClassExternalAgent {
		t.Fatalf("expected caller_class external_agent on the ledger call, got %q", got.CallerClass)
	}
	if got.AppUserID != "user_1" {
		t.Fatalf("expected app_user_id user_1 (the token's owner), got %q", got.AppUserID)
	}
}

func TestCallerConsent_ExternalAbsentVerdictLedgerDenies(t *testing.T) {
	consentHits := &atomic.Int32{}
	client := newCallerConsentClient(t, externalPathHandler(
		activeBody,
		http.StatusOK,
		`{"caller_class":"external_agent","granted":false,"source":"setting","evaluated_at":"x"}`,
		consentHits, nil,
	))
	called, next := nextRecorder()
	rec := httptest.NewRecorder()

	client.CallerConsentMiddleware(CallerConsentOptions{})(next).ServeHTTP(rec, agentReq())

	if called.Load() {
		t.Fatal("next handler must NOT run")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "consent_not_granted") {
		t.Fatalf("expected consent_not_granted body, got %s", rec.Body.String())
	}
	if consentHits.Load() != 1 {
		t.Fatalf("expected exactly 1 /consent/check call, got %d", consentHits.Load())
	}
}

func TestCallerConsent_ExternalAbsentVerdictLedgerErrorFailsClosed(t *testing.T) {
	client := newCallerConsentClient(t, externalPathHandler(
		activeBody,
		http.StatusInternalServerError, `{"error":"boom"}`,
		nil, nil,
	))
	called, next := nextRecorder()
	rec := httptest.NewRecorder()

	client.CallerConsentMiddleware(CallerConsentOptions{})(next).ServeHTTP(rec, agentReq())

	if called.Load() {
		t.Fatal("next handler must NOT run")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "consent_unavailable") {
		t.Fatalf("expected consent_unavailable body, got %s", rec.Body.String())
	}
}

func TestCallerConsent_ExternalAbsentVerdictNoOwnerFailsClosed(t *testing.T) {
	consentHits := &atomic.Int32{}
	client := newCallerConsentClient(t, externalPathHandler(
		`{"active":true,"connection_id":"conn_1","scopes":["read:things"],"app_id":"app_1"}`, // no user_id
		http.StatusOK, `{"caller_class":"external_agent","granted":true,"source":"setting","evaluated_at":"x"}`,
		consentHits, nil,
	))
	called, next := nextRecorder()
	rec := httptest.NewRecorder()

	client.CallerConsentMiddleware(CallerConsentOptions{})(next).ServeHTTP(rec, agentReq())

	if called.Load() {
		t.Fatal("next handler must NOT run")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "consent_unavailable") {
		t.Fatalf("expected consent_unavailable body, got %s", rec.Body.String())
	}
	if consentHits.Load() != 0 {
		t.Fatalf("no owner is resolvable, so the ledger must not be called; got %d calls", consentHits.Load())
	}
}

func TestCallerConsent_ExternalMalformedVerdictFallsBackToLedger(t *testing.T) {
	// A type-malformed consent block is dropped by decodeVerifyResponse
	// (nil verdict) and must behave exactly like an absent one: ledger
	// fallback, never a grant.
	consentHits := &atomic.Int32{}
	client := newCallerConsentClient(t, externalPathHandler(
		`{"active":true,"user_id":"user_1","connection_id":"conn_1","scopes":["read:things"],"app_id":"app_1","consent":{"granted":"yes"}}`,
		http.StatusOK,
		`{"caller_class":"external_agent","granted":true,"source":"setting","evaluated_at":"x"}`,
		consentHits, nil,
	))
	called, next := nextRecorder()
	rec := httptest.NewRecorder()

	client.CallerConsentMiddleware(CallerConsentOptions{})(next).ServeHTTP(rec, agentReq())

	if !called.Load() {
		t.Fatalf("next handler must run; status=%d body=%s", rec.Code, rec.Body.String())
	}
	if consentHits.Load() != 1 {
		t.Fatalf("expected exactly 1 /consent/check call, got %d", consentHits.Load())
	}
}

func TestCallerConsent_ExternalConsentDeniedBeforeScopeCheck(t *testing.T) {
	// Patent FIG. 3 stage order: the owner's consent verdict is evaluated
	// BEFORE any scope check. A denied caller that ALSO lacks the required
	// scope gets only consent_not_granted — no scope state, no granted_scopes,
	// no step-up guidance.
	consentHits := &atomic.Int32{}
	client := newCallerConsentClient(t, externalPathHandler(
		`{"active":true,"user_id":"user_1","connection_id":"conn_1","scopes":["read:things"],"app_id":"app_1","consent":{"caller_class":"external_agent","granted":false,"source":"setting","evaluated_at":"x"}}`,
		http.StatusOK, `{"caller_class":"external_agent","granted":true,"source":"setting","evaluated_at":"x"}`,
		consentHits, nil,
	))
	called, next := nextRecorder()
	rec := httptest.NewRecorder()

	client.CallerConsentMiddleware(CallerConsentOptions{RequiredScope: "write:things"})(next).ServeHTTP(rec, agentReq())

	if called.Load() {
		t.Fatal("next handler must NOT run")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "consent_not_granted") {
		t.Fatalf("expected consent_not_granted body, got %s", body)
	}
	if strings.Contains(body, "granted_scopes") || strings.Contains(body, "insufficient_scope") {
		t.Fatalf("a denied-consent caller must learn nothing about scope state, got %s", body)
	}
	if consentHits.Load() != 0 {
		t.Fatalf("inline denied verdict must not trigger a ledger call; got %d calls", consentHits.Load())
	}
}

func TestCallerConsent_ExternalRejectsInvalidToken(t *testing.T) {
	client := newCallerConsentClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":false,"error":"invalid_token"}`))
	})
	called, next := nextRecorder()
	rec := httptest.NewRecorder()

	client.CallerConsentMiddleware(CallerConsentOptions{})(next).ServeHTTP(rec, agentReq())

	if called.Load() {
		t.Fatal("next handler must NOT run")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// in_app_ai path
// ---------------------------------------------------------------------------

func internalAiOptions() CallerConsentOptions {
	return CallerConsentOptions{
		ClassifyNonAgent:   func(*http.Request) string { return CallerClassInAppAI },
		ResolveDataOwnerID: func(*http.Request) string { return "user_8842" },
	}
}

func TestCallerConsent_InAppAiAllowsWhenGranted(t *testing.T) {
	client := newCallerConsentClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"caller_class":"in_app_ai","granted":true,"source":"setting","evaluated_at":"x"}`))
	})
	called, next := nextRecorder()
	rec := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodGet, "/api/records", nil)
	client.CallerConsentMiddleware(internalAiOptions())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := ConsentVerdictFromContext(r.Context()); v == nil || !v.Granted {
			t.Error("expected granted verdict in context")
		}
		next.ServeHTTP(w, r)
	})).ServeHTTP(rec, req)

	if !called.Load() {
		t.Fatalf("next handler must run; status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCallerConsent_InAppAiDeniedWhenDenied(t *testing.T) {
	client := newCallerConsentClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"caller_class":"in_app_ai","granted":false,"source":"setting","evaluated_at":"x"}`))
	})
	called, next := nextRecorder()
	rec := httptest.NewRecorder()

	client.CallerConsentMiddleware(internalAiOptions())(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if called.Load() {
		t.Fatal("next handler must NOT run")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestCallerConsent_InAppAiFailsClosedOnLedgerError(t *testing.T) {
	client := newCallerConsentClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	called, next := nextRecorder()
	rec := httptest.NewRecorder()

	client.CallerConsentMiddleware(internalAiOptions())(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if called.Load() {
		t.Fatal("next handler must NOT run")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "consent_unavailable") {
		t.Fatalf("expected consent_unavailable body, got %s", rec.Body.String())
	}
}

func TestCallerConsent_InAppAiRequiresOwnerResolver(t *testing.T) {
	client := newCallerConsentClient(t, func(w http.ResponseWriter, r *http.Request) {})
	called, next := nextRecorder()
	rec := httptest.NewRecorder()

	opts := CallerConsentOptions{ClassifyNonAgent: func(*http.Request) string { return CallerClassInAppAI }}
	client.CallerConsentMiddleware(opts)(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if called.Load() {
		t.Fatal("next handler must NOT run")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// human_session path
// ---------------------------------------------------------------------------

func TestCallerConsent_HumanDefersWithoutLedgerCall(t *testing.T) {
	ledgerCalls := &atomic.Int32{}
	client := newCallerConsentClient(t, func(w http.ResponseWriter, r *http.Request) {
		ledgerCalls.Add(1)
	})
	called, next := nextRecorder()
	rec := httptest.NewRecorder()

	req := humanReq()
	client.CallerConsentMiddleware(CallerConsentOptions{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := CallerClassFromContext(r.Context()); got != CallerClassHumanSession {
			t.Errorf("expected human_session in context, got %q", got)
		}
		next.ServeHTTP(w, r)
	})).ServeHTTP(rec, req)

	if !called.Load() {
		t.Fatal("human path must continue by default")
	}
	if ledgerCalls.Load() != 0 {
		t.Fatalf("Branch A is the app's own model; expected 0 ledger calls, got %d", ledgerCalls.Load())
	}
}

func TestCallerConsent_HumanGatedWhenGateHuman(t *testing.T) {
	client := newCallerConsentClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"caller_class":"human_session","granted":false,"source":"setting","evaluated_at":"x"}`))
	})
	called, next := nextRecorder()
	rec := httptest.NewRecorder()

	opts := CallerConsentOptions{
		GateHuman:          true,
		ResolveDataOwnerID: func(*http.Request) string { return "user_1" },
	}
	client.CallerConsentMiddleware(opts)(next).ServeHTTP(rec, humanReq())

	if called.Load() {
		t.Fatal("next handler must NOT run")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}
