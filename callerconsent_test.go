package agentadmit

// CallerConsentMiddleware tests: classify the caller from credential
// structure before any consent check; route each class to its OWN isolated
// path; fail closed on a denied verdict or an unreachable ledger; and never
// let one class inherit another's decision.

import (
	"context"
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
	client := newCallerConsentClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(activeBody))
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
}

func TestCallerConsent_ExternalDeniedMissingScope(t *testing.T) {
	client := newCallerConsentClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(activeBody))
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
	if !strings.Contains(rec.Body.String(), "insufficient_scope") {
		t.Fatalf("expected insufficient_scope body, got %s", rec.Body.String())
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

func TestCallerConsent_ExternalAllowsWithoutConsentBlock(t *testing.T) {
	client := newCallerConsentClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(activeBody))
	})
	called, next := nextRecorder()
	rec := httptest.NewRecorder()

	client.CallerConsentMiddleware(CallerConsentOptions{})(next).ServeHTTP(rec, agentReq())

	if !called.Load() {
		t.Fatalf("next handler must run; status=%d body=%s", rec.Code, rec.Body.String())
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
