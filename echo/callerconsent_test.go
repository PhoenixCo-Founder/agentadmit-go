package agecho

// CallerConsent (Echo adapter) tests. The adapter wraps the core
// CallerConsentMiddleware, so these tests pin the WRAPPER contract: denials
// are written by the core middleware and end the chain, permits carry caller
// class / consent verdict / TokenInfo into the Echo context, and the core
// semantics (consent before scope, ledger fallback fail-closed) hold through
// the adapter.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/PhoenixCo-Founder/agentadmit-go"
	"github.com/labstack/echo/v4"
)

const activeGrantedBody = `{"active":true,"user_id":"user_1","connection_id":"conn_1","scopes":["read:things"],"app_id":"app_1","consent":{"caller_class":"external_agent","granted":true,"source":"setting","evaluated_at":"x"}}`

const activeNoVerdictBody = `{"active":true,"user_id":"user_1","connection_id":"conn_1","scopes":["read:things"],"app_id":"app_1"}`

const activeDeniedBody = `{"active":true,"user_id":"user_1","connection_id":"conn_1","scopes":["read:things"],"app_id":"app_1","consent":{"caller_class":"external_agent","granted":false,"source":"setting","evaluated_at":"x"}}`

func newConsentClient(t *testing.T, verifyBody string, consentStatus int, consentBody string, consentHits *atomic.Int32) *agentadmit.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/consent/check") {
			if consentHits != nil {
				consentHits.Add(1)
			}
			w.WriteHeader(consentStatus)
			w.Write([]byte(consentBody))
			return
		}
		w.Write([]byte(verifyBody))
	}))
	t.Cleanup(server.Close)
	client, err := agentadmit.New(agentadmit.Config{
		APIKey:     "aa_test_dummy",
		VerifyURL:  server.URL,
		APIURL:     server.URL,
		MaxRetries: 0,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func serveConsent(client *agentadmit.Client, opts agentadmit.CallerConsentOptions, authorization string) (*httptest.ResponseRecorder, *bool, *string, **agentadmit.TokenInfo) {
	handlerRan := false
	callerClass := ""
	var tokenInfo *agentadmit.TokenInfo
	e := echo.New()
	e.GET("/api/records", func(c echo.Context) error {
		handlerRan = true
		callerClass = agentadmit.CallerClassFromContext(c.Request().Context())
		tokenInfo = GetTokenInfo(c)
		return c.String(http.StatusOK, "ok")
	}, CallerConsent(client, opts))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/records", nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	e.ServeHTTP(w, req)
	return w, &handlerRan, &callerClass, &tokenInfo
}

func TestCallerConsent_ExternalPermitCarriesContext(t *testing.T) {
	var hits atomic.Int32
	client := newConsentClient(t, activeGrantedBody, 200, "{}", &hits)
	w, ran, class, info := serveConsent(client, agentadmit.CallerConsentOptions{RequiredScope: "read:things"}, "Bearer ag_at_dummy")
	if w.Code != 200 || !*ran {
		t.Fatalf("want permit, got %d handlerRan=%v body=%s", w.Code, *ran, w.Body.String())
	}
	if *class != agentadmit.CallerClassExternalAgent {
		t.Fatalf("caller class not carried into echo chain: %q", *class)
	}
	if *info == nil || (*info).UserID != "user_1" {
		t.Fatalf("TokenInfo not stored for GetTokenInfo: %+v", *info)
	}
	if hits.Load() != 0 {
		t.Fatalf("inline verdict must not hit the ledger, got %d", hits.Load())
	}
}

func TestCallerConsent_ConsentDeniedBeforeScope(t *testing.T) {
	client := newConsentClient(t, activeDeniedBody, 200, "{}", nil)
	w, ran, _, _ := serveConsent(client, agentadmit.CallerConsentOptions{RequiredScope: "write:things"}, "Bearer ag_at_dummy")
	if *ran {
		t.Fatal("handler must not run on denied consent")
	}
	if w.Code != 403 || !strings.Contains(w.Body.String(), "consent_not_granted") {
		t.Fatalf("want 403 consent_not_granted, got %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "granted_scopes") {
		t.Fatalf("denied consent leaked scope state: %s", w.Body.String())
	}
}

func TestCallerConsent_AbsentVerdictLedgerAllow(t *testing.T) {
	var hits atomic.Int32
	client := newConsentClient(t, activeNoVerdictBody, 200,
		`{"caller_class":"external_agent","granted":true,"source":"app_default","evaluated_at":"x"}`, &hits)
	w, ran, _, _ := serveConsent(client, agentadmit.CallerConsentOptions{}, "Bearer ag_at_dummy")
	if w.Code != 200 || !*ran {
		t.Fatalf("want ledger-resolved permit, got %d handlerRan=%v body=%s", w.Code, *ran, w.Body.String())
	}
	if hits.Load() != 1 {
		t.Fatalf("want exactly 1 ledger fallback call, got %d", hits.Load())
	}
}

func TestCallerConsent_AbsentVerdictLedgerDeny(t *testing.T) {
	client := newConsentClient(t, activeNoVerdictBody, 200,
		`{"caller_class":"external_agent","granted":false,"source":"setting","evaluated_at":"x"}`, nil)
	w, ran, _, _ := serveConsent(client, agentadmit.CallerConsentOptions{}, "Bearer ag_at_dummy")
	if *ran || w.Code != 403 || !strings.Contains(w.Body.String(), "consent_not_granted") {
		t.Fatalf("want 403 consent_not_granted, got %d handlerRan=%v %s", w.Code, *ran, w.Body.String())
	}
}

func TestCallerConsent_AbsentVerdictLedgerErrorFailsClosed(t *testing.T) {
	client := newConsentClient(t, activeNoVerdictBody, 500, `{"error":"boom"}`, nil)
	w, ran, _, _ := serveConsent(client, agentadmit.CallerConsentOptions{}, "Bearer ag_at_dummy")
	if *ran || w.Code != 503 || !strings.Contains(w.Body.String(), "consent_unavailable") {
		t.Fatalf("want 503 consent_unavailable, got %d handlerRan=%v %s", w.Code, *ran, w.Body.String())
	}
}

func TestCallerConsent_MissingScopeAfterConsent(t *testing.T) {
	client := newConsentClient(t, activeGrantedBody, 200, "{}", nil)
	w, ran, _, _ := serveConsent(client, agentadmit.CallerConsentOptions{RequiredScope: "write:things"}, "Bearer ag_at_dummy")
	if *ran || w.Code != 403 {
		t.Fatalf("want 403, got %d handlerRan=%v", w.Code, *ran)
	}
	body := w.Body.String()
	if !strings.Contains(body, "insufficient_scope") || !strings.Contains(body, `"write:things"`) || !strings.Contains(body, "granted_scopes") {
		t.Fatalf("want spec step-up body, got %s", body)
	}
}

func TestCallerConsent_HumanPassthrough(t *testing.T) {
	var hits atomic.Int32
	client := newConsentClient(t, activeGrantedBody, 200, "{}", &hits)
	w, ran, class, _ := serveConsent(client, agentadmit.CallerConsentOptions{}, "Bearer session_jwt")
	if w.Code != 200 || !*ran {
		t.Fatalf("human session must pass through, got %d handlerRan=%v", w.Code, *ran)
	}
	if *class != agentadmit.CallerClassHumanSession {
		t.Fatalf("want human_session class in context, got %q", *class)
	}
	if hits.Load() != 0 {
		t.Fatalf("ungated human path must never call the ledger, got %d", hits.Load())
	}
}

func TestCallerConsent_InAppAILedgerGated(t *testing.T) {
	var hits atomic.Int32
	client := newConsentClient(t, activeGrantedBody, 200,
		`{"caller_class":"in_app_ai","granted":false,"source":"setting","evaluated_at":"x"}`, &hits)
	w, ran, _, _ := serveConsent(client, agentadmit.CallerConsentOptions{
		ClassifyNonAgent:   func(*http.Request) string { return agentadmit.CallerClassInAppAI },
		ResolveDataOwnerID: func(*http.Request) string { return "user_8842" },
	}, "Bearer internal_service_token")
	if *ran || w.Code != 403 || !strings.Contains(w.Body.String(), "in_app_ai") {
		t.Fatalf("want 403 in_app_ai denial, got %d handlerRan=%v %s", w.Code, *ran, w.Body.String())
	}
	if hits.Load() != 1 {
		t.Fatalf("in_app_ai must consult the ledger exactly once, got %d", hits.Load())
	}
}
