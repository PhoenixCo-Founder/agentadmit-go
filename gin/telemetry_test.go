package aggin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PhoenixCo-Founder/agentadmit-go"
	"github.com/gin-gonic/gin"
)

// fakeVerifyCapture is fakeVerify plus capture of every verify request body.
func fakeVerifyCapture(t *testing.T, response string, captured *[]map[string]interface{}) *agentadmit.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]interface{}
		_ = json.Unmarshal(raw, &body)
		*captured = append(*captured, body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(srv.Close)

	client, err := agentadmit.New(agentadmit.Config{
		APIKey:     "aa_test_abc",
		VerifyURL:  srv.URL,
		APIURL:     srv.URL,
		MaxRetries: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// The gin adapter must send the same per-call telemetry as the core
// middleware: the enforced scope, the request path (query stripped), and
// the uppercase method.
func TestMiddleware_SendsTelemetry(t *testing.T) {
	var captured []map[string]interface{}
	client := fakeVerifyCapture(t,
		`{"active":true,"scopes":["read:orders"],"app_id":"app_1","user_id":"user_1"}`, &captured)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/orders/:id", Middleware(client, "read:orders"), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/orders/42?debug=1", nil)
	req.Header.Set("Authorization", "Bearer ag_at_tok")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(captured) != 1 {
		t.Fatalf("expected 1 verify call, got %d", len(captured))
	}
	body := captured[0]
	if body["scope_used"] != "read:orders" {
		t.Errorf("scope_used = %v, want read:orders", body["scope_used"])
	}
	if body["endpoint"] != "/orders/42" {
		t.Errorf("endpoint = %v, want /orders/42 (query stripped)", body["endpoint"])
	}
	if body["method"] != "GET" {
		t.Errorf("method = %v, want GET", body["method"])
	}
}

// An active response carrying error: bound_exceeded is a refusal — the gin
// adapter must abort with 403 and never run the handler.
func TestMiddleware_ActiveBoundExceeded403(t *testing.T) {
	var captured []map[string]interface{}
	client := fakeVerifyCapture(t,
		`{"active":true,"scopes":["pay:invoices"],"app_id":"app_1","error":"bound_exceeded","error_description":"Spending bound exhausted.","bound":{"kind":"spend","limit":100}}`,
		&captured)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	invoked := false
	r.POST("/pay", Middleware(client, "pay:invoices"), func(c *gin.Context) {
		invoked = true
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodPost, "/pay", nil)
	req.Header.Set("Authorization", "Bearer ag_at_tok")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if invoked {
		t.Fatal("handler must NOT be invoked on an active+error refusal")
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("403 body is not valid JSON: %v", err)
	}
	if body["error"] != "bound_exceeded" || body["error_description"] != "Spending bound exhausted." {
		t.Errorf("hosted refusal fields not passed through: %v", body)
	}
	if bound, ok := body["bound"].(map[string]interface{}); !ok || bound["kind"] != "spend" {
		t.Errorf("bound not passed through verbatim: %v", body["bound"])
	}
}
