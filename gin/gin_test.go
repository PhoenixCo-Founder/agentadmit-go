package aggin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PhoenixCo-Founder/agentadmit-go"
	"github.com/gin-gonic/gin"
)

// fakeVerify returns a Client wired to an httptest server that answers
// /api/v1/verify with the given response body.
func fakeVerify(t *testing.T, status int, body map[string]interface{}) *agentadmit.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)

	client, err := agentadmit.New(agentadmit.Config{
		APIKey:    "aa_test_abc",
		VerifyURL: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func serve(mw gin.HandlerFunc, authHeader string) (*httptest.ResponseRecorder, *agentadmit.TokenInfo) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	var seen *agentadmit.TokenInfo
	r.GET("/x", mw, func(c *gin.Context) {
		seen = GetTokenInfo(c)
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec, seen
}

func TestMiddleware_ValidToken(t *testing.T) {
	client := fakeVerify(t, 200, map[string]interface{}{
		"active": true, "scopes": []string{"read:orders"}, "app_id": "app_1",
		"user_id": "user_1", "connection_id": "conn_1",
	})

	rec, info := serve(Middleware(client, "read:orders"), "Bearer ag_at_tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if info == nil || info.UserID != "user_1" || info.ConnectionID != "conn_1" {
		t.Fatalf("TokenInfo not propagated to handler: %+v", info)
	}
}

func TestMiddleware_NoAuthHeaderPassesThrough(t *testing.T) {
	client := fakeVerify(t, 200, map[string]interface{}{"active": false, "error": "invalid_token"})

	rec, info := serve(Middleware(client, "read:orders"), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected passthrough 200, got %d", rec.Code)
	}
	if info != nil {
		t.Fatalf("expected no TokenInfo for non-agent request, got %+v", info)
	}
}

func TestMiddleware_InactiveToken401(t *testing.T) {
	client := fakeVerify(t, 200, map[string]interface{}{"active": false, "error": "token_expired"})

	rec, _ := serve(Middleware(client), "Bearer ag_at_tok")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMiddleware_InsufficientScopes403(t *testing.T) {
	client := fakeVerify(t, 200, map[string]interface{}{
		"active": true, "scopes": []string{"read:orders"}, "app_id": "app_1", "user_id": "user_1",
	})

	rec, _ := serve(Middleware(client, "write:orders"), "Bearer ag_at_tok")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMiddleware_ServiceError503(t *testing.T) {
	client := fakeVerify(t, 500, map[string]interface{}{"error": "boom"})

	rec, _ := serve(Middleware(client), "Bearer ag_at_tok")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRequireAgent_MissingToken401(t *testing.T) {
	client := fakeVerify(t, 200, map[string]interface{}{"active": true})

	rec, _ := serve(RequireAgent(client), "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got %d", rec.Code)
	}
}

func TestRequireAgent_ValidToken(t *testing.T) {
	client := fakeVerify(t, 200, map[string]interface{}{
		"active": true, "scopes": []string{"read:orders"}, "app_id": "app_1", "user_id": "user_1",
	})

	rec, info := serve(RequireAgent(client, "read:orders"), "Bearer ag_at_tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if info == nil {
		t.Fatal("TokenInfo not propagated to handler")
	}
}
