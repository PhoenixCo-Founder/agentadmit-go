package agentadmit

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// The 403 written for an insufficient-scope failure must follow spec §6.4:
// name the unmet scope (required_scope) and the scopes the token carries
// (granted_scopes) so the agent can relay a precise step-up request to the
// user.
func TestWriteMiddlewareErrorInsufficientScopeBody(t *testing.T) {
	scopeErr := newError(ErrCodeInsufficientScopes, "token missing required scopes: [write:data]", nil)
	scopeErr.RequiredScopes = []string{"write:data"}
	scopeErr.GrantedScopes = []string{"read:profile", "read:history"}

	rec := httptest.NewRecorder()
	writeMiddlewareError(rec, scopeErr)

	if rec.Code != 403 {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	var body struct {
		Error         string   `json:"error"`
		RequiredScope string   `json:"required_scope"`
		GrantedScopes []string `json:"granted_scopes"`
		Message       string   `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if body.Error != "insufficient_scope" {
		t.Errorf("error = %q, want insufficient_scope", body.Error)
	}
	if body.RequiredScope != "write:data" {
		t.Errorf("required_scope = %q, want write:data", body.RequiredScope)
	}
	if len(body.GrantedScopes) != 2 || body.GrantedScopes[0] != "read:profile" {
		t.Errorf("granted_scopes = %v, want [read:profile read:history]", body.GrantedScopes)
	}
	if body.Message == "" {
		t.Error("message is empty")
	}
}

// When the unmet scope is not known locally (server-side denial), the body
// must still be valid: no required_scope key, granted_scopes always an array.
func TestWriteMiddlewareErrorInsufficientScopeUnknownRequired(t *testing.T) {
	scopeErr := newError(ErrCodeInsufficientScopes, "token is not active: insufficient_scope", nil)

	rec := httptest.NewRecorder()
	writeMiddlewareError(rec, scopeErr)

	if rec.Code != 403 {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if _, present := body["required_scope"]; present {
		t.Error("required_scope should be omitted when unknown")
	}
	if _, ok := body["granted_scopes"].([]interface{}); !ok {
		t.Errorf("granted_scopes should be a JSON array, got %T", body["granted_scopes"])
	}
}
