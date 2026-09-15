package aggin

// Confirm-each-time (Gin adapter) tests. The refusal semantics and the 403
// body shape live in the core package; these tests pin the ADAPTER contract:
// a confirmation_required refusal aborts the Gin chain with the confirmation
// link intact, a malformed ceremony still fails closed, the *WithOptions
// variants carry the digest and summary without costing c.ShouldBindJSON its
// body, and an accepted retry exposes the consumed ceremony via
// GetActionConfirmation.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PhoenixCo-Founder/agentadmit-go"
	"github.com/gin-gonic/gin"
)

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
  "scopes": ["leak"],
  "user_id": "user_leak"
}`

func paySummary(_ *http.Request, body []byte) string {
	var parsed struct {
		Trainer string `json:"trainer"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "Pay someone"
	}
	return "Pay " + parsed.Trainer + " $50"
}

func payOptions() agentadmit.ScopeOptions {
	return agentadmit.ScopeOptions{ActionSummary: paySummary}
}

// Both option-bearing variants must surface the same 403 with the link.
func confirmingVariants(client *agentadmit.Client) map[string]gin.HandlerFunc {
	return map[string]gin.HandlerFunc{
		"MiddlewareWithOptions":   MiddlewareWithOptions(client, payOptions(), "write:payments"),
		"RequireAgentWithOptions": RequireAgentWithOptions(client, payOptions(), "write:payments"),
	}
}

func TestMiddleware_ConfirmationRequired403CarriesTheLink(t *testing.T) {
	for name := range confirmingVariants(nil) {
		t.Run(name, func(t *testing.T) {
			var captured []map[string]interface{}
			client := fakeVerifyCapture(t, confirmationRefusalResponse, &captured)
			mw := confirmingVariants(client)[name]

			gin.SetMode(gin.TestMode)
			r := gin.New()
			invoked := false
			r.POST("/api/payments", mw, func(c *gin.Context) {
				invoked = true
				c.String(http.StatusOK, "ok")
			})

			payload := `{"trainer":"alex","amount":50}`
			req := httptest.NewRequest(http.MethodPost, "/api/payments", strings.NewReader(payload))
			req.Header.Set("Authorization", "Bearer ag_at_tok")
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
			}
			if invoked {
				t.Fatal("handler must NOT be invoked on a confirmation_required refusal")
			}

			var body struct {
				Error                  string                         `json:"error"`
				ErrorDescription       string                         `json:"error_description"`
				Confirmation           *agentadmit.ActionConfirmation `json:"confirmation"`
				AttestationStatus      string                         `json:"attestation_status"`
				AttestationDescription string                         `json:"attestation_description"`
				Scopes                 []string                       `json:"scopes"`
				UserID                 string                         `json:"user_id"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("403 body is not valid JSON: %v: %s", err, rec.Body.String())
			}
			if body.Error != "confirmation_required" {
				t.Errorf("error = %q, want confirmation_required", body.Error)
			}
			if body.ErrorDescription == "" {
				t.Error("error_description missing from the refusal body")
			}
			if body.Confirmation == nil {
				t.Fatalf("confirmation block missing from 403 body: %s", rec.Body.String())
			}
			if body.Confirmation.ActionSessionURL != "https://agentadmit.com/confirm/action/asess_abc" {
				t.Errorf("action_session_url = %q", body.Confirmation.ActionSessionURL)
			}
			if body.Confirmation.ActionSessionID != "asess_abc" || body.Confirmation.ExpiresAt != "2026-09-02T18:30:00.000Z" || body.Confirmation.Scope != "write:payments" {
				t.Errorf("confirmation identity fields not preserved: %+v", body.Confirmation)
			}
			if body.AttestationStatus != "action_mismatch" || body.AttestationDescription == "" {
				t.Errorf("attestation_status/description not passed through: %+v", body)
			}
			// A refusal must not leak the active response's grant state.
			if len(body.Scopes) != 0 || body.UserID != "" {
				t.Errorf("refusal leaked token state: %s", rec.Body.String())
			}

			// The verify call carried the confirm-each-time telemetry.
			if len(captured) != 1 {
				t.Fatalf("expected 1 verify call, got %d", len(captured))
			}
			if captured[0]["action_summary"] != "Pay alex $50" {
				t.Errorf("action_summary = %v, want the app's summary", captured[0]["action_summary"])
			}
			if captured[0]["request_digest"] != agentadmit.RequestDigest([]byte(payload)) {
				t.Errorf("request_digest = %v, want sha256 of the raw body", captured[0]["request_digest"])
			}
		})
	}
}

// A malformed ceremony block still refuses (403) but carries no link.
func TestMiddleware_ConfirmationRequiredMalformedFailsClosed(t *testing.T) {
	var captured []map[string]interface{}
	client := fakeVerifyCapture(t,
		`{"active":true,"error":"confirmation_required","confirmation":{"action_session_id":123},"scopes":["write:payments"]}`,
		&captured)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	invoked := false
	r.POST("/api/payments", MiddlewareWithOptions(client, payOptions(), "write:payments"), func(c *gin.Context) {
		invoked = true
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/payments", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer ag_at_tok")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || invoked {
		t.Fatalf("expected 403 and no handler, got %d invoked=%v: %s", rec.Code, invoked, rec.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("403 body is not valid JSON: %v", err)
	}
	if body["error"] != "confirmation_required" {
		t.Errorf("error = %v, want confirmation_required", body["error"])
	}
	if _, present := body["confirmation"]; present {
		t.Errorf("malformed ceremony must not be relayed as a link: %s", rec.Body.String())
	}
}

// The accepted retry: the attestation header is forwarded, the digest and
// summary ride along, c.ShouldBindJSON still sees the full body, and the
// consumed ceremony is readable via GetActionConfirmation.
func TestMiddlewareWithOptions_AcceptedRetryKeepsBodyAndExposesConsumed(t *testing.T) {
	var captured []map[string]interface{}
	client := fakeVerifyCapture(t,
		`{"active":true,"scopes":["write:payments"],"app_id":"app_1","user_id":"user_1","action_confirmation":{"action_session_id":"asess_abc","consumed":true}}`,
		&captured)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	var seen struct {
		Trainer string `json:"trainer"`
		Amount  int    `json:"amount"`
	}
	var consumed *agentadmit.ActionConfirmationConsumed
	invoked := false
	r.POST("/api/payments", MiddlewareWithOptions(client, payOptions(), "write:payments"), func(c *gin.Context) {
		invoked = true
		if err := c.ShouldBindJSON(&seen); err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		consumed = GetActionConfirmation(c)
		c.String(http.StatusOK, "ok")
	})

	payload := `{"trainer":"alex","amount":50}`
	req := httptest.NewRequest(http.MethodPost, "/api/payments?debug=1", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer ag_at_tok")
	req.Header.Set(agentadmit.ActionAttestationHeader, "asess_abc")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !invoked {
		t.Fatalf("status = %d, invoked = %v: %s", rec.Code, invoked, rec.Body.String())
	}
	if seen.Trainer != "alex" || seen.Amount != 50 {
		t.Errorf("handler could not bind the original body after the digest: %+v", seen)
	}
	if consumed == nil || consumed.ActionSessionID != "asess_abc" || !consumed.Consumed {
		t.Errorf("GetActionConfirmation = %+v, want the consumed ceremony", consumed)
	}
	if len(captured) != 1 {
		t.Fatalf("expected 1 verify call, got %d", len(captured))
	}
	body := captured[0]
	if body["action_attestation_id"] != "asess_abc" {
		t.Errorf("action_attestation_id = %v, want asess_abc", body["action_attestation_id"])
	}
	if body["action_summary"] != "Pay alex $50" {
		t.Errorf("action_summary = %v", body["action_summary"])
	}
	if body["request_digest"] != agentadmit.RequestDigest([]byte(payload)) {
		t.Errorf("request_digest = %v, want sha256 of the raw body", body["request_digest"])
	}
	if body["scope_used"] != "write:payments" || body["endpoint"] != "/api/payments" || body["method"] != "POST" {
		t.Errorf("1.10 telemetry regressed: %v", body)
	}
	if rec.Header().Get(agentadmit.ActionAttestationHeader) != "" {
		t.Error("attestation header leaked onto the success response")
	}
}

// Without options the attestation header is still forwarded, but no digest
// or summary is sent, and GetActionConfirmation is nil when nothing was
// consumed.
func TestMiddleware_PlainRouteForwardsAttestationOnly(t *testing.T) {
	var captured []map[string]interface{}
	client := fakeVerifyCapture(t,
		`{"active":true,"scopes":["write:payments"],"app_id":"app_1","user_id":"user_1"}`, &captured)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	var consumed *agentadmit.ActionConfirmationConsumed
	r.POST("/api/payments", Middleware(client, "write:payments"), func(c *gin.Context) {
		consumed = GetActionConfirmation(c)
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/payments", strings.NewReader(`{"trainer":"alex"}`))
	req.Header.Set("Authorization", "Bearer ag_at_tok")
	req.Header.Set(agentadmit.ActionAttestationHeader, "  asess_abc  ")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if consumed != nil {
		t.Errorf("GetActionConfirmation = %+v, want nil", consumed)
	}
	body := captured[0]
	if body["action_attestation_id"] != "asess_abc" {
		t.Errorf("action_attestation_id = %v, want trimmed asess_abc", body["action_attestation_id"])
	}
	if _, present := body["request_digest"]; present {
		t.Error("request_digest sent without a summary option")
	}
	if _, present := body["action_summary"]; present {
		t.Error("action_summary sent without a summary option")
	}
}
