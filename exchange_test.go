package agentadmit

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// exchangeCapture answers POST /api/v1/exchange and records the request.
func exchangeCapture(t *testing.T, body *map[string]interface{}, auth *string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/exchange" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		*auth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, body); err != nil {
			t.Errorf("exchange body is not JSON: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"ag_at_x","token_type":"Bearer","expires_in":900,"scopes":["read:orders"],"connection_id":"conn_1"}`))
	}
}

func TestExchange_OmitsEverythingOptionalWhenUnset(t *testing.T) {
	var body map[string]interface{}
	var auth string
	client, _ := newPurposeTestClient(t, exchangeCapture(t, &body, &auth))

	res, err := client.Exchange(ExchangeRequest{Token: "ag_ct_abc"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if res.AccessToken != "ag_at_x" {
		t.Fatalf("access token = %q", res.AccessToken)
	}
	if len(body) != 1 || body["token"] != "ag_ct_abc" {
		t.Fatalf("body must carry only the token, got %v", body)
	}
	if auth != "" {
		t.Fatalf("exchange must not send the API key, got Authorization %q", auth)
	}
}

func TestExchange_ForwardsWhatTheAgentSaysItRunsOn(t *testing.T) {
	var body map[string]interface{}
	var auth string
	client, _ := newPurposeTestClient(t, exchangeCapture(t, &body, &auth))

	_, err := client.Exchange(ExchangeRequest{
		Token:         "ag_ct_abc",
		AgentLabel:    "My Agent",
		AgentPlatform: "ExampleAgent 2.1",
		AgentModel:    &AgentReportedModel{ID: "example-model", Version: "2026-01"},
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if body["agent_label"] != "My Agent" || body["agent_platform"] != "ExampleAgent 2.1" {
		t.Fatalf("label/platform not forwarded: %v", body)
	}
	model, ok := body["agent_model"].(map[string]interface{})
	if !ok || model["id"] != "example-model" || model["version"] != "2026-01" || len(model) != 2 {
		t.Fatalf("agent_model not forwarded as {id, version}: %v", body["agent_model"])
	}
}

func TestExchange_ModelWithoutVersionOmitsVersion(t *testing.T) {
	var body map[string]interface{}
	var auth string
	client, _ := newPurposeTestClient(t, exchangeCapture(t, &body, &auth))

	if _, err := client.Exchange(ExchangeRequest{
		Token:      "ag_ct_abc",
		AgentModel: &AgentReportedModel{ID: "example-model"},
	}); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	model, ok := body["agent_model"].(map[string]interface{})
	if !ok || len(model) != 1 || model["id"] != "example-model" {
		t.Fatalf("agent_model must be {id} only, got %v", body["agent_model"])
	}
	if _, present := body["agent_platform"]; present {
		t.Fatalf("an unset platform must be omitted, got %v", body)
	}
}
