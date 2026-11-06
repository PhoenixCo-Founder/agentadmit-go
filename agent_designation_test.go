package agentadmit

// Tests for agent designation on the verify result (v1.14.0).
//
// On AgentAdmit's consent page the user says which agent app a connection is
// for and, optionally, which AI model family it mainly uses. Separately, the
// agent may report its own platform and model when it redeems the connection
// token. The hosted /verify response carries both:
//
//	designated_agent: {agent_id, name, source: "user_declared", model} | null
//	agent_reported:   {platform, model: {id, version}} | null
//
// Semantic matrix (identical in every server SDK):
//   - a well-formed designated_agent reaches TokenInfo unchanged
//   - null / absent / malformed (no name, wrong source, not an object) -> nil,
//     never coerced, and the verify still succeeds
//   - a typed name has an empty AgentID; a model with no listed id has an
//     empty ModelID; a malformed model is dropped and the app is kept
//   - agent_reported reaches TokenInfo when it has a string platform or a
//     model with a string id; Version is empty when not a string
//   - agent_reported with neither is nil
//   - both are review-time records: nothing in the SDK branches on them

import (
	"net/http"
	"testing"
)

const designationBase = `"active":true,"user_id":"user_1","connection_id":"conn_1","scopes":["read:orders"],"app_id":"app_1"`

func validateWithBody(t *testing.T, body string) *TokenInfo {
	t.Helper()
	client, _ := newPurposeTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	info, err := client.Validate("ag_at_dummy", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ConnectionID != "conn_1" {
		t.Fatalf("token fields must still parse, got connection_id %q", info.ConnectionID)
	}
	return info
}

func TestValidate_DesignatedAgentParsed(t *testing.T) {
	info := validateWithBody(t, `{`+designationBase+`,"agent_label":"Claude Code 2.1","designated_agent":{"agent_id":"agt_openclaw","name":"OpenClaw","source":"user_declared","model":{"model_id":"agt_claude","name":"Claude (Anthropic)"},"extra":"dropped"}}`)
	d := info.DesignatedAgent
	if d == nil {
		t.Fatal("expected a designation")
	}
	if d.AgentID != "agt_openclaw" || d.Name != "OpenClaw" || d.Source != "user_declared" {
		t.Fatalf("unexpected designation: %+v", d)
	}
	if d.Model == nil || d.Model.ModelID != "agt_claude" || d.Model.Name != "Claude (Anthropic)" {
		t.Fatalf("unexpected model: %+v", d.Model)
	}
}

func TestValidate_DesignatedAgentTypedNameAndNoModel(t *testing.T) {
	info := validateWithBody(t, `{`+designationBase+`,"designated_agent":{"agent_id":null,"name":"My research agent","source":"user_declared","model":null}}`)
	d := info.DesignatedAgent
	if d == nil || d.AgentID != "" || d.Name != "My research agent" || d.Model != nil {
		t.Fatalf("unexpected designation: %+v", d)
	}
}

func TestValidate_DesignationAbsentOrNull(t *testing.T) {
	bodies := map[string]string{
		"absent": `{` + designationBase + `}`,
		"null":   `{` + designationBase + `,"designated_agent":null,"agent_reported":null}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			info := validateWithBody(t, body)
			if info.DesignatedAgent != nil || info.AgentReported != nil {
				t.Fatalf("expected nil records, got %+v / %+v", info.DesignatedAgent, info.AgentReported)
			}
		})
	}
}

func TestValidate_MalformedDesignationDroppedWithoutFailing(t *testing.T) {
	bad := map[string]string{
		"string":       `"OpenClaw"`,
		"number":       `7`,
		"array":        `[]`,
		"empty object": `{}`,
		"empty name":   `{"name":"","source":"user_declared"}`,
		"numeric name": `{"name":5,"source":"user_declared"}`,
		"no source":    `{"name":"OpenClaw"}`,
		"wrong source": `{"name":"OpenClaw","source":"operator_verified"}`,
	}
	for name, value := range bad {
		t.Run(name, func(t *testing.T) {
			info := validateWithBody(t, `{`+designationBase+`,"designated_agent":`+value+`}`)
			if info.DesignatedAgent != nil {
				t.Fatalf("malformed designation must be dropped, got %+v", info.DesignatedAgent)
			}
		})
	}
}

func TestValidate_AgentReportedParsed(t *testing.T) {
	info := validateWithBody(t, `{`+designationBase+`,"agent_reported":{"platform":"OpenClaw 2026.6","model":{"id":"example-model","version":"2026-01"}}}`)
	r := info.AgentReported
	if r == nil || r.Platform != "OpenClaw 2026.6" || r.Model == nil || r.Model.ID != "example-model" || r.Model.Version != "2026-01" {
		t.Fatalf("unexpected agent_reported: %+v", r)
	}
}

func TestValidate_BothRecordsIndependent(t *testing.T) {
	info := validateWithBody(t, `{`+designationBase+`,"designated_agent":{"agent_id":"agt_openclaw","name":"OpenClaw","source":"user_declared","model":{"model_id":"agt_claude","name":"Claude (Anthropic)"}},"agent_reported":{"platform":null,"model":{"id":"gpt-x","version":null}}}`)
	if info.DesignatedAgent == nil || info.DesignatedAgent.Model.Name != "Claude (Anthropic)" {
		t.Fatalf("unexpected designation: %+v", info.DesignatedAgent)
	}
	r := info.AgentReported
	if r == nil || r.Platform != "" || r.Model == nil || r.Model.ID != "gpt-x" || r.Model.Version != "" {
		t.Fatalf("unexpected agent_reported: %+v", r)
	}
}

func TestParseDesignatedAgent_MalformedModelDroppedAppKept(t *testing.T) {
	for _, model := range []string{`"Grok"`, `3`, `{}`, `{"name":""}`, `{"name":9}`, `{"model_id":"agt_x"}`} {
		d := ParseDesignatedAgent([]byte(`{"agent_id":"agt_1","name":"Hermes","source":"user_declared","model":` + model + `}`))
		if d == nil || d.AgentID != "agt_1" || d.Name != "Hermes" || d.Model != nil {
			t.Fatalf("model %s: unexpected %+v", model, d)
		}
	}
}

func TestParseDesignatedAgent_ModelWithoutListedID(t *testing.T) {
	d := ParseDesignatedAgent([]byte(`{"agent_id":"agt_1","name":"OpenClaw","source":"user_declared","model":{"name":"Mistral"}}`))
	if d == nil || d.Model == nil || d.Model.ModelID != "" || d.Model.Name != "Mistral" {
		t.Fatalf("unexpected %+v", d)
	}
}

func TestParseDesignatedAgent_RejectsAnythingElse(t *testing.T) {
	for _, raw := range []string{``, `null`, `"x"`, `1`, `[]`, `{}`, `{"name":"x"}`, `{"name":"x","source":"agent_reported"}`} {
		if d := ParseDesignatedAgent([]byte(raw)); d != nil {
			t.Fatalf("%q: expected nil, got %+v", raw, d)
		}
	}
}

func TestParseAgentReported_PartialValues(t *testing.T) {
	if r := ParseAgentReported([]byte(`{"platform":"ExampleAgent"}`)); r == nil || r.Platform != "ExampleAgent" || r.Model != nil {
		t.Fatalf("platform only: %+v", r)
	}
	if r := ParseAgentReported([]byte(`{"model":{"id":"m1"}}`)); r == nil || r.Platform != "" || r.Model == nil || r.Model.ID != "m1" || r.Model.Version != "" {
		t.Fatalf("model only: %+v", r)
	}
	if r := ParseAgentReported([]byte(`{"model":{"id":"m1","version":3}}`)); r == nil || r.Model == nil || r.Model.Version != "" {
		t.Fatalf("non-string version: %+v", r)
	}
}

func TestParseAgentReported_NilWithoutPlatformOrModelID(t *testing.T) {
	for _, raw := range []string{``, `null`, `"x"`, `1`, `[]`, `{}`, `{"platform":5}`, `{"platform":""}`, `{"model":{}}`, `{"model":{"version":"1"}}`, `{"platform":null,"model":null}`} {
		if r := ParseAgentReported([]byte(raw)); r != nil {
			t.Fatalf("%q: expected nil, got %+v", raw, r)
		}
	}
}
