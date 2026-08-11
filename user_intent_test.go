package agentadmit

// Tests for user-declared-intent behavior.
//
// Issue path: a non-empty UserIntent on IssueTokenRequest must be sent as
// `user_intent` in the POST /api/v1/apps/{app_id}/token body; an empty
// UserIntent must omit the field entirely. A user intent longer than 300
// characters fails client-side before any HTTP call.
//
// Verify path: the hosted /verify response carries a nullable `user_intent`;
// it must parse into TokenInfo.UserIntent, and an absent or null user intent
// must read as the empty string (none declared). UserIntent is a review-time
// record only, never an enforcement input.

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// TestIssueToken_UserIntentSent verifies that a non-empty UserIntent is
// included as `user_intent` in the outbound token-issuance body.
func TestIssueToken_UserIntentSent(t *testing.T) {
	var body []byte
	client, _ := newPurposeTestClient(t, issueTokenStub(t, &body))

	_, err := client.IssueToken("app_1", IssueTokenRequest{
		UserID:     "user_1",
		Scopes:     []string{"read:orders"},
		UserIntent: "just rebook my tuesday spin class, nothing else",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sent map[string]interface{}
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("outbound body is not valid JSON: %v", err)
	}
	if got, ok := sent["user_intent"]; !ok {
		t.Fatalf("outbound body missing user_intent, got %s", body)
	} else if got != "just rebook my tuesday spin class, nothing else" {
		t.Fatalf("unexpected user_intent in outbound body: %v", got)
	}
}

// TestIssueToken_UserIntentOmittedWhenEmpty verifies that an unset
// UserIntent omits the `user_intent` key from the outbound body entirely.
func TestIssueToken_UserIntentOmittedWhenEmpty(t *testing.T) {
	var body []byte
	client, _ := newPurposeTestClient(t, issueTokenStub(t, &body))

	_, err := client.IssueToken("app_1", IssueTokenRequest{
		UserID: "user_1",
		Scopes: []string{"read:orders"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(string(body), "user_intent") {
		t.Fatalf("empty user_intent must omit the field, got %s", body)
	}
}

// TestIssueToken_UserIntentTooLong verifies that a user intent longer than
// 300 characters fails client-side, before any HTTP call is made.
func TestIssueToken_UserIntentTooLong(t *testing.T) {
	client, requests := newPurposeTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("no HTTP request must be made for an over-length user intent")
	})

	_, err := client.IssueToken("app_1", IssueTokenRequest{
		UserID:     "user_1",
		Scopes:     []string{"read:orders"},
		UserIntent: strings.Repeat("a", 301),
	})
	if err == nil {
		t.Fatal("expected error for 301-character user intent, got nil")
	}
	if !strings.Contains(err.Error(), "300") {
		t.Fatalf("error should name the 300-character limit, got: %v", err)
	}
	if !strings.Contains(err.Error(), "user_intent") {
		t.Fatalf("error should name user_intent, got: %v", err)
	}
	if got := atomic.LoadInt32(requests); got != 0 {
		t.Fatalf("guard must fire before the HTTP call, saw %d requests", got)
	}
}

// TestIssueToken_UserIntentAtLimit verifies that exactly 300 characters
// passes the guard (the limit is inclusive).
func TestIssueToken_UserIntentAtLimit(t *testing.T) {
	var body []byte
	client, _ := newPurposeTestClient(t, issueTokenStub(t, &body))

	_, err := client.IssueToken("app_1", IssueTokenRequest{
		UserID:     "user_1",
		Scopes:     []string{"read:orders"},
		UserIntent: strings.Repeat("a", 300),
	})
	if err != nil {
		t.Fatalf("300-character user intent must pass, got: %v", err)
	}
}

// TestIssueToken_PurposeAndUserIntentBothSent verifies that the two
// declarations are independent fields and can travel together in one
// outbound body.
func TestIssueToken_PurposeAndUserIntentBothSent(t *testing.T) {
	var body []byte
	client, _ := newPurposeTestClient(t, issueTokenStub(t, &body))

	_, err := client.IssueToken("app_1", IssueTokenRequest{
		UserID:     "user_1",
		Scopes:     []string{"read:orders"},
		Purpose:    "Rebook my Tuesday class when a spot opens",
		UserIntent: "just rebook my tuesday spin class, nothing else",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sent map[string]interface{}
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("outbound body is not valid JSON: %v", err)
	}
	if sent["purpose"] != "Rebook my Tuesday class when a spot opens" {
		t.Fatalf("unexpected purpose in outbound body: %v", sent["purpose"])
	}
	if sent["user_intent"] != "just rebook my tuesday spin class, nothing else" {
		t.Fatalf("unexpected user_intent in outbound body: %v", sent["user_intent"])
	}
}

// TestValidate_UserIntentParsed verifies that a `user_intent` field in the
// verify response parses into TokenInfo.UserIntent.
func TestValidate_UserIntentParsed(t *testing.T) {
	client, _ := newPurposeTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"user_id":"user_1","connection_id":"conn_1","scopes":["read:orders"],"app_id":"app_1","purpose":"Rebook my Tuesday class when a spot opens","user_intent":"just rebook my tuesday spin class, nothing else"}`))
	})

	info, err := client.Validate("ag_at_dummy", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.UserIntent != "just rebook my tuesday spin class, nothing else" {
		t.Fatalf("unexpected UserIntent: %q", info.UserIntent)
	}
	if info.Purpose != "Rebook my Tuesday class when a spot opens" {
		t.Fatalf("Purpose must still parse alongside UserIntent, got %q", info.Purpose)
	}
	if info.ConnectionID != "conn_1" {
		t.Fatalf("token fields must still parse, got connection_id %q", info.ConnectionID)
	}
}

// TestValidate_UserIntentAbsentOrNull verifies that a missing or null
// user_intent reads as the empty string (none declared) without error.
func TestValidate_UserIntentAbsentOrNull(t *testing.T) {
	bodies := map[string]string{
		"absent": `{"active":true,"user_id":"u1","connection_id":"c1","scopes":[]}`,
		"null":   `{"active":true,"user_id":"u1","connection_id":"c1","scopes":[],"user_intent":null}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			payload := body
			client, _ := newPurposeTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(payload))
			})
			info, err := client.Validate("ag_at_dummy", nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if info.UserIntent != "" {
				t.Fatalf("expected empty UserIntent, got %q", info.UserIntent)
			}
		})
	}
}
