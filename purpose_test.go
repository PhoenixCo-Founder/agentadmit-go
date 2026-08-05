package agentadmit

// Tests for declared-purpose behavior.
//
// Issue path: a non-empty Purpose on IssueTokenRequest must be sent as
// `purpose` in the POST /api/v1/apps/{app_id}/token body; an empty Purpose
// must omit the field entirely. A purpose longer than 300 characters fails
// client-side before any HTTP call.
//
// Verify path: the hosted /verify response carries a nullable `purpose`;
// it must parse into TokenInfo.Purpose, and an absent or null purpose must
// read as the empty string (none declared). Purpose is a review-time record
// only, never an enforcement input.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// newPurposeTestClient builds a client whose verify and management API
// endpoints both point at a test server (127.0.0.1 so http is allowed),
// with retries disabled for deterministic tests. It also returns a request
// counter so tests can assert that client-side guards fire before any
// HTTP call.
func newPurposeTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *int32) {
	t.Helper()
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	client, err := New(Config{
		APIKey:     "aa_test_dummy",
		VerifyURL:  server.URL, // http://127.0.0.1:PORT -- allowed
		APIURL:     server.URL,
		MaxRetries: 0,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, &requests
}

// issueTokenStub answers POST /api/v1/apps/{app_id}/token with a minimal
// valid response and captures the raw request body.
func issueTokenStub(t *testing.T, capturedBody *[]byte) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		*capturedBody = b
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"ag_ct_dummy","exchange_url":"https://api.agentadmit.com/api/v1/exchange","expires_at":"2026-08-05T00:00:00Z","expires_in":600,"connection_id":"conn_1","scopes":["read:orders"]}`))
	}
}

// TestIssueToken_PurposeSent verifies that a non-empty Purpose is included
// as `purpose` in the outbound token-issuance body.
func TestIssueToken_PurposeSent(t *testing.T) {
	var body []byte
	client, _ := newPurposeTestClient(t, issueTokenStub(t, &body))

	_, err := client.IssueToken("app_1", IssueTokenRequest{
		UserID:  "user_1",
		Scopes:  []string{"read:orders"},
		Purpose: "Rebook my Tuesday class when a spot opens",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sent map[string]interface{}
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("outbound body is not valid JSON: %v", err)
	}
	if got, ok := sent["purpose"]; !ok {
		t.Fatalf("outbound body missing purpose, got %s", body)
	} else if got != "Rebook my Tuesday class when a spot opens" {
		t.Fatalf("unexpected purpose in outbound body: %v", got)
	}
}

// TestIssueToken_PurposeOmittedWhenEmpty verifies that an unset Purpose
// omits the `purpose` key from the outbound body entirely.
func TestIssueToken_PurposeOmittedWhenEmpty(t *testing.T) {
	var body []byte
	client, _ := newPurposeTestClient(t, issueTokenStub(t, &body))

	_, err := client.IssueToken("app_1", IssueTokenRequest{
		UserID: "user_1",
		Scopes: []string{"read:orders"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(string(body), "purpose") {
		t.Fatalf("empty purpose must omit the field, got %s", body)
	}
}

// TestIssueToken_PurposeTooLong verifies that a purpose longer than 300
// characters fails client-side, before any HTTP call is made.
func TestIssueToken_PurposeTooLong(t *testing.T) {
	client, requests := newPurposeTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("no HTTP request must be made for an over-length purpose")
	})

	_, err := client.IssueToken("app_1", IssueTokenRequest{
		UserID:  "user_1",
		Scopes:  []string{"read:orders"},
		Purpose: strings.Repeat("a", 301),
	})
	if err == nil {
		t.Fatal("expected error for 301-character purpose, got nil")
	}
	if !strings.Contains(err.Error(), "300") {
		t.Fatalf("error should name the 300-character limit, got: %v", err)
	}
	if got := atomic.LoadInt32(requests); got != 0 {
		t.Fatalf("guard must fire before the HTTP call, saw %d requests", got)
	}
}

// TestIssueToken_PurposeAtLimit verifies that exactly 300 characters passes
// the guard (the limit is inclusive).
func TestIssueToken_PurposeAtLimit(t *testing.T) {
	var body []byte
	client, _ := newPurposeTestClient(t, issueTokenStub(t, &body))

	_, err := client.IssueToken("app_1", IssueTokenRequest{
		UserID:  "user_1",
		Scopes:  []string{"read:orders"},
		Purpose: strings.Repeat("a", 300),
	})
	if err != nil {
		t.Fatalf("300-character purpose must pass, got: %v", err)
	}
}

// TestValidate_PurposeParsed verifies that a `purpose` field in the verify
// response parses into TokenInfo.Purpose.
func TestValidate_PurposeParsed(t *testing.T) {
	client, _ := newPurposeTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"user_id":"user_1","connection_id":"conn_1","scopes":["read:orders"],"app_id":"app_1","purpose":"Rebook my Tuesday class when a spot opens"}`))
	})

	info, err := client.Validate("ag_at_dummy", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Purpose != "Rebook my Tuesday class when a spot opens" {
		t.Fatalf("unexpected Purpose: %q", info.Purpose)
	}
	if info.ConnectionID != "conn_1" {
		t.Fatalf("token fields must still parse, got connection_id %q", info.ConnectionID)
	}
}

// TestValidate_PurposeAbsentOrNull verifies that a missing or null purpose
// reads as the empty string (none declared) without error.
func TestValidate_PurposeAbsentOrNull(t *testing.T) {
	bodies := map[string]string{
		"absent": `{"active":true,"user_id":"u1","connection_id":"c1","scopes":[]}`,
		"null":   `{"active":true,"user_id":"u1","connection_id":"c1","scopes":[],"purpose":null}`,
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
			if info.Purpose != "" {
				t.Fatalf("expected empty Purpose, got %q", info.Purpose)
			}
		})
	}
}
