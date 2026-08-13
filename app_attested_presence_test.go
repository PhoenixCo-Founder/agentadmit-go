package agentadmit

// Tests for app-attested presence: typed forwarding at token issuance.
//
// Issue path: a non-nil Presence on IssueTokenRequest must be sent as
// `presence: {verified: true, uv: true, method, verified_at}` in the POST
// /api/v1/apps/{app_id}/token body — verified/uv are literal true by
// construction (the marshaler emits them; the struct cannot represent
// anything else). A nil Presence must omit the field entirely. An
// out-of-contract method (^[a-z0-9_]+$, 1-60) or a zero VerifiedAt fails
// client-side before any HTTP call: a zero time would serialize as year 1
// and fail the hosted freshness window (10 minutes, 60 s future skew), and
// time.Time marshals RFC 3339 with an explicit offset, which the hosted
// contract requires.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

var ceremonyAt = time.Date(2026, 8, 13, 17, 0, 0, 0, time.UTC)

// TestIssueToken_PresenceSent verifies that a non-nil Presence is included
// as the full literal-true wire object in the outbound token-issuance body.
func TestIssueToken_PresenceSent(t *testing.T) {
	var body []byte
	client, _ := newPurposeTestClient(t, issueTokenStub(t, &body))

	_, err := client.IssueToken("app_1", IssueTokenRequest{
		UserID: "user_1",
		Scopes: []string{"read:orders"},
		Presence: &AppAttestedPresence{
			Method:     "my_webauthn",
			VerifiedAt: ceremonyAt,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sent map[string]interface{}
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("outbound body is not valid JSON: %v", err)
	}
	presence, ok := sent["presence"].(map[string]interface{})
	if !ok {
		t.Fatalf("outbound body missing presence object, got %s", body)
	}
	if presence["verified"] != true {
		t.Errorf("presence.verified must be literal true, got %v", presence["verified"])
	}
	if presence["uv"] != true {
		t.Errorf("presence.uv must be literal true, got %v", presence["uv"])
	}
	if presence["method"] != "my_webauthn" {
		t.Errorf("unexpected presence.method: %v", presence["method"])
	}
	verifiedAt, _ := presence["verified_at"].(string)
	if verifiedAt != "2026-08-13T17:00:00Z" {
		t.Errorf("presence.verified_at must be RFC 3339 with offset, got %q", verifiedAt)
	}
}

// TestIssueToken_PresencePreservesNonUTCOffset verifies that a non-UTC
// location survives serialization with its explicit offset.
func TestIssueToken_PresencePreservesNonUTCOffset(t *testing.T) {
	var body []byte
	client, _ := newPurposeTestClient(t, issueTokenStub(t, &body))

	pacific := time.FixedZone("PDT", -7*60*60)
	_, err := client.IssueToken("app_1", IssueTokenRequest{
		UserID: "user_1",
		Scopes: []string{"read:orders"},
		Presence: &AppAttestedPresence{
			Method:     "my_webauthn",
			VerifiedAt: time.Date(2026, 8, 13, 10, 0, 0, 0, pacific),
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(body), `"verified_at":"2026-08-13T10:00:00-07:00"`) {
		t.Fatalf("expected offset-carrying verified_at in body, got %s", body)
	}
}

// TestIssueToken_PresenceOmittedWhenNil verifies that a nil Presence omits
// the `presence` key from the outbound body entirely (omitting the field is
// the only way to say "no ceremony").
func TestIssueToken_PresenceOmittedWhenNil(t *testing.T) {
	var body []byte
	client, _ := newPurposeTestClient(t, issueTokenStub(t, &body))

	_, err := client.IssueToken("app_1", IssueTokenRequest{
		UserID: "user_1",
		Scopes: []string{"read:orders"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(string(body), "presence") {
		t.Fatalf("nil Presence must omit the field, got %s", body)
	}
}

// TestIssueToken_PresenceBadMethod verifies that out-of-contract methods
// fail client-side, before any HTTP call is made.
func TestIssueToken_PresenceBadMethod(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
	}{
		{"uppercase", "My_WebAuthn"},
		{"space", "my webauthn"},
		{"hyphen", "my-webauthn"},
		{"empty", ""},
		{"61 chars", strings.Repeat("m", 61)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, requests := newPurposeTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				t.Error("no HTTP request must be made for an out-of-contract presence method")
			})

			_, err := client.IssueToken("app_1", IssueTokenRequest{
				UserID: "user_1",
				Scopes: []string{"read:orders"},
				Presence: &AppAttestedPresence{
					Method:     tc.method,
					VerifiedAt: ceremonyAt,
				},
			})
			if err == nil {
				t.Fatalf("expected error for method %q, got nil", tc.method)
			}
			if !strings.Contains(err.Error(), "presence method") {
				t.Fatalf("unexpected error: %v", err)
			}
			if *requests != 0 {
				t.Fatalf("expected 0 HTTP requests, got %d", *requests)
			}
		})
	}
}

// TestIssueToken_PresenceZeroVerifiedAt verifies that a zero VerifiedAt
// fails client-side, before any HTTP call is made.
func TestIssueToken_PresenceZeroVerifiedAt(t *testing.T) {
	client, requests := newPurposeTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("no HTTP request must be made for a zero presence verified_at")
	})

	_, err := client.IssueToken("app_1", IssueTokenRequest{
		UserID:   "user_1",
		Scopes:   []string{"read:orders"},
		Presence: &AppAttestedPresence{Method: "my_webauthn"},
	})
	if err == nil {
		t.Fatal("expected error for zero verified_at, got nil")
	}
	if !strings.Contains(err.Error(), "verified_at") {
		t.Fatalf("unexpected error: %v", err)
	}
	if *requests != 0 {
		t.Fatalf("expected 0 HTTP requests, got %d", *requests)
	}
}
