package agentadmit

// Tests for presence behavior (WebAuthn human-presence step-up).
//
// The presence block in a verify response is additive metadata. A
// type-malformed presence block must be dropped (Presence = nil) without
// failing token validation; a well-formed block must still parse. Nil
// Presence means "not verified" and presence-gated callers fail closed on
// it: IsPresenceVerified() is true only for a parsed block with
// verified set to true.

import (
	"net/http"
	"testing"
)

// TestValidate_WellFormedPresenceParsed verifies that a well-formed,
// verified presence block parses into TokenInfo.Presence and that
// IsPresenceVerified() reports true.
func TestValidate_WellFormedPresenceParsed(t *testing.T) {
	client := newIntrospectClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"user_id":"user_1","connection_id":"conn_1","scopes":[],"app_id":"app_1","presence":{"verified":true,"method":"webauthn","uv":true,"verified_at":"2026-07-05T00:00:00Z"}}`))
	})

	info, err := client.Validate("ag_at_dummy", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Presence == nil {
		t.Fatal("expected well-formed presence block to be parsed, got nil")
	}
	if !info.Presence.Verified {
		t.Fatalf("expected verified=true, got %+v", info.Presence)
	}
	if info.Presence.Method != "webauthn" {
		t.Fatalf("unexpected method: %q", info.Presence.Method)
	}
	if info.Presence.UV == nil || !*info.Presence.UV {
		t.Fatalf("expected uv=true, got %+v", info.Presence.UV)
	}
	if info.Presence.VerifiedAt != "2026-07-05T00:00:00Z" {
		t.Fatalf("unexpected verified_at: %q", info.Presence.VerifiedAt)
	}
	if !info.IsPresenceVerified() {
		t.Fatal("expected IsPresenceVerified() to be true for a verified block")
	}
}

// TestValidate_UnverifiedPresenceParsed verifies that an unverified presence
// block (connection minted without a ceremony: verified=false with null
// method/uv/verified_at) parses, and IsPresenceVerified() reports false.
func TestValidate_UnverifiedPresenceParsed(t *testing.T) {
	client := newIntrospectClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"user_id":"user_2","connection_id":"conn_2","scopes":[],"app_id":"app_1","presence":{"verified":false,"method":null,"uv":null,"verified_at":null}}`))
	})

	info, err := client.Validate("ag_at_dummy", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Presence == nil {
		t.Fatal("expected unverified presence block to be parsed, got nil")
	}
	if info.Presence.Verified {
		t.Fatalf("expected verified=false, got %+v", info.Presence)
	}
	if info.Presence.Method != "" {
		t.Fatalf("expected empty method for null, got %q", info.Presence.Method)
	}
	if info.Presence.UV != nil {
		t.Fatalf("expected nil uv for null, got %v", *info.Presence.UV)
	}
	if info.Presence.VerifiedAt != "" {
		t.Fatalf("expected empty verified_at for null, got %q", info.Presence.VerifiedAt)
	}
	if info.IsPresenceVerified() {
		t.Fatal("expected IsPresenceVerified() to be false for verified=false")
	}
}

// TestValidate_PresenceAbsentOrNull verifies that a missing or null presence
// field (older servers) leaves Presence nil without error, and that
// IsPresenceVerified() fails closed to false.
func TestValidate_PresenceAbsentOrNull(t *testing.T) {
	bodies := map[string]string{
		"absent": `{"active":true,"user_id":"u3","connection_id":"c3","scopes":[]}`,
		"null":   `{"active":true,"user_id":"u3","connection_id":"c3","scopes":[],"presence":null}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			payload := body
			client := newIntrospectClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(payload))
			})
			info, err := client.Validate("ag_at_dummy", nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if info.Presence != nil {
				t.Fatalf("expected nil Presence, got %+v", info.Presence)
			}
			if info.IsPresenceVerified() {
				t.Fatal("expected IsPresenceVerified() to be false when presence is absent")
			}
		})
	}
}

// TestValidate_MalformedPresenceDropped verifies that a type-malformed
// presence block (wrong JSON type for the object, or verified as a string)
// is dropped to nil without failing an otherwise valid verify, and that
// IsPresenceVerified() fails closed to false.
func TestValidate_MalformedPresenceDropped(t *testing.T) {
	bodies := map[string]string{
		"string":          `{"active":true,"user_id":"user_4","connection_id":"conn_4","scopes":["read:data"],"app_id":"app_1","presence":"verified"}`,
		"coerced-boolean": `{"active":true,"user_id":"user_4","connection_id":"conn_4","scopes":["read:data"],"app_id":"app_1","presence":{"verified":"true","method":"webauthn"}}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			payload := body
			client := newIntrospectClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(payload))
			})
			info, err := client.Validate("ag_at_dummy", nil)
			if err != nil {
				t.Fatalf("malformed presence block must not fail verify, got: %v", err)
			}
			if info.Presence != nil {
				t.Fatalf("expected Presence to be dropped to nil, got %+v", info.Presence)
			}
			if info.IsPresenceVerified() {
				t.Fatal("expected IsPresenceVerified() to be false for a dropped block")
			}
			if info.UserID != "user_4" {
				t.Fatalf("token fields must survive presence drop, got user_id %q", info.UserID)
			}
			if len(info.Scopes) != 1 || info.Scopes[0] != "read:data" {
				t.Fatalf("token scopes must survive presence drop, got %v", info.Scopes)
			}
		})
	}
}

// TestValidate_PresenceUnknownFieldsTolerated verifies that unknown fields,
// both inside the presence block and at the top level of the verify
// response, are still tolerated (additive server changes must not break
// older SDKs).
func TestValidate_PresenceUnknownFieldsTolerated(t *testing.T) {
	client := newIntrospectClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"user_id":"user_5","connection_id":"conn_5","scopes":[],"app_id":"app_1","future_top_level":{"x":1},"presence":{"verified":true,"method":"webauthn","uv":false,"verified_at":"2026-07-05T00:00:00Z","future_field":"y"}}`))
	})

	info, err := client.Validate("ag_at_dummy", nil)
	if err != nil {
		t.Fatalf("unknown fields must be tolerated, got: %v", err)
	}
	if info.Presence == nil {
		t.Fatal("expected presence block with unknown fields to still parse, got nil")
	}
	if !info.IsPresenceVerified() {
		t.Fatal("expected IsPresenceVerified() to be true despite unknown fields")
	}
	if info.Presence.UV == nil || *info.Presence.UV {
		t.Fatalf("expected uv=false, got %+v", info.Presence.UV)
	}
}
