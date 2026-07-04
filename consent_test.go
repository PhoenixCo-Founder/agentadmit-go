package agentadmit

// Tests for Consent Ledger behavior.
//
// Verify path: the consent block in a verify response is additive metadata.
// A type-malformed consent block must be dropped (Consent = nil) without
// failing token validation; a well-formed block must still parse. Nil
// Consent means "no verdict" and consent-gated callers fail closed on it.
//
// CheckConsent path: fail-closed semantics. Any transport or decode failure
// must return a nil verdict plus a non-nil error; callers deny on error.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// Verify response: lenient consent decoding
// ---------------------------------------------------------------------------

// TestValidate_MalformedConsentString verifies that a valid token payload
// with "consent" set to a bare string (wrong JSON type for the object)
// still validates, with Consent dropped to nil.
func TestValidate_MalformedConsentString(t *testing.T) {
	client := newIntrospectClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"user_id":"user_1","connection_id":"conn_1","scopes":["read:data"],"app_id":"app_1","consent":"garbage"}`))
	})

	info, err := client.Validate("ag_at_dummy", nil)
	if err != nil {
		t.Fatalf("malformed consent block must not fail verify, got: %v", err)
	}
	if info.Consent != nil {
		t.Fatalf("expected Consent to be dropped to nil, got %+v", info.Consent)
	}
	if info.UserID != "user_1" {
		t.Fatalf("token fields must survive consent drop, got user_id %q", info.UserID)
	}
	if len(info.Scopes) != 1 || info.Scopes[0] != "read:data" {
		t.Fatalf("token scopes must survive consent drop, got %v", info.Scopes)
	}
}

// TestValidate_MalformedConsentFieldTypes verifies that a consent object
// with mismatched field types (granted as a string) is dropped without
// failing the overall verify.
func TestValidate_MalformedConsentFieldTypes(t *testing.T) {
	client := newIntrospectClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"user_id":"user_2","connection_id":"conn_2","scopes":[],"app_id":"app_1","consent":{"caller_class":"external_agent","granted":"yes","source":"setting"}}`))
	})

	info, err := client.Validate("ag_at_dummy", nil)
	if err != nil {
		t.Fatalf("type-mismatched consent block must not fail verify, got: %v", err)
	}
	if info.Consent != nil {
		t.Fatalf("expected Consent to be dropped to nil, got %+v", info.Consent)
	}
}

// TestValidate_WellFormedConsentParsed verifies that a well-formed consent
// block still parses into TokenInfo.Consent (lenient decoding must not
// discard valid verdicts).
func TestValidate_WellFormedConsentParsed(t *testing.T) {
	client := newIntrospectClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"user_id":"user_3","connection_id":"conn_3","scopes":[],"app_id":"app_1","consent":{"caller_class":"external_agent","granted":true,"source":"setting","evaluated_at":"2026-07-03T00:00:00Z"}}`))
	})

	info, err := client.Validate("ag_at_dummy", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Consent == nil {
		t.Fatal("expected well-formed consent verdict to be parsed, got nil")
	}
	if !info.Consent.Granted {
		t.Fatalf("expected granted=true, got %+v", info.Consent)
	}
	if info.Consent.CallerClass != CallerClassExternalAgent {
		t.Fatalf("unexpected caller_class: %q", info.Consent.CallerClass)
	}
	if info.Consent.Source != "setting" {
		t.Fatalf("unexpected source: %q", info.Consent.Source)
	}
}

// TestValidate_ConsentAbsentOrNull verifies that a missing or null consent
// field leaves Consent nil without error (no verdict returned).
func TestValidate_ConsentAbsentOrNull(t *testing.T) {
	bodies := map[string]string{
		"absent": `{"active":true,"user_id":"u4","connection_id":"c4","scopes":[]}`,
		"null":   `{"active":true,"user_id":"u4","connection_id":"c4","scopes":[],"consent":null}`,
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
			if info.Consent != nil {
				t.Fatalf("expected nil Consent, got %+v", info.Consent)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CheckConsent: fail-closed semantics
// ---------------------------------------------------------------------------

// newConsentClient builds a client whose management API base points at a
// test server (127.0.0.1 so http is allowed).
func newConsentClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := New(Config{
		APIKey:     "aa_test_dummy",
		APIURL:     server.URL, // http://127.0.0.1:PORT -- allowed
		MaxRetries: 0,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

// TestCheckConsent_GrantedVerdict verifies the happy path: a 200 response
// with a well-formed verdict is parsed and returned.
func TestCheckConsent_GrantedVerdict(t *testing.T) {
	client := newConsentClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/consent/check" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"caller_class":"human_session","granted":true,"source":"app_default","evaluated_at":"2026-07-03T00:00:00Z"}`))
	})

	verdict, err := client.CheckConsent("user_1", CallerClassHumanSession, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict == nil {
		t.Fatal("expected a verdict, got nil")
	}
	if !verdict.Granted {
		t.Fatalf("expected granted=true, got %+v", verdict)
	}
	if verdict.CallerClass != CallerClassHumanSession {
		t.Fatalf("unexpected caller_class: %q", verdict.CallerClass)
	}
	if verdict.Source != "app_default" {
		t.Fatalf("unexpected source: %q", verdict.Source)
	}
}

// TestCheckConsent_Non200FailsClosed verifies that a non-200 response
// returns an error and no verdict; callers must deny on error.
func TestCheckConsent_Non200FailsClosed(t *testing.T) {
	statuses := []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusInternalServerError}
	for _, status := range statuses {
		code := status
		client := newConsentClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"error":"nope"}`))
		})

		verdict, err := client.CheckConsent("user_1", CallerClassInAppAI, nil)
		if err == nil {
			t.Fatalf("status %d: expected error, got nil", code)
		}
		if verdict != nil {
			t.Fatalf("status %d: fail closed requires nil verdict on error, got %+v", code, verdict)
		}
	}
}

// TestCheckConsent_MalformedBodyFailsClosed verifies that a 200 response
// with a malformed JSON body returns an error and no verdict.
func TestCheckConsent_MalformedBodyFailsClosed(t *testing.T) {
	client := newConsentClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"granted": tru`)) // truncated, not valid JSON
	})

	verdict, err := client.CheckConsent("user_1", CallerClassHumanSession, nil)
	if err == nil {
		t.Fatal("expected decode error for malformed body, got nil")
	}
	if verdict != nil {
		t.Fatalf("fail closed requires nil verdict on decode error, got %+v", verdict)
	}
}
