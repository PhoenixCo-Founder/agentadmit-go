package agentadmit

// Tests for audit findings M4, M5, and M7.
//
// M4: HTTPS scheme enforcement at client construction.
// M5: Introspection response must be 2xx AND active:true to be honored.
// M7: Bearer scheme extraction is case-insensitive (RFC 7235).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// M4 -- HTTPS scheme enforcement
// ---------------------------------------------------------------------------

func TestNew_RequiresHTTPS_VerifyURL(t *testing.T) {
	tests := []struct {
		name      string
		verifyURL string
		wantErr   bool
	}{
		{
			name:      "https accepted",
			verifyURL: "https://api.example.com/verify",
			wantErr:   false,
		},
		{
			name:      "http on localhost accepted",
			verifyURL: "http://localhost:9999/verify",
			wantErr:   false,
		},
		{
			name:      "http on 127.0.0.1 accepted",
			verifyURL: "http://127.0.0.1:9999/verify",
			wantErr:   false,
		},
		{
			name:      "http on [::1] accepted",
			verifyURL: "http://[::1]:9999/verify",
			wantErr:   false,
		},
		{
			name:      "http on non-loopback rejected",
			verifyURL: "http://api.example.com/verify",
			wantErr:   true,
		},
		{
			name:      "http on 192.168.1.1 rejected",
			verifyURL: "http://192.168.1.1/verify",
			wantErr:   true,
		},
		{
			name:      "empty verifyURL uses default (https)",
			verifyURL: "",
			wantErr:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(Config{
				APIKey:    "aa_test_dummy",
				VerifyURL: tc.verifyURL,
			})
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for VerifyURL %q, got nil", tc.verifyURL)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for VerifyURL %q: %v", tc.verifyURL, err)
			}
			if tc.wantErr && err != nil {
				aaErr, ok := err.(*AgentAdmitError)
				if !ok {
					t.Fatalf("expected *AgentAdmitError, got %T", err)
				}
				if aaErr.Code != ErrCodeConfig {
					t.Fatalf("expected ErrCodeConfig, got %q", aaErr.Code)
				}
			}
		})
	}
}

func TestNew_RequiresHTTPS_APIURL(t *testing.T) {
	tests := []struct {
		name    string
		apiURL  string
		wantErr bool
	}{
		{
			name:    "https accepted",
			apiURL:  "https://api.example.com",
			wantErr: false,
		},
		{
			name:    "http on localhost accepted",
			apiURL:  "http://localhost:8080",
			wantErr: false,
		},
		{
			name:    "http on 127.0.0.1 accepted",
			apiURL:  "http://127.0.0.1:8080",
			wantErr: false,
		},
		{
			name:    "http on non-loopback rejected",
			apiURL:  "http://api.example.com",
			wantErr: true,
		},
		{
			name:    "empty APIURL uses default (https)",
			apiURL:  "",
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(Config{
				APIKey: "aa_test_dummy",
				APIURL: tc.apiURL,
			})
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for APIURL %q, got nil", tc.apiURL)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for APIURL %q: %v", tc.apiURL, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// M5 -- Introspection 2xx gating
// ---------------------------------------------------------------------------

// newIntrospectClient builds a client against a test server (127.0.0.1 so
// http is allowed) with retries disabled for deterministic tests.
func newIntrospectClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := New(Config{
		APIKey:     "aa_test_dummy",
		VerifyURL:  server.URL, // http://127.0.0.1:PORT -- allowed
		MaxRetries: 0,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Instant sleep so any accidental retry doesn't slow tests.
	client.sleep = func(_ context.Context, _ time.Duration) error { return nil }
	return client
}

// TestValidate_400ActiveTrue verifies that a 400 response with {"active":true}
// is NOT honored -- the 2xx gate must reject it as ErrCodeInvalidToken.
func TestValidate_400ActiveTrue(t *testing.T) {
	client := newIntrospectClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"active":true,"user_id":"user_1","connection_id":"conn_1","scopes":["read:things"]}`))
	})

	_, err := client.Validate("ag_at_dummy", nil)
	if err == nil {
		t.Fatal("expected error for 400 response, got nil")
	}
	aaErr, ok := err.(*AgentAdmitError)
	if !ok {
		t.Fatalf("expected *AgentAdmitError, got %T: %v", err, err)
	}
	if aaErr.Code != ErrCodeInvalidToken {
		t.Fatalf("expected ErrCodeInvalidToken for 400, got %q", aaErr.Code)
	}
}

// TestValidate_200ActiveFalseIsInvalidToken verifies that 200 + active:false
// returns ErrCodeInvalidToken.
func TestValidate_200ActiveFalseIsInvalidToken(t *testing.T) {
	client := newIntrospectClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":false,"error":"token_expired"}`))
	})

	_, err := client.Validate("ag_at_dummy", nil)
	if !IsInvalidToken(err) {
		t.Fatalf("expected IsInvalidToken=true, got %v", err)
	}
}

// TestValidate_200ActiveTrueIsValid verifies that 200 + active:true returns
// valid TokenInfo with correctly typed fields.
func TestValidate_200ActiveTrueIsValid(t *testing.T) {
	client := newIntrospectClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"user_id":"user_42","connection_id":"conn_99","scopes":["read:data"],"app_id":"app_1"}`))
	})

	info, err := client.Validate("ag_at_dummy", nil)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if info.UserID != "user_42" {
		t.Fatalf("unexpected user_id: %q", info.UserID)
	}
	if info.ConnectionID != "conn_99" {
		t.Fatalf("unexpected connection_id: %q", info.ConnectionID)
	}
	if info.AppID != "app_1" {
		t.Fatalf("unexpected app_id: %q", info.AppID)
	}
}

// TestValidate_401Rejected verifies that a 401 response is treated as
// ErrCodeInvalidToken, not a service error.
func TestValidate_401Rejected(t *testing.T) {
	client := newIntrospectClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	})

	_, err := client.Validate("ag_at_dummy", nil)
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
	aaErr, ok := err.(*AgentAdmitError)
	if !ok {
		t.Fatalf("expected *AgentAdmitError, got %T", err)
	}
	if aaErr.Code != ErrCodeInvalidToken {
		t.Fatalf("expected ErrCodeInvalidToken for 401, got %q", aaErr.Code)
	}
}

// TestValidate_500IsServiceUnavailable verifies that 5xx responses remain
// ErrCodeServiceUnavailable (unchanged from existing behavior).
func TestValidate_500IsServiceUnavailable(t *testing.T) {
	client := newIntrospectClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal"}`))
	})

	_, err := client.Validate("ag_at_dummy", nil)
	if !IsServiceUnavailable(err) {
		t.Fatalf("expected IsServiceUnavailable=true, got %v", err)
	}
}

// TestValidate_ScopesIsTypedSlice verifies that Go's typed unmarshal of
// TokenInfo.Scopes produces a []string (not interface{}) so downstream
// scope checks are safe.
func TestValidate_ScopesIsTypedSlice(t *testing.T) {
	client := newIntrospectClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"user_id":"u1","connection_id":"c1","scopes":["read:a","write:b"]}`))
	})

	info, err := client.Validate("ag_at_dummy", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(info.Scopes) != 2 {
		t.Fatalf("expected 2 scopes, got %d: %v", len(info.Scopes), info.Scopes)
	}
	if info.Scopes[0] != "read:a" || info.Scopes[1] != "write:b" {
		t.Fatalf("unexpected scopes: %v", info.Scopes)
	}
}

// TestValidate_NonStandardSuccessCode verifies 201 (2xx non-200) is accepted.
func TestValidate_NonStandardSuccessCode(t *testing.T) {
	client := newIntrospectClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"active":true,"user_id":"u2","connection_id":"c2","scopes":[]}`))
	})

	info, err := client.Validate("ag_at_dummy", nil)
	if err != nil {
		t.Fatalf("expected 201 to be accepted as 2xx, got: %v", err)
	}
	if info.UserID != "u2" {
		t.Fatalf("unexpected user_id: %q", info.UserID)
	}
}

// ---------------------------------------------------------------------------
// M7 -- Bearer scheme case-insensitivity
// ---------------------------------------------------------------------------

func TestBearerToken_CaseInsensitive(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"Bearer mytoken", "mytoken"},
		{"bearer mytoken", "mytoken"},
		{"BEARER mytoken", "mytoken"},
		{"BeArEr mytoken", "mytoken"},
		{"Basic dXNlcjpwYXNz", ""},
		{"", ""},
		{"Bearertoken", ""}, // no space -- not a valid Bearer scheme
	}

	for _, tc := range tests {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		got := bearerToken(req)
		if got != tc.want {
			t.Errorf("bearerToken(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}
