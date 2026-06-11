package agentadmit

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIssueTokenRequest_DurationOmitted(t *testing.T) {
	b, err := json.Marshal(IssueTokenRequest{
		UserID: "user_1",
		Scopes: []string{"read:orders"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "duration_seconds") {
		t.Fatalf("unset duration must omit the field, got %s", b)
	}
}

func TestIssueTokenRequest_DurationUntilRevoked(t *testing.T) {
	b, err := json.Marshal(IssueTokenRequest{
		UserID:          "user_1",
		Scopes:          []string{"read:orders"},
		DurationSeconds: DurationUntilRevoked(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"duration_seconds":null`) {
		t.Fatalf("until-revoked must send explicit null, got %s", b)
	}
}

func TestIssueTokenRequest_DurationExplicit(t *testing.T) {
	b, err := json.Marshal(IssueTokenRequest{
		UserID:          "user_1",
		Scopes:          []string{"read:orders"},
		DurationSeconds: Duration(3600),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"duration_seconds":3600`) {
		t.Fatalf("explicit duration must send the integer, got %s", b)
	}
}

func TestNew_KeyPrefixValidation(t *testing.T) {
	if _, err := New(Config{APIKey: "sk_bad_prefix"}); err == nil {
		t.Fatal("expected error for bad key prefix")
	}
	if _, err := New(Config{APIKey: "aa_test_abc"}); err != nil {
		t.Fatalf("aa_test_ key rejected: %v", err)
	}
	if _, err := New(Config{APIKey: "aa_live_abc"}); err != nil {
		t.Fatalf("aa_live_ key rejected: %v", err)
	}
}
