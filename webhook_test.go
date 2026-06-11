package agentadmit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"
)

const (
	testSecret = "whsec_test123"
	testNowTS  = int64(1750000000)
)

var (
	testPayload = []byte(`{"event":"agentadmit.alert","alert_type":"usage_spike"}`)
	testNow     = time.Unix(testNowTS, 0)
)

func signTest(payload []byte, secret string, ts int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", ts)
	mac.Write(payload)
	return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac.Sum(nil)))
}

func TestVerifyWebhookSignature_Valid(t *testing.T) {
	header := signTest(testPayload, testSecret, testNowTS)
	if err := verifyWebhookSignatureAt(testPayload, header, testSecret, DefaultWebhookTolerance, testNow); err != nil {
		t.Fatalf("expected valid signature, got %v", err)
	}
}

func TestVerifyWebhookSignature_TamperedPayload(t *testing.T) {
	header := signTest(testPayload, testSecret, testNowTS)
	err := verifyWebhookSignatureAt(append(testPayload, ' '), header, testSecret, DefaultWebhookTolerance, testNow)
	if !errors.Is(err, ErrWebhookBadSignature) {
		t.Fatalf("expected ErrWebhookBadSignature, got %v", err)
	}
}

func TestVerifyWebhookSignature_WrongSecret(t *testing.T) {
	header := signTest(testPayload, "whsec_other456", testNowTS)
	err := verifyWebhookSignatureAt(testPayload, header, testSecret, DefaultWebhookTolerance, testNow)
	if !errors.Is(err, ErrWebhookBadSignature) {
		t.Fatalf("expected ErrWebhookBadSignature, got %v", err)
	}
}

func TestVerifyWebhookSignature_StaleTimestamp(t *testing.T) {
	header := signTest(testPayload, testSecret, testNowTS-600)
	err := verifyWebhookSignatureAt(testPayload, header, testSecret, DefaultWebhookTolerance, testNow)
	if !errors.Is(err, ErrWebhookStaleTimestamp) {
		t.Fatalf("expected ErrWebhookStaleTimestamp, got %v", err)
	}
}

func TestVerifyWebhookSignature_FutureTimestamp(t *testing.T) {
	header := signTest(testPayload, testSecret, testNowTS+600)
	err := verifyWebhookSignatureAt(testPayload, header, testSecret, DefaultWebhookTolerance, testNow)
	if !errors.Is(err, ErrWebhookStaleTimestamp) {
		t.Fatalf("expected ErrWebhookStaleTimestamp, got %v", err)
	}
}

func TestVerifyWebhookSignature_WithinTolerance(t *testing.T) {
	header := signTest(testPayload, testSecret, testNowTS-200)
	if err := verifyWebhookSignatureAt(testPayload, header, testSecret, DefaultWebhookTolerance, testNow); err != nil {
		t.Fatalf("expected valid signature within tolerance, got %v", err)
	}
}

func TestVerifyWebhookSignature_ToleranceDisabled(t *testing.T) {
	header := signTest(testPayload, testSecret, testNowTS-99999)
	if err := verifyWebhookSignatureAt(testPayload, header, testSecret, 0, testNow); err != nil {
		t.Fatalf("expected valid signature with tolerance disabled, got %v", err)
	}
}

func TestVerifyWebhookSignature_MissingHeader(t *testing.T) {
	err := verifyWebhookSignatureAt(testPayload, "", testSecret, DefaultWebhookTolerance, testNow)
	if !errors.Is(err, ErrWebhookMissingSignature) {
		t.Fatalf("expected ErrWebhookMissingSignature, got %v", err)
	}
}

func TestVerifyWebhookSignature_MalformedHeader(t *testing.T) {
	for _, header := range []string{"nonsense", "t=abc,v1=def", "t=123", "v1=abc"} {
		err := verifyWebhookSignatureAt(testPayload, header, testSecret, DefaultWebhookTolerance, testNow)
		if !errors.Is(err, ErrWebhookMalformedHeader) {
			t.Fatalf("header %q: expected ErrWebhookMalformedHeader, got %v", header, err)
		}
	}
}

func TestVerifyWebhookSignature_MissingSecret(t *testing.T) {
	header := signTest(testPayload, testSecret, testNowTS)
	err := verifyWebhookSignatureAt(testPayload, header, "", DefaultWebhookTolerance, testNow)
	if !errors.Is(err, ErrWebhookMissingSecret) {
		t.Fatalf("expected ErrWebhookMissingSecret, got %v", err)
	}
}

func TestVerifyWebhookSignature_MultipleCandidates(t *testing.T) {
	header := signTest(testPayload, testSecret, testNowTS) + ",v1=deadbeef"
	if err := verifyWebhookSignatureAt(testPayload, header, testSecret, DefaultWebhookTolerance, testNow); err != nil {
		t.Fatalf("expected valid signature with extra v1 candidate, got %v", err)
	}
}
