package agentadmit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// SignatureHeader is the header AgentAdmit signs alert webhook deliveries with.
const SignatureHeader = "X-AgentAdmit-Signature"

// DefaultWebhookTolerance is the maximum allowed clock skew between the
// signature timestamp and now. Deliveries outside the window are rejected
// to prevent replay.
const DefaultWebhookTolerance = 5 * time.Minute

// Webhook verification errors. Messages never include the secret or payload.
var (
	ErrWebhookMissingSecret    = errors.New("agentadmit: webhook signing secret is required")
	ErrWebhookMissingSignature = errors.New("agentadmit: missing X-AgentAdmit-Signature header")
	ErrWebhookMalformedHeader  = errors.New("agentadmit: malformed signature header")
	ErrWebhookStaleTimestamp   = errors.New("agentadmit: signature timestamp outside tolerance window")
	ErrWebhookBadSignature     = errors.New("agentadmit: webhook signature verification failed")
)

// VerifyWebhookSignature verifies the X-AgentAdmit-Signature header on an
// inbound alert webhook, using DefaultWebhookTolerance for replay protection.
//
// AgentAdmit signs deliveries Stripe-style: the header is
// `t=<unix_ts>,v1=<hex>` where hex is the HMAC-SHA256 of `{t}.{rawBody}`
// keyed with the app's whsec_… signing secret (returned once when the
// webhook URL is configured). Always verify against the raw request body,
// before any JSON parsing.
func VerifyWebhookSignature(payload []byte, header, secret string) error {
	return VerifyWebhookSignatureWithTolerance(payload, header, secret, DefaultWebhookTolerance)
}

// VerifyWebhookSignatureWithTolerance is VerifyWebhookSignature with a custom
// timestamp tolerance. Pass 0 to disable the timestamp check.
func VerifyWebhookSignatureWithTolerance(payload []byte, header, secret string, tolerance time.Duration) error {
	return verifyWebhookSignatureAt(payload, header, secret, tolerance, time.Now())
}

// verifyWebhookSignatureAt allows tests to inject the current time.
func verifyWebhookSignatureAt(payload []byte, header, secret string, tolerance time.Duration, now time.Time) error {
	if secret == "" {
		return ErrWebhookMissingSecret
	}
	if header == "" {
		return ErrWebhookMissingSignature
	}

	var timestamp int64 = -1
	var candidates []string
	for _, part := range strings.Split(header, ",") {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			continue
		}
		switch key {
		case "t":
			ts, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return ErrWebhookMalformedHeader
			}
			timestamp = ts
		case "v1":
			candidates = append(candidates, value)
		}
	}

	if timestamp < 0 || len(candidates) == 0 {
		return ErrWebhookMalformedHeader
	}

	if tolerance > 0 {
		skew := now.Unix() - timestamp
		if skew < 0 {
			skew = -skew
		}
		if time.Duration(skew)*time.Second > tolerance {
			return ErrWebhookStaleTimestamp
		}
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))

	for _, candidate := range candidates {
		if hmac.Equal([]byte(expected), []byte(candidate)) {
			return nil
		}
	}
	return ErrWebhookBadSignature
}
