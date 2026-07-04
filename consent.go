package agentadmit

// Consent Ledger client — hosted caller-identity consent verdicts.
//
// External agents get their verdict inline in the verify response
// (TokenInfo.Consent). The two token-less caller classes (human sessions
// and your app's own in-app AI) ask CheckConsent.
//
// Consent is orthogonal to token revocation: on a denied verdict your app
// returns its own 403; nothing is revoked. Every evaluation is appended to
// the exportable consent trail.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Caller classes for consent checks.
const (
	CallerClassHumanSession  = "human_session"
	CallerClassInAppAI       = "in_app_ai"
	CallerClassExternalAgent = "external_agent"
)

// ConsentVerdict is the Consent Ledger's answer for one caller class.
// Source is which layer resolved it: "setting", "scope_setting",
// "app_default", or "platform_default".
type ConsentVerdict struct {
	CallerClass string `json:"caller_class"`
	Granted     bool   `json:"granted"`
	ScopeGroup  string `json:"scope_group,omitempty"`
	Source      string `json:"source"`
	EvaluatedAt string `json:"evaluated_at"`
}

type checkConsentRequest struct {
	AppUserID   string `json:"app_user_id"`
	CallerClass string `json:"caller_class"`
	ScopeGroup  string `json:"scope_group,omitempty"`
}

// CheckConsent asks whether a caller class may act on a user's data.
// scopeGroup may be nil for the class-wide verdict.
// Calls POST /api/v1/consent/check on the AgentAdmit hosted service.
func (c *Client) CheckConsent(appUserID, callerClass string, scopeGroup *string) (*ConsentVerdict, error) {
	return c.CheckConsentContext(context.Background(), appUserID, callerClass, scopeGroup)
}

// CheckConsentContext is the context-aware variant of CheckConsent.
func (c *Client) CheckConsentContext(ctx context.Context, appUserID, callerClass string, scopeGroup *string) (*ConsentVerdict, error) {
	req := checkConsentRequest{AppUserID: appUserID, CallerClass: callerClass}
	if scopeGroup != nil {
		req.ScopeGroup = *scopeGroup
	}
	respBytes, _, err := c.callManagementAPI(ctx, http.MethodPost, "/api/v1/consent/check", req)
	if err != nil {
		return nil, err
	}
	var verdict ConsentVerdict
	if err := json.Unmarshal(respBytes, &verdict); err != nil {
		return nil, fmt.Errorf("agentadmit: decode consent verdict: %w", err)
	}
	return &verdict, nil
}
