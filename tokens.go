package agentadmit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// DurationSeconds expresses the tri-state `duration_seconds` field on
// IssueTokenRequest:
//
//   - nil (field left unset)         → omitted from the JSON; the hosted
//     service applies its default (30 days)
//   - DurationUntilRevoked()         → explicit JSON null; the connection
//     lasts until revoked
//   - Duration(n)                    → explicit duration in seconds
//     (60–31536000)
type DurationSeconds struct {
	value *int64
}

// Duration returns a DurationSeconds carrying an explicit duration in seconds.
func Duration(seconds int64) *DurationSeconds {
	return &DurationSeconds{value: &seconds}
}

// DurationUntilRevoked returns a DurationSeconds that marshals as explicit
// JSON null — the connection lasts until revoked.
func DurationUntilRevoked() *DurationSeconds {
	return &DurationSeconds{}
}

// MarshalJSON implements json.Marshaler.
func (d *DurationSeconds) MarshalJSON() ([]byte, error) {
	if d == nil || d.value == nil {
		return []byte("null"), nil
	}
	return json.Marshal(*d.value)
}

// IssueTokenRequest is the body for POST /api/v1/apps/{app_id}/token.
type IssueTokenRequest struct {
	// UserID is your app's identifier for the user the connection belongs to.
	UserID string `json:"user_id"`

	// Scopes the connection grants (must be registered on the app when any are).
	Scopes []string `json:"scopes"`

	// Role is the user's role granted on the connection. Optional.
	Role string `json:"role,omitempty"`

	// DurationSeconds controls the connection lifetime. Leave nil for the
	// hosted default (30 days), DurationUntilRevoked() for until-revoked,
	// or Duration(n) for an explicit duration. See DurationSeconds.
	DurationSeconds *DurationSeconds `json:"duration_seconds,omitempty"`
}

// IssueTokenResponse is returned by POST /api/v1/apps/{app_id}/token.
type IssueTokenResponse struct {
	// Token is the self-describing connection token (ag_ct_…). Give it to
	// the user's agent; it is single-use and short-lived.
	Token        string   `json:"token"`
	ExchangeURL  string   `json:"exchange_url"`
	ExpiresAt    string   `json:"expires_at"`
	ExpiresIn    int      `json:"expires_in"`
	ConnectionID string   `json:"connection_id"`
	Scopes       []string `json:"scopes"`
}

// IssueToken issues a connection token for one of your users.
// Calls POST /api/v1/apps/{app_id}/token on the AgentAdmit hosted service.
func (c *Client) IssueToken(appID string, req IssueTokenRequest) (*IssueTokenResponse, error) {
	return c.IssueTokenContext(context.Background(), appID, req)
}

// IssueTokenContext is the context-aware variant of IssueToken.
func (c *Client) IssueTokenContext(ctx context.Context, appID string, req IssueTokenRequest) (*IssueTokenResponse, error) {
	respBytes, _, err := c.callManagementAPI(ctx, http.MethodPost, "/api/v1/apps/"+appID+"/token", req)
	if err != nil {
		return nil, err
	}
	var result IssueTokenResponse
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("agentadmit: decode issue token response: %w", err)
	}
	return &result, nil
}

// ExchangeRequest is the body for POST /api/v1/exchange.
type ExchangeRequest struct {
	// Token is the ag_ct_… connection token (preferred). Provide Token or Secret.
	Token         string                 `json:"token,omitempty"`
	Secret        string                 `json:"secret,omitempty"`
	AgentLabel    string                 `json:"agent_label,omitempty"`
	AgentID       string                 `json:"agent_id,omitempty"`
	AgentMetadata map[string]interface{} `json:"agent_metadata,omitempty"`
}

// ExchangeResponse is returned by POST /api/v1/exchange.
type ExchangeResponse struct {
	AccessToken  string                 `json:"access_token"`
	TokenType    string                 `json:"token_type"`
	ExpiresIn    int                    `json:"expires_in"`
	Scopes       []string               `json:"scopes"`
	Role         string                 `json:"role"`
	ConnectionID string                 `json:"connection_id"`
	App          map[string]interface{} `json:"app,omitempty"`
	Endpoints    map[string]interface{} `json:"endpoints,omitempty"`
}

// Exchange swaps a single-use connection token for an access token.
// Calls POST /api/v1/exchange — unauthenticated by design: the connection
// token itself is the credential, so the operator API key is NOT sent.
func (c *Client) Exchange(req ExchangeRequest) (*ExchangeResponse, error) {
	return c.ExchangeContext(context.Background(), req)
}

// ExchangeContext is the context-aware variant of Exchange.
func (c *Client) ExchangeContext(ctx context.Context, req ExchangeRequest) (*ExchangeResponse, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("agentadmit: marshal exchange request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL()+"/api/v1/exchange", bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("agentadmit: build request: %w", err)
	}
	// No Authorization header — the connection token is the credential.
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", userAgent)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("agentadmit: exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("agentadmit: read response body: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("agentadmit: exchange returned %d: %s", resp.StatusCode, string(respBytes))
	}

	var result ExchangeResponse
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("agentadmit: decode exchange response: %w", err)
	}
	return &result, nil
}

// RevokeRequest is the body for POST /api/v1/revoke.
type RevokeRequest struct {
	ConnectionID string `json:"connection_id"`
	Reason       string `json:"reason,omitempty"`
}

// RevokeResponse is returned by POST /api/v1/revoke.
type RevokeResponse struct {
	OK            bool   `json:"ok"`
	ConnectionID  string `json:"connection_id"`
	RevokedAt     string `json:"revoked_at"`
	TokensRevoked bool   `json:"tokens_revoked"`
}

// Revoke revokes a connection (and its access tokens).
// Calls POST /api/v1/revoke on the AgentAdmit hosted service.
func (c *Client) Revoke(req RevokeRequest) (*RevokeResponse, error) {
	return c.RevokeContext(context.Background(), req)
}

// RevokeContext is the context-aware variant of Revoke.
func (c *Client) RevokeContext(ctx context.Context, req RevokeRequest) (*RevokeResponse, error) {
	respBytes, _, err := c.callManagementAPI(ctx, http.MethodPost, "/api/v1/revoke", req)
	if err != nil {
		return nil, err
	}
	var result RevokeResponse
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("agentadmit: decode revoke response: %w", err)
	}
	return &result, nil
}
