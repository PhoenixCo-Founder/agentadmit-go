package agentadmit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

const DefaultAPIURL = "https://api.agentadmit.com"

// apiURL returns the management API base URL from Config, defaulting to DefaultAPIURL.
func (c *Client) apiURL() string {
	if c.apiURLStr != "" {
		return c.apiURLStr
	}
	return DefaultAPIURL
}

// callManagementAPI makes an authenticated request to the AgentAdmit management API.
// method must be "GET" or "POST". For GET, body should be nil.
func (c *Client) callManagementAPI(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	base := c.apiURL()
	fullURL := base + path

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("agentadmit: marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("agentadmit: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("agentadmit: management API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("agentadmit: read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, resp.StatusCode, fmt.Errorf("agentadmit: management API returned %d: %s",
			resp.StatusCode, string(respBytes))
	}

	return respBytes, resp.StatusCode, nil
}

// ConfigureAlerts configures alert thresholds for an app or connection.
// Calls POST /api/v1/alerts on the AgentAdmit hosted service.
func (c *Client) ConfigureAlerts(req ConfigureAlertsRequest) (*ConfigureAlertsResponse, error) {
	return c.ConfigureAlertsContext(context.Background(), req)
}

// ConfigureAlertsContext is the context-aware variant of ConfigureAlerts.
func (c *Client) ConfigureAlertsContext(ctx context.Context, req ConfigureAlertsRequest) (*ConfigureAlertsResponse, error) {
	respBytes, _, err := c.callManagementAPI(ctx, http.MethodPost, "/api/v1/alerts", req)
	if err != nil {
		return nil, err
	}
	var result ConfigureAlertsResponse
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("agentadmit: decode configure alerts response: %w", err)
	}
	return &result, nil
}

// ListAlertsOptions holds filters and pagination for ListAlerts.
type ListAlertsOptions struct {
	AppID        string
	ConnectionID string    // optional
	AlertType    AlertType // optional
	Limit        int       // 0 = default (50)
	Offset       int
}

// ListAlerts retrieves alert events for an app.
// Calls GET /api/v1/alerts on the AgentAdmit hosted service.
func (c *Client) ListAlerts(opts ListAlertsOptions) (*ListAlertsResponse, error) {
	return c.ListAlertsContext(context.Background(), opts)
}

// ListAlertsContext is the context-aware variant of ListAlerts.
func (c *Client) ListAlertsContext(ctx context.Context, opts ListAlertsOptions) (*ListAlertsResponse, error) {
	q := url.Values{}
	q.Set("app_id", opts.AppID)
	if opts.ConnectionID != "" {
		q.Set("connection_id", opts.ConnectionID)
	}
	if opts.AlertType != "" {
		q.Set("alert_type", opts.AlertType)
	}
	limit := opts.Limit
	if limit == 0 {
		limit = 50
	}
	q.Set("limit", strconv.Itoa(limit))
	q.Set("offset", strconv.Itoa(opts.Offset))

	path := "/api/v1/alerts?" + q.Encode()
	respBytes, _, err := c.callManagementAPI(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var result ListAlertsResponse
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("agentadmit: decode list alerts response: %w", err)
	}
	return &result, nil
}

// GetAlertConfigOptions holds filters for GetAlertConfig.
type GetAlertConfigOptions struct {
	AppID        string
	ConnectionID string // optional
}

// GetAlertConfig retrieves the current alert configuration for an app.
// Calls GET /api/v1/alerts/config on the AgentAdmit hosted service.
func (c *Client) GetAlertConfig(opts GetAlertConfigOptions) (*AlertConfigResponse, error) {
	return c.GetAlertConfigContext(context.Background(), opts)
}

// GetAlertConfigContext is the context-aware variant of GetAlertConfig.
func (c *Client) GetAlertConfigContext(ctx context.Context, opts GetAlertConfigOptions) (*AlertConfigResponse, error) {
	q := url.Values{}
	q.Set("app_id", opts.AppID)
	if opts.ConnectionID != "" {
		q.Set("connection_id", opts.ConnectionID)
	}

	path := "/api/v1/alerts/config?" + q.Encode()
	respBytes, _, err := c.callManagementAPI(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var result AlertConfigResponse
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("agentadmit: decode alert config response: %w", err)
	}
	return &result, nil
}
