package agentadmit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type OutcomeReport struct {
	OutcomeRowID string       `json:"outcome_row_id"`
	Outcome      Outcome      `json:"outcome"`
	StatusClass  *StatusClass `json:"status_class"`
	ChainSeq     *int64       `json:"chain_seq"`
	RowHash      *string      `json:"row_hash"`
	ReportedAt   string       `json:"reported_at"`
}

func StatusClassFor(statusCode int) *StatusClass {
	if statusCode < 100 || statusCode > 599 {
		return nil
	}
	klass := StatusClass(fmt.Sprintf("%dxx", statusCode/100))
	return &klass
}

func OutcomeForStatus(statusCode int) *Outcome {
	if StatusClassFor(statusCode) == nil {
		return nil
	}
	outcome := OutcomeExecuted
	if statusCode >= 400 {
		outcome = OutcomeFailed
	}
	return &outcome
}

func (c *Client) ReportOutcome(ctx context.Context, auditRowID string, outcome Outcome, statusClass *StatusClass) (*OutcomeReport, error) {
	if auditRowID == "" {
		return nil, newError(ErrCodeConfig, "auditRowID is required", nil)
	}
	if outcome != OutcomeExecuted && outcome != OutcomeFailed && outcome != OutcomeUnknown {
		return nil, newError(ErrCodeConfig, "outcome must be executed, failed, or unknown", nil)
	}
	if statusClass != nil {
		switch *statusClass {
		case Status1xx, Status2xx, Status3xx, Status4xx, Status5xx:
		default:
			return nil, newError(ErrCodeConfig, "statusClass must be 1xx, 2xx, 3xx, 4xx, 5xx, or nil", nil)
		}
	}
	body, err := json.Marshal(struct {
		Outcome     Outcome      `json:"outcome"`
		StatusClass *StatusClass `json:"status_class"`
	}{Outcome: outcome, StatusClass: statusClass})
	if err != nil {
		return nil, newError(ErrCodeConfig, "failed to marshal outcome request", err)
	}
	url := strings.TrimRight(c.apiURLStr, "/") + "/api/v1/audit/" + auditRowID + "/outcome"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, newError(ErrCodeConfig, "failed to build outcome request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, newError(ErrCodeServiceUnavailable, "outcome report failed", err)
	}
	defer resp.Body.Close()
	var out OutcomeReport
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode >= 400 {
		return nil, newError(ErrCodeServiceUnavailable, fmt.Sprintf("outcome report returned %d", resp.StatusCode), nil)
	}
	return &out, nil
}
