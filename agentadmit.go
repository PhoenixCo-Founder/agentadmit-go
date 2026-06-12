package agentadmit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultVerifyURL is the AgentAdmit introspection endpoint.
	DefaultVerifyURL = "https://api.agentadmit.com/api/v1/verify"

	// DefaultTimeout is the default HTTP timeout for introspection calls.
	DefaultTimeout = 5 * time.Second
)

// DefaultMaxRetries is the default number of retry attempts on HTTP 429.
const DefaultMaxRetries = 3

// Client is the AgentAdmit SDK client. Create one via New() and reuse it
// across requests. It is safe for concurrent use.
type Client struct {
	apiKey     string
	verifyURL  string
	apiURLStr  string
	http       *http.Client
	maxRetries int
}

// New creates a new AgentAdmit Client with the provided Config.
// Returns ErrCodeConfig if the API key is empty or doesn't carry an
// aa_test_/aa_live_ prefix.
func New(cfg Config) (*Client, error) {
	if cfg.APIKey == "" {
		return nil, newError(ErrCodeConfig, "APIKey is required", nil)
	}
	// Validate the prefix without ever echoing the key itself.
	if !strings.HasPrefix(cfg.APIKey, "aa_test_") && !strings.HasPrefix(cfg.APIKey, "aa_live_") {
		return nil, newError(ErrCodeConfig, "APIKey must start with 'aa_test_' or 'aa_live_'", nil)
	}

	verifyURL := cfg.VerifyURL
	if verifyURL == "" {
		verifyURL = DefaultVerifyURL
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	maxRetries := cfg.MaxRetries
	if maxRetries == 0 {
		maxRetries = DefaultMaxRetries
	}

	apiURLStr := cfg.APIURL
	if apiURLStr == "" {
		apiURLStr = DefaultAPIURL
	}

	return &Client{
		apiKey:     cfg.APIKey,
		verifyURL:  verifyURL,
		apiURLStr:  apiURLStr,
		http:       &http.Client{Timeout: timeout},
		maxRetries: maxRetries,
	}, nil
}

// Validate sends the agent token to AgentAdmit's introspection endpoint and
// verifies it has the required scopes.
//
//   - token: the AgentAdmit access token presented by the AI agent
//     (typically extracted from the Authorization header).
//   - requiredScopes: scopes that must be present on the token.
//     Pass nil or an empty slice to skip scope enforcement (token valid = pass).
//
// Returns *TokenInfo on success, or an *AgentAdmitError on failure.
// The error Code distinguishes between ErrCodeInvalidToken,
// ErrCodeInsufficientScopes, and ErrCodeServiceUnavailable.
func (c *Client) Validate(token string, requiredScopes []string) (*TokenInfo, error) {
	return c.ValidateContext(context.Background(), token, requiredScopes)
}

// ValidateContext is the context-aware variant of Validate. Prefer this in
// HTTP handlers so the introspection call respects request cancellation.
func (c *Client) ValidateContext(ctx context.Context, token string, requiredScopes []string) (*TokenInfo, error) {
	if token == "" {
		return nil, newError(ErrCodeInvalidToken, "token is empty", nil)
	}

	// Build request body
	reqBody := verifyRequest{
		Token:  token,
		Scopes: requiredScopes,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, newError(ErrCodeConfig, "failed to marshal verify request", err)
	}

	// Retry loop — handles 429 with exponential backoff + jitter.
	delayMs := 1000.0 // initial backoff: 1 second (in ms)

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.verifyURL, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, newError(ErrCodeConfig, "failed to build HTTP request", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("User-Agent", userAgent)

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, newError(ErrCodeServiceUnavailable, "introspection request failed", err)
		}

		if resp.StatusCode == 429 {
			// Parse rate-limit headers
			retryAfter := parseFloatHeader(resp, "Retry-After")
			rlLimit := parseIntHeader(resp, "X-RateLimit-Limit")
			rlRemaining := parseIntHeader(resp, "X-RateLimit-Remaining")
			rlReset := parseInt64Header(resp, "X-RateLimit-Reset")
			resp.Body.Close()

			if attempt >= c.maxRetries {
				return nil, &RateLimitError{
					RetryAfter: retryAfter,
					Limit:      rlLimit,
					Remaining:  rlRemaining,
					Reset:      rlReset,
					MaxRetries: c.maxRetries,
				}
			}

			// Compute wait: Retry-After beats exponential backoff; cap at 30s
			var waitMs float64
			if retryAfter >= 0 {
				waitMs = retryAfter * 1000
			} else {
				waitMs = math.Min(delayMs, 30_000)
			}
			jitterMs := rand.Float64() * 500 // 0–500 ms
			totalWait := time.Duration((waitMs + jitterMs) * float64(time.Millisecond))

			select {
			case <-ctx.Done():
				return nil, newError(ErrCodeServiceUnavailable, "context cancelled during rate-limit retry", ctx.Err())
			case <-time.After(totalWait):
			}

			delayMs = math.Min(delayMs*2, 30_000)
			continue
		}

		// Non-429 response — read and process
		respBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, newError(ErrCodeServiceUnavailable, "failed to read introspection response", err)
		}

		if resp.StatusCode >= 500 {
			return nil, newError(ErrCodeServiceUnavailable,
				fmt.Sprintf("AgentAdmit service returned %d", resp.StatusCode), nil)
		}

		var info TokenInfo
		if err := json.Unmarshal(respBytes, &info); err != nil {
			return nil, newError(ErrCodeServiceUnavailable, "failed to decode introspection response", err)
		}

		// Derive ExpiresAt from the RFC 7662 `exp` claim for back-compat.
		if info.ExpiresAt == "" && info.Exp > 0 {
			info.ExpiresAt = time.Unix(info.Exp, 0).UTC().Format(time.RFC3339)
		}

		if !info.Active {
			// info.Error is one of the Verify* constants (e.g. token_expired,
			// connection_expired, environment_mismatch); unknown codes pass
			// through. insufficient_scope maps to the scopes error class.
			reason := info.Error
			if reason == "" {
				reason = VerifyErrorInvalidToken
			}
			if reason == VerifyErrorInsufficientScope {
				return nil, newError(ErrCodeInsufficientScopes, "token is not active: "+reason, nil)
			}
			return nil, newError(ErrCodeInvalidToken, "token is not active: "+reason, nil)
		}

		// Scope enforcement (AgentAdmit also enforces server-side, but this gives
		// a clear local error for logging and fast-fail before sending data).
		if len(requiredScopes) > 0 {
			missing := missingScopes(info.Scopes, requiredScopes)
			if len(missing) > 0 {
				return nil, newError(ErrCodeInsufficientScopes,
					fmt.Sprintf("token missing required scopes: %v", missing), nil)
			}
		}

		return &info, nil
	}

	// Should never be reached
	return nil, newError(ErrCodeServiceUnavailable, "unexpected exit from retry loop", nil)
}

// ---------------------------------------------------------------------------
// Rate-limit header parsing helpers
// ---------------------------------------------------------------------------

// parseFloatHeader reads a float64 from a response header. Returns -1 if absent or invalid.
func parseFloatHeader(resp *http.Response, name string) float64 {
	v := resp.Header.Get(name)
	if v == "" {
		return -1
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return -1
	}
	return f
}

// parseIntHeader reads an int from a response header. Returns -1 if absent or invalid.
func parseIntHeader(resp *http.Response, name string) int {
	v := resp.Header.Get(name)
	if v == "" {
		return -1
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return -1
	}
	return n
}

// parseInt64Header reads an int64 from a response header. Returns -1 if absent or invalid.
func parseInt64Header(resp *http.Response, name string) int64 {
	v := resp.Header.Get(name)
	if v == "" {
		return -1
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return -1
	}
	return n
}

// TokenFromContext retrieves a previously validated *TokenInfo from a
// context.Context. Returns nil if no token was stored.
//
// This is used by middleware to propagate token metadata to downstream
// handlers without re-validating.
func TokenFromContext(ctx context.Context) *TokenInfo {
	if v := ctx.Value(tokenContextKey); v != nil {
		if info, ok := v.(*TokenInfo); ok {
			return info
		}
	}
	return nil
}

// contextWithToken returns a new context with the given *TokenInfo attached.
// Used internally by middleware.
func contextWithToken(ctx context.Context, info *TokenInfo) context.Context {
	return context.WithValue(ctx, tokenContextKey, info)
}

// missingScopes returns scopes from required that are absent from granted.
func missingScopes(granted, required []string) []string {
	grantedSet := make(map[string]struct{}, len(granted))
	for _, s := range granted {
		grantedSet[s] = struct{}{}
	}
	var missing []string
	for _, s := range required {
		if _, ok := grantedSet[s]; !ok {
			missing = append(missing, s)
		}
	}
	return missing
}
