package agentadmit

// Regression tests for 429 retry handling in ValidateContext.
//
// A server-supplied Retry-After header is untrusted input: a compromised or
// misconfigured endpoint could send `Retry-After: 3600` and pin the caller's
// request for an hour. Every wait must be capped at 30 seconds, and
// cumulative wait across retries of one verify call must be capped at 120
// seconds.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// newRetryTestClient builds a client against a stub verify endpoint and
// replaces the sleep hook with a recorder so tests never actually wait.
func newRetryTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *[]time.Duration, *int32) {
	t.Helper()

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		handler(w, r)
	}))
	t.Cleanup(server.Close)

	client, err := New(Config{
		APIKey:    "aa_test_dummy",
		VerifyURL: server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	sleeps := []time.Duration{}
	client.sleep = func(ctx context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		return nil
	}
	return client, &sleeps, &requests
}

func always429(retryAfter string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", retryAfter)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
	}
}

func TestRetryAfterCappedAt30s(t *testing.T) {
	client, sleeps, _ := newRetryTestClient(t, always429("3600"))

	_, err := client.Validate("ag_at_dummy", nil)

	var rlErr *RateLimitError
	if !errors.As(err, &rlErr) {
		t.Fatalf("want RateLimitError, got %v", err)
	}
	if len(*sleeps) == 0 {
		t.Fatal("expected at least one retry wait")
	}
	maxWait := 30*time.Second + 500*time.Millisecond
	for _, d := range *sleeps {
		if d > maxWait {
			t.Fatalf("wait %v exceeds cap %v — Retry-After was not capped", d, maxWait)
		}
	}
}

func TestCumulativeRetryBudget(t *testing.T) {
	client, sleeps, requests := newRetryTestClient(t, always429("30"))
	// High retry count so the 120s budget, not the retry count, is the limiter.
	client.maxRetries = 99

	_, err := client.Validate("ag_at_dummy", nil)

	var rlErr *RateLimitError
	if !errors.As(err, &rlErr) {
		t.Fatalf("want RateLimitError, got %v", err)
	}
	// ~30s + jitter per wait -> at most 3 sleeps before the 4th would blow
	// the 120s budget.
	if len(*sleeps) > 3 {
		t.Fatalf("budget allowed %d sleeps, want <= 3", len(*sleeps))
	}
	if got := atomic.LoadInt32(requests); got > 4 {
		t.Fatalf("budget allowed %d requests, want <= 4", got)
	}
}

func TestRecoversWithinBudget(t *testing.T) {
	var calls int32
	client, sleeps, _ := newRetryTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"user_id":"user_1","connection_id":"conn_1","scopes":["read:things"]}`))
	})

	info, err := client.Validate("ag_at_dummy", nil)
	if err != nil {
		t.Fatal(err)
	}
	if info.ConnectionID != "conn_1" {
		t.Fatalf("want conn_1, got %q", info.ConnectionID)
	}
	if len(*sleeps) != 1 {
		t.Fatalf("want exactly one retry wait, got %d", len(*sleeps))
	}
}
