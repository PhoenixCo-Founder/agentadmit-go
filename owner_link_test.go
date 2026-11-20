package agentadmit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 1.15.0, Row A: confirmation.enrollment_required on the confirmation_required
// refusal, strict (only a JSON boolean is kept), typed on the error and in the
// 403 body; Row B: Client.CreateOwnerLink.

const enrollmentSentence = "This action requires a fresh human confirmation, and this user has no passkey on file for the app yet, so the confirmation link alone cannot be used. Ask the user to open the request from inside the app. After they confirm, retry with the X-AgentAdmit-Action-Attestation header."

func refusalWithEnrollment(fragment string) string {
	return `{"active":true,"error":"confirmation_required","confirmation":{` +
		`"action_session_id":"asess_abc","action_session_url":"https://agentadmit.com/confirm/action/asess_abc",` +
		fragment +
		`"expires_at":"e","scope":"write:payments","method":null,"endpoint":null,"request_digest":null,"summary":null}}`
}

// runRefusal drives the net/http middleware and returns the typed error from
// Verify plus the decoded 403 body.
func runRefusal(t *testing.T, response string) (*AgentAdmitError, map[string]json.RawMessage) {
	t.Helper()
	var captured []map[string]interface{}
	client := newTelemetryClient(t, response, &captured)

	_, err := client.ValidateContext(context.Background(), "ag_at_tok", []string{"write:payments"})
	var aaErr *AgentAdmitError
	if !errors.As(err, &aaErr) {
		t.Fatalf("Validate err = %v, want *AgentAdmitError", err)
	}
	if aaErr.Confirmation != nil && !IsConfirmationRequired(err) {
		t.Fatalf("Validate err = %T, want *ConfirmationRequiredError", err)
	}

	var invoked bool
	var seen string
	handler := client.Middleware("write:payments")(echoBodyHandler(&invoked, &seen))
	req := httptest.NewRequest(http.MethodPost, "/api/payments", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer ag_at_tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || invoked {
		t.Fatalf("status = %d invoked = %v, want 403 and no handler", rec.Code, invoked)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("403 body is not JSON: %v", err)
	}
	return aaErr, body
}

func TestEnrollmentRequired_Matrix(t *testing.T) {
	cases := []struct {
		name     string
		fragment string
		want     *bool // nil = not stated
		wireKey  string
	}{
		{"true", `"enrollment_required":true,`, boolPtr(true), "true"},
		{"false", `"enrollment_required":false,`, boolPtr(false), "false"},
		{"absent", ``, nil, ""},
		{"null", `"enrollment_required":null,`, nil, ""},
		{"string true", `"enrollment_required":"true",`, nil, ""},
		{"one", `"enrollment_required":1,`, nil, ""},
		{"zero", `"enrollment_required":0,`, nil, ""},
		{"object", `"enrollment_required":{},`, nil, ""},
		{"array", `"enrollment_required":[],`, nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			aaErr, body := runRefusal(t, refusalWithEnrollment(tc.fragment))
			if aaErr.Confirmation == nil {
				t.Fatal("typed confirmation missing")
			}
			got := aaErr.Confirmation.EnrollmentRequired
			if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
				t.Errorf("typed EnrollmentRequired = %v, want %v", got, tc.want)
			}
			var conf map[string]json.RawMessage
			if err := json.Unmarshal(body["confirmation"], &conf); err != nil {
				t.Fatalf("confirmation not an object: %v", err)
			}
			raw, present := conf["enrollment_required"]
			if tc.wireKey == "" {
				if present {
					t.Errorf("403 body carries enrollment_required = %s, want the key absent", raw)
				}
			} else if string(raw) != tc.wireKey {
				t.Errorf("403 body enrollment_required = %s, want %s", raw, tc.wireKey)
			}
			if string(conf["action_session_url"]) != `"https://agentadmit.com/confirm/action/asess_abc"` {
				t.Errorf("action_session_url lost: %s", conf["action_session_url"])
			}
		})
	}
}

func TestEnrollmentRequired_BlockMissingURLStillDroppedWhole(t *testing.T) {
	aaErr, body := runRefusal(t, `{"active":true,"error":"confirmation_required","confirmation":{`+
		`"action_session_id":"asess_abc","enrollment_required":true,"expires_at":"e","scope":"write:payments"}}`)
	if aaErr.Confirmation != nil {
		t.Fatalf("typed confirmation = %+v, want nil", aaErr.Confirmation)
	}
	if _, present := body["confirmation"]; present {
		t.Fatalf("403 body carries a confirmation block: %s", body["confirmation"])
	}
	var description string
	_ = json.Unmarshal(body["error_description"], &description)
	if description != confirmationRequiredDescription {
		t.Errorf("error_description = %q, want the unchanged fallback", description)
	}
}

func TestEnrollmentRequired_Sentence(t *testing.T) {
	description := func(fragment string) string {
		_, body := runRefusal(t, refusalWithEnrollment(fragment))
		var d string
		_ = json.Unmarshal(body["error_description"], &d)
		return d
	}
	if got := description(`"enrollment_required":true,`); got != enrollmentSentence {
		t.Errorf("true: error_description = %q", got)
	}
	for _, fragment := range []string{`"enrollment_required":false,`, ``} {
		if got := description(fragment); got != confirmationRequiredDescription {
			t.Errorf("%q: error_description = %q, want the unchanged sentence", fragment, got)
		}
	}
	// The hosted description still wins for false and absent, as before.
	_, body := runRefusal(t, `{"active":true,"error":"confirmation_required","error_description":"hosted words",`+
		`"confirmation":{"action_session_id":"asess_abc","action_session_url":"u","enrollment_required":false,"expires_at":"e","scope":"s"}}`)
	if string(body["error_description"]) != `"hosted words"` {
		t.Errorf("false with hosted description: %s", body["error_description"])
	}
	// For true the enrollment sentence replaces the hosted one.
	_, body = runRefusal(t, `{"active":true,"error":"confirmation_required","error_description":"hosted words",`+
		`"confirmation":{"action_session_id":"asess_abc","action_session_url":"u","enrollment_required":true,"expires_at":"e","scope":"s"}}`)
	var d string
	_ = json.Unmarshal(body["error_description"], &d)
	if d != enrollmentSentence {
		t.Errorf("true with hosted description: %q", d)
	}
}

func boolPtr(b bool) *bool { return &b }

// ---------------------------------------------------------------------------
// Row B: CreateOwnerLink
// ---------------------------------------------------------------------------

type ownerLinkCall struct {
	method, escapedPath, auth, contentType string
	body                                   map[string]interface{}
}

func newOwnerLinkClient(t *testing.T, status int, response string, calls *[]ownerLinkCall) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]interface{}
		_ = json.Unmarshal(raw, &body)
		*calls = append(*calls, ownerLinkCall{
			method:      r.Method,
			escapedPath: r.URL.EscapedPath(),
			auth:        r.Header.Get("Authorization"),
			contentType: r.Header.Get("Content-Type"),
			body:        body,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(server.Close)
	client, err := New(Config{APIKey: "aa_test_dummy", VerifyURL: server.URL, APIURL: server.URL, MaxRetries: 0})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

const ownerLinkSession = "asess_0123456789abcdef"

func TestCreateOwnerLink_Request(t *testing.T) {
	var calls []ownerLinkCall
	client := newOwnerLinkClient(t, http.StatusCreated, `{"action_session_id":"asess_a/b c-_0123456789","owner_session_url":"https://agentadmit.com/confirm/action/x#t=secret","enrollment_required":true,"enrollment_reason":"no_passkey","expires_at":"e"}`, &calls)

	// An id with characters that need encoding proves it goes through an
	// encoder (real ids only use - and _).
	if _, err := client.CreateOwnerLink(context.Background(), "asess_a/b c-_0123456789", "user_42"); err != nil {
		t.Fatalf("CreateOwnerLink: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	c := calls[0]
	if c.method != http.MethodPost {
		t.Errorf("method = %s", c.method)
	}
	if c.escapedPath != "/api/v1/action-sessions/asess_a%2Fb%20c-_0123456789/owner-link" {
		t.Errorf("path = %s", c.escapedPath)
	}
	if c.auth != "Bearer aa_test_dummy" {
		t.Errorf("Authorization = %q", c.auth)
	}
	if c.contentType != "application/json" {
		t.Errorf("Content-Type = %q", c.contentType)
	}
	if len(c.body) != 1 || c.body["app_user_id"] != "user_42" {
		t.Errorf("body = %v, want exactly {app_user_id: user_42}", c.body)
	}

	// The ordinary id is sent unchanged.
	calls = nil
	if _, err := client.CreateOwnerLink(context.Background(), ownerLinkSession, "user_42"); err != nil {
		t.Fatal(err)
	}
	if calls[0].escapedPath != "/api/v1/action-sessions/"+ownerLinkSession+"/owner-link" {
		t.Errorf("path = %s", calls[0].escapedPath)
	}
}

func TestCreateOwnerLink_201And200(t *testing.T) {
	var calls []ownerLinkCall
	client := newOwnerLinkClient(t, http.StatusCreated, `{"action_session_id":"`+ownerLinkSession+`","owner_session_url":"https://agentadmit.com/o#t=1","enrollment_required":true,"enrollment_reason":"no_eligible_authenticator","expires_at":"2026-11-20T18:00:00.000Z"}`, &calls)
	link, err := client.CreateOwnerLink(context.Background(), ownerLinkSession, "user_42")
	if err != nil {
		t.Fatal(err)
	}
	if link.ActionSessionID != ownerLinkSession || link.OwnerSessionURL != "https://agentadmit.com/o#t=1" ||
		!link.EnrollmentRequired || link.EnrollmentReason == nil || *link.EnrollmentReason != "no_eligible_authenticator" ||
		link.ExpiresAt != "2026-11-20T18:00:00.000Z" {
		t.Errorf("201 result = %+v", link)
	}

	client = newOwnerLinkClient(t, http.StatusOK, `{"action_session_id":"`+ownerLinkSession+`","owner_session_url":"https://agentadmit.com/confirm/action/x","enrollment_required":false,"expires_at":"e"}`, &calls)
	link, err = client.CreateOwnerLink(context.Background(), ownerLinkSession, "user_42")
	if err != nil {
		t.Fatal(err)
	}
	if link.EnrollmentRequired || link.EnrollmentReason != nil || link.OwnerSessionURL != "https://agentadmit.com/confirm/action/x" {
		t.Errorf("200 result = %+v", link)
	}
	out, _ := json.Marshal(link)
	if strings.Contains(string(out), "enrollment_reason") {
		t.Errorf("200 result marshals enrollment_reason: %s", out)
	}
}

func TestCreateOwnerLink_ErrorStatuses(t *testing.T) {
	cases := []struct {
		status int
		code   string
	}{
		{401, "invalid_api_key"},
		{403, "api_key_not_app_linked"},
		{404, "not_found"},
		{409, "already_consumed"},
		{409, "already_verified"},
		{410, "session_expired"},
		{429, "rate_limited"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			var calls []ownerLinkCall
			client := newOwnerLinkClient(t, tc.status, `{"error":"`+tc.code+`","error_description":"d"}`, &calls)
			link, err := client.CreateOwnerLink(context.Background(), ownerLinkSession, "user_42")
			if link != nil {
				t.Fatalf("result = %+v, want nil", link)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("err = %v, want *APIError", err)
			}
			if apiErr.StatusCode != tc.status || apiErr.Code != tc.code {
				t.Errorf("APIError = %d %q, want %d %q", apiErr.StatusCode, apiErr.Code, tc.status, tc.code)
			}
			if len(calls) != 1 {
				t.Errorf("calls = %d, want 1 (no retry on 4xx)", len(calls))
			}
		})
	}
}

func TestCreateOwnerLink_ArgumentErrorsMakeNoRequest(t *testing.T) {
	var calls []ownerLinkCall
	client := newOwnerLinkClient(t, http.StatusCreated, `{}`, &calls)
	cases := []struct{ session, user string }{
		{"sess_0123456789abcdefgh", "user_42"},       // wrong prefix
		{"asess_short", "user_42"},                   // too short
		{"", "user_42"},                              // empty
		{ownerLinkSession, ""},                       // empty user id
		{ownerLinkSession, strings.Repeat("u", 256)}, // user id too long
	}
	for _, tc := range cases {
		_, err := client.CreateOwnerLink(context.Background(), tc.session, tc.user)
		if !errors.Is(err, ErrInvalidOwnerLinkArgument) {
			t.Errorf("(%q, %d chars): err = %v, want ErrInvalidOwnerLinkArgument", tc.session, len(tc.user), err)
		}
	}
	if len(calls) != 0 {
		t.Errorf("calls = %d, want 0", len(calls))
	}
	if _, err := client.CreateOwnerLink(context.Background(), ownerLinkSession, strings.Repeat("u", 255)); errors.Is(err, ErrInvalidOwnerLinkArgument) {
		t.Errorf("255-character user id rejected")
	}
}

func TestCreateOwnerLink_Malformed2xx(t *testing.T) {
	bodies := []string{
		`{"action_session_id":"x","enrollment_required":true,"expires_at":"e"}`,
		`{"action_session_id":"x","owner_session_url":5,"enrollment_required":true}`,
		`{"action_session_id":"x","owner_session_url":"https://agentadmit.com/o#t=secret","expires_at":"e"}`,
		`{"action_session_id":"x","owner_session_url":"https://agentadmit.com/o#t=secret","enrollment_required":"true"}`,
		`not json https://agentadmit.com/o#t=secret`,
		`[]`,
		// Same rule as the other five SDKs: the result promises all four
		// fields, so a body without the id or the expiry is malformed too.
		`{"owner_session_url":"https://agentadmit.com/o#t=secret","enrollment_required":true,"expires_at":"e"}`,
		`{"action_session_id":"x","owner_session_url":"https://agentadmit.com/o#t=secret","enrollment_required":true}`,
		`{"action_session_id":7,"owner_session_url":"https://agentadmit.com/o#t=secret","enrollment_required":false,"expires_at":"e"}`,
	}
	for _, body := range bodies {
		var calls []ownerLinkCall
		client := newOwnerLinkClient(t, http.StatusCreated, body, &calls)
		link, err := client.CreateOwnerLink(context.Background(), ownerLinkSession, "user_42")
		if link != nil || !errors.Is(err, ErrMalformedOwnerLinkResponse) {
			t.Errorf("%s: link = %+v err = %v, want ErrMalformedOwnerLinkResponse", body, link, err)
		}
		// The owner session URL never reaches an error message.
		if err != nil && (strings.Contains(err.Error(), "agentadmit.com/o") || strings.Contains(err.Error(), "secret")) {
			t.Errorf("error message carries the URL: %v", err)
		}
	}
}

// The reason belongs to an enrollment: a stray enrollment_reason on a
// "passkey already on file" answer is not copied through (same in all six SDKs).
func TestCreateOwnerLink_ReasonOnlyWithEnrollment(t *testing.T) {
	var calls []ownerLinkCall
	body := `{"action_session_id":"` + ownerLinkSession + `","owner_session_url":"https://agentadmit.com/confirm/action/x","enrollment_required":false,"enrollment_reason":"no_passkey","expires_at":"2026-11-20T18:30:00.000Z"}`
	client := newOwnerLinkClient(t, http.StatusOK, body, &calls)
	link, err := client.CreateOwnerLink(context.Background(), ownerLinkSession, "user_42")
	if err != nil || link == nil {
		t.Fatalf("err = %v link = %+v", err, link)
	}
	if link.EnrollmentRequired || link.EnrollmentReason != nil {
		t.Errorf("EnrollmentRequired = %v EnrollmentReason = %v, want false and nil", link.EnrollmentRequired, link.EnrollmentReason)
	}
}
