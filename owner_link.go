package agentadmit

// Owner link (1.15.0): open a confirm-each-time request for the app's own
// signed-in user.
//
// A confirmation link handed to an agent can only ask a passkey already on
// file to sign. When the user has none yet, the confirmation_required
// refusal says so (ActionConfirmation.EnrollmentRequired), and the app opens
// the request for its signed-in user instead: the user creates a passkey and
// confirms on the page the owner link opens. On a computer that page can show
// a QR code to continue on the user's phone.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Argument limits for CreateOwnerLink, checked before any network call.
const (
	ownerLinkSessionPrefix   = "asess_"
	ownerLinkMinSessionChars = 20
	ownerLinkMaxUserIDChars  = 255
)

// ErrInvalidOwnerLinkArgument is wrapped by the error CreateOwnerLink
// returns, before any network call, when the action session id is not an
// "asess_" id of at least 20 characters or the app user id is empty or
// longer than 255 characters.
var ErrInvalidOwnerLinkArgument = errors.New("agentadmit: invalid owner link argument")

// ErrMalformedOwnerLinkResponse is returned when the hosted service answers
// 2xx but the body has no string owner_session_url or no boolean
// enrollment_required. No partial result is returned.
var ErrMalformedOwnerLinkResponse = errors.New("agentadmit: malformed owner link response")

// OwnerLink is the result of CreateOwnerLink.
//
// OwnerSessionURL opens the confirmation for the app's signed-in user. It is
// a secret for that user: send it only to that user's browser, never to an
// agent, and never log it. The SDK does not log it either.
type OwnerLink struct {
	ActionSessionID string `json:"action_session_id"`
	OwnerSessionURL string `json:"owner_session_url"`
	// EnrollmentRequired is true when the user has no passkey on file for
	// the app yet (201): the page has them create one, then confirm. False
	// (200) means a passkey is already on file and the URL is the ordinary
	// confirmation page.
	EnrollmentRequired bool `json:"enrollment_required"`
	// EnrollmentReason is "no_passkey" or "no_eligible_authenticator" when
	// EnrollmentRequired is true; nil otherwise.
	EnrollmentReason *string `json:"enrollment_reason,omitempty"`
	ExpiresAt        string  `json:"expires_at"`
}

type ownerLinkRequest struct {
	AppUserID string `json:"app_user_id"`
}

// CreateOwnerLink opens a pending confirm-each-time request for the app's
// own signed-in user. Calls POST /api/v1/action-sessions/{id}/owner-link
// with the app's API key.
//
// Two rules:
//   - Call it only from a route your signed-in human uses, passing that
//     user's own id as appUserID. The hosted service answers 404 when the
//     session belongs to a different user than the one named.
//   - Never return OwnerSessionURL to an agent. Send it to the signed-in
//     user's browser only.
//
// Do not mount it as an agent-facing route; it is a method your own
// signed-in-user route calls. Hosted error statuses (401 invalid_api_key,
// 403 api_key_not_app_linked, 404 not_found, 409 already_consumed or
// already_verified, 410 session_expired, 429) come back as *APIError and are
// not retried. Calling it again for the same session is safe: a new link
// replaces the previous one.
func (c *Client) CreateOwnerLink(ctx context.Context, actionSessionID, appUserID string) (*OwnerLink, error) {
	if !strings.HasPrefix(actionSessionID, ownerLinkSessionPrefix) || len(actionSessionID) < ownerLinkMinSessionChars {
		return nil, fmt.Errorf("%w: actionSessionID must be an %s id of at least %d characters",
			ErrInvalidOwnerLinkArgument, ownerLinkSessionPrefix, ownerLinkMinSessionChars)
	}
	if appUserID == "" || len(appUserID) > ownerLinkMaxUserIDChars {
		return nil, fmt.Errorf("%w: appUserID must be 1 to %d characters",
			ErrInvalidOwnerLinkArgument, ownerLinkMaxUserIDChars)
	}

	path := "/api/v1/action-sessions/" + url.PathEscape(actionSessionID) + "/owner-link"
	respBytes, _, err := c.callManagementAPI(ctx, http.MethodPost, path, ownerLinkRequest{AppUserID: appUserID})
	if err != nil {
		return nil, err
	}
	return parseOwnerLink(respBytes)
}

// parseOwnerLink strictly decodes a 2xx owner link body. The body is never
// put into an error, since it carries the owner session URL.
func parseOwnerLink(respBytes []byte) (*OwnerLink, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(respBytes, &fields); err != nil || fields == nil {
		return nil, ErrMalformedOwnerLinkResponse
	}
	ownerURL, okURL := rawString(fields["owner_session_url"])
	enrollment := strictBool(fields["enrollment_required"])
	if !okURL || enrollment == nil {
		return nil, ErrMalformedOwnerLinkResponse
	}
	link := &OwnerLink{
		OwnerSessionURL:    ownerURL,
		EnrollmentRequired: *enrollment,
	}
	link.ActionSessionID, _ = rawString(fields["action_session_id"])
	link.ExpiresAt, _ = rawString(fields["expires_at"])
	if reason, ok := rawString(fields["enrollment_reason"]); ok {
		link.EnrollmentReason = &reason
	}
	return link, nil
}
