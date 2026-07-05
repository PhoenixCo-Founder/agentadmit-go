package agentadmit

// Human-presence fact from the WebAuthn human-presence step-up.
//
// The verify response can carry an additive "presence" block reporting
// whether the human who authorized the connection completed a presence
// ceremony (WebAuthn) on the consent page. Older servers omit it, and
// connections minted without a ceremony (direct-API tokens, presence-off
// sessions, pre-presence connections) carry Verified = false.
//
// Presence is additive metadata: a missing or dropped block never fails an
// otherwise valid verify. Callers that gate on presence must fail closed,
// treating nil Presence as not verified.

// Presence is the human-presence fact for the connection, returned inline
// in the verify response (TokenInfo.Presence). Nil when the platform did
// not return one.
type Presence struct {
	// Verified reports whether the human who authorized this connection
	// completed a presence ceremony.
	Verified bool `json:"verified"`

	// Method is the ceremony type, e.g. "webauthn". Empty when never
	// verified (the platform sends null).
	Method string `json:"method,omitempty"`

	// UV is the authenticator user-verification flag reported by the
	// ceremony. Nil when never verified (the platform sends null).
	UV *bool `json:"uv,omitempty"`

	// VerifiedAt is the ceremony timestamp in ISO-8601 format. Empty when
	// never verified (the platform sends null).
	VerifiedAt string `json:"verified_at,omitempty"`
}

// IsPresenceVerified reports whether the connection behind this token was
// authorized by a human who completed a presence ceremony (WebAuthn) on the
// consent page. Strict: it is true only when the platform returned a
// presence block with verified set to true. An absent or dropped block is
// NOT verified, including all responses from servers that predate the
// presence feature (fail closed).
func (info *TokenInfo) IsPresenceVerified() bool {
	return info.Presence != nil && info.Presence.Verified
}
