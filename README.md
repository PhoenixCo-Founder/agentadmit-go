# AgentAdmit SDK for Go

User-mediated AI agent authorization for Go apps. Supports **net/http**, **Gin**, **Echo**, and **MCP servers**.

> **Get started:** Sign up at [agentadmit.com](https://agentadmit.com) → Get your test keys → Install the SDK → Build.
> Test keys are available immediately after signup. Live keys become available when you subscribe an app.

## Installation

```bash
go get github.com/PhoenixCo-Founder/agentadmit-go
```

## Quickstart

```go
import "github.com/PhoenixCo-Founder/agentadmit-go"

client, _ := agentadmit.New(agentadmit.Config{
    APIKey: os.Getenv("AGENTADMIT_API_KEY"),
})

// Validate a token and enforce required scopes
info, err := client.Validate(token, []string{"read:workouts"})
if err != nil {
    // see error handling below
}
// info.AppID, info.Scopes, info.ExpiresAt
```

## How It Works

1. **User generates a token** in your app's Agent Access page (powered by the AgentAdmit React SDK)
2. **User gives the token to their AI agent** — the token goes to the human, not the agent. No automated delivery = no prompt injection surface.
3. **Agent presents the token** on each API request via `Authorization: Bearer ag_at_...`
4. **Your backend validates via AgentAdmit** — one SDK call enforces scopes, logs the request, and keeps access revocable

## net/http Middleware

```go
import "github.com/PhoenixCo-Founder/agentadmit-go"

client, _ := agentadmit.New(agentadmit.Config{
    APIKey: os.Getenv("AGENTADMIT_API_KEY"),
})

mux := http.NewServeMux()

// Requests without a Bearer token pass through to your existing auth.
// Requests with an AgentAdmit token are validated + scope-checked.
mux.Handle("/api/workouts",
    client.Middleware("read:workouts")(http.HandlerFunc(getWorkouts)))

mux.Handle("/api/workouts/create",
    client.Middleware("create:workouts")(http.HandlerFunc(createWorkout)))

http.ListenAndServe(":8080", mux)
```

Access validated token info in your handler:

```go
func getWorkouts(w http.ResponseWriter, r *http.Request) {
    tokenInfo := agentadmit.TokenFromContext(r.Context())
    if tokenInfo != nil {
        // Agent request — tokenInfo.AppID, tokenInfo.Scopes
    }
    // Regular user request — your existing auth
}
```

## Gin Middleware

```go
import (
    "github.com/PhoenixCo-Founder/agentadmit-go"
    aggin "github.com/PhoenixCo-Founder/agentadmit-go/gin"
    "github.com/gin-gonic/gin"
)

client, _ := agentadmit.New(agentadmit.Config{
    APIKey: os.Getenv("AGENTADMIT_API_KEY"),
})

r := gin.Default()
r.GET("/api/workouts", aggin.Middleware(client, "read:workouts"), func(c *gin.Context) {
    tokenInfo := aggin.GetTokenInfo(c) // nil for regular user requests
    c.JSON(200, gin.H{"workouts": getWorkouts()})
})

r.Run(":8080")
```

## Echo Middleware

```go
import (
    "github.com/PhoenixCo-Founder/agentadmit-go"
    agecho "github.com/PhoenixCo-Founder/agentadmit-go/echo"
    "github.com/labstack/echo/v4"
)

// Note: the subpackage is named agecho to avoid collision with Echo's own package name.
// Import with alias: agecho "github.com/PhoenixCo-Founder/agentadmit-go/echo"

client, _ := agentadmit.New(agentadmit.Config{
    APIKey: os.Getenv("AGENTADMIT_API_KEY"),
})

e := echo.New()
e.GET("/api/workouts", getWorkouts, agecho.Middleware(client, "read:workouts"))

e.Start(":8080")
```

## MCP Server Integration

MCP servers are the primary target for the Go SDK. Go is one of the most popular languages for building MCP servers, and AgentAdmit is the natural auth layer underneath.

The pattern: extract the AgentAdmit token from the tool's `arguments`, validate it, execute only if valid.

```go
import "github.com/PhoenixCo-Founder/agentadmit-go"

// Initialize once at server startup
client, _ := agentadmit.New(agentadmit.Config{
    APIKey: os.Getenv("AGENTADMIT_API_KEY"),
})

// In your JSON-RPC tool/call handler:
func handleToolCall(ctx context.Context, req JSONRPCRequest) JSONRPCResponse {
    var params struct {
        Name      string                 `json:"name"`
        Arguments map[string]interface{} `json:"arguments"`
    }
    json.Unmarshal(req.Params, &params)

    // 1. Extract the token from the tool arguments
    token, _ := params.Arguments["agentadmit_token"].(string)

    // 2. Validate and enforce scopes
    tokenInfo, err := client.ValidateContext(ctx, token, []string{"read:workouts"})
    if err != nil {
        return jsonRPCError(err) // returns 401 or 403 JSON-RPC error
    }

    // 3. Token is valid — execute the tool
    return executeTool(params.Name, params.Arguments, tokenInfo)
}
```

Your MCP tool schema should declare `agentadmit_token` as a required parameter so agents know to include it:

```go
ToolDefinition{
    Name: "get_workouts",
    InputSchema: InputSchema{
        Properties: map[string]Property{
            "agentadmit_token": {
                Type:        "string",
                Description: "AgentAdmit access token (ag_at_...). User obtains this from your app.",
            },
        },
        Required: []string{"agentadmit_token"},
    },
}
```

See [`examples/mcp-server/main.go`](examples/mcp-server/main.go) for a complete, working MCP server example with multiple tools, proper JSON-RPC error codes, and scope-per-tool mapping.

## Error Handling

```go
info, err := client.Validate(token, []string{"read:workouts"})
if err != nil {
    var aaErr *agentadmit.AgentAdmitError
    if errors.As(err, &aaErr) {
        switch aaErr.Code {
        case agentadmit.ErrCodeInvalidToken:
            // Token expired, revoked, or invalid → 401
        case agentadmit.ErrCodeInsufficientScopes:
            // Token valid but lacks required scopes → 403
        case agentadmit.ErrCodeServiceUnavailable:
            // AgentAdmit API unreachable → 503
        case agentadmit.ErrCodeConfig:
            // Misconfigured client (bad API key, etc.) → check startup
        }
    }
}

// Or use the convenience helpers:
if agentadmit.IsInvalidToken(err) { /* 401 */ }
if agentadmit.IsInsufficientScopes(err) { /* 403 */ }
if agentadmit.IsServiceUnavailable(err) { /* 503 */ }
```

## Configuration

```go
client, err := agentadmit.New(agentadmit.Config{
    APIKey:    "aa_test_...",               // Required. From agentadmit.com.
    VerifyURL: "https://api.agentadmit.com/api/v1/verify", // Optional. Default shown.
    Timeout:   5 * time.Second,             // Optional. Default: 5s.
})
```

## Issuing & Exchanging Tokens

Issue a connection token for one of your users, hand it to their agent, and the agent exchanges it for an access token:

```go
// duration_seconds is tri-state:
//   unset                              → AgentAdmit default (30 days)
//   agentadmit.DurationUntilRevoked()  → until the user revokes
//   agentadmit.Duration(3600)          → explicit seconds (60–31536000)
issued, err := client.IssueToken("app_abc123", agentadmit.IssueTokenRequest{
    UserID:          "user_42",
    Scopes:          []string{"read:orders"},
    DurationSeconds: agentadmit.DurationUntilRevoked(),
})

// Agent side — no API key needed; the connection token is the credential.
granted, err := client.Exchange(agentadmit.ExchangeRequest{
    Token:      issued.Token, // ag_ct_…
    AgentLabel: "MyAssistant",
})
// granted.AccessToken (ag_at_…), granted.Scopes, granted.ConnectionID

// Revoke when the user disconnects the agent.
_, err = client.Revoke(agentadmit.RevokeRequest{ConnectionID: granted.ConnectionID})
```

## Context Support

All SDK methods accept a `context.Context` for graceful cancellation and deadline propagation:

```go
// Preferred in HTTP handlers — respects request cancellation
info, err := client.ValidateContext(r.Context(), token, scopes)
```

## Thread Safety

`*agentadmit.Client` is safe for concurrent use. Create one instance at startup and share it across all goroutines.

## Important

**Mandatory introspection.** All token validation goes through `api.agentadmit.com`. There is no self-hosted mode. No local JWT validation. No bypass. This is required for security, audit logging, and real-time revocation.

Every agent request triggers a call to AgentAdmit's introspection API. Latency is typically under 200ms and only applies to agent requests, never your regular user traffic. The AI agent is making the API call, not the user — latency here doesn't affect the user experience.

**Admin revocation.** As the app/server operator, you can revoke any user's agent connection via `DELETE /agentadmit/admin/connections/{connection_id}` (requires admin role or `manage:connections` scope). Your own AI agent can also revoke connections if given this scope, enabling automated abuse detection and response.

**Embeddable admin panel.** Drop the `<AgentAdmitAdminPanel>` React component into your admin section to view all agent connections, usage metrics, billing status, and revoke any connection without leaving your app. See the React SDK for details.

**In-app AI scopes.** If your app has built-in AI features (analysis, plan generation, photo recognition), do not expose those as agent scopes. The user's AI agent can read the raw data and do the analysis itself. Exposing in-app AI endpoints to agents creates double cost: the user pays for their agent's model AND your app pays for the in-app AI call. Give agents read access to the raw data instead.

## Full Examples

| Example | Description |
|---------|-------------|
| [`examples/net-http/`](examples/net-http/) | Standard library HTTP server with middleware |
| [`examples/gin/`](examples/gin/) | Gin framework with route-level and group middleware |
| [`examples/mcp-server/`](examples/mcp-server/) | Complete MCP server with JSON-RPC, multiple tools, and token-per-call auth |

## Rate Limiting

The AgentAdmit introspection endpoint enforces rate limits. The Go SDK handles HTTP 429 responses **automatically** with exponential backoff and jitter — no changes needed in your handler or middleware code.

### Retry behavior

| Parameter | Default | Description |
|-----------|---------|-------------|
| Initial delay | 1 second | First retry wait |
| Backoff multiplier | 2× | Doubles each retry |
| Cap | 30 seconds | Maximum wait per retry |
| Jitter | 0–500 ms | Random addition to each delay |
| Max retries | **3** | Configurable via `Config.MaxRetries` |

The SDK also respects the `Retry-After` response header — if present, it overrides the computed backoff delay. Context cancellation is respected during retry sleeps.

### Configuring max retries

```go
client, err := agentadmit.New(agentadmit.Config{
    APIKey:     os.Getenv("AGENTADMIT_API_KEY"),
    MaxRetries: 5, // default: 3. Set to 0 to use default (3).
})
```

### Handling exhausted retries

When all retries are exhausted, `Validate` / `ValidateContext` returns a `*RateLimitError`:

```go
info, err := client.Validate(token, requiredScopes)
if err != nil {
    var rlErr *agentadmit.RateLimitError
    if errors.As(err, &rlErr) {
        w.Header().Set("Retry-After", fmt.Sprintf("%.0f", rlErr.RetryAfter))
        http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
        return
    }
    // handle other errors...
}
```

`RateLimitError` fields:
- `RetryAfter` — seconds from `Retry-After` header (-1 if absent)
- `Limit` — `X-RateLimit-Limit` header value (-1 if absent)
- `Remaining` — `X-RateLimit-Remaining` header value (-1 if absent)
- `Reset` — `X-RateLimit-Reset` Unix timestamp (-1 if absent)
- `MaxRetries` — number of retry attempts that were made

Use `agentadmit.IsRateLimit(err)` for a quick boolean check.

## Security

- Connection Tokens are hashed (SHA-256) before storage — plaintext is never persisted (spec §5.3.1)
- All agent requests validated via mandatory introspection through AgentAdmit's hosted service
- Tokens are displayed to users once and never retrievable again
- User-mediated delivery eliminates prompt injection at the credential exchange layer

## Documentation

Full integration guide: https://agentadmit.com/docs/app-owner-guide


## Data Collection & Privacy

The AgentAdmit Go SDK runs server-side and does not interact with app stores or end-user devices directly.

### What the SDK does
- Validates AgentAdmit tokens presented by AI agents
- Enforces scope-based access control on your API routes
- Manages connection lifecycle (create, revoke, audit)

### What the SDK does NOT do
- Does not collect end-user data
- Does not send telemetry or analytics
- Does not phone home to AgentAdmit servers (all operations use your configured keys and storage)
- Does not track users or devices

### Privacy impact
Since this SDK runs on your server, it has no direct App Store or Play Store compliance surface. Your client-side integration (e.g., the AgentAdmit React SDK) handles privacy manifest and data safety requirements.

For complete compliance guidance, see our [compliance guide](https://agentadmit.com/docs/compliance).

## License

All rights reserved. Patent pending.

## Security Alerts

Monitor suspicious agent activity. Six alert type constants: `AlertTypeVolumeSpike`, `AlertTypeFailedScopeAttempts`, `AlertTypeBurstPattern`, `AlertTypeStaleReactivation`, `AlertTypeNewScopeUsage`, `AlertTypeRevokedConnectionAttempt`.

### Configure Alert Thresholds

```go
enabled := true
threshold := 100.0
windowMin := 5

result, err := client.ConfigureAlerts(agentadmit.ConfigureAlertsRequest{
    AppID:                  "app_abc123",
    AlertType:              agentadmit.AlertTypeVolumeSpike,
    Enabled:                &enabled,
    ThresholdValue:         &threshold,
    ThresholdWindowMinutes: &windowMin,
})
```

### List Alert Events

```go
events, err := client.ListAlerts(agentadmit.ListAlertsOptions{
    AppID:     "app_abc123",
    AlertType: agentadmit.AlertTypeVolumeSpike,
    Limit:     50,
})
```

### Get Current Config

```go
config, err := client.GetAlertConfig(agentadmit.GetAlertConfigOptions{AppID: "app_abc123"})
```


### Notifying Your Users

AgentAdmit detects anomalies, fires alerts, and (with kill switch) auto-revokes connections. **How you notify your own users is up to you.** AgentAdmit provides the data — you deliver it through your own system (in-app notifications, email, push, etc.).

- **Poll alerts** — Use the SDK methods above from your backend to check for new events, then notify users through your existing system.
- **Webhook delivery** — Configure a webhook URL in your AgentAdmit dashboard. When an alert fires, AgentAdmit POSTs the payload to your server, signed with your `whsec_…` secret. Always verify the signature against the raw request body before trusting the payload:

  ```go
  http.HandleFunc("/agentadmit/alerts", func(w http.ResponseWriter, r *http.Request) {
      payload, err := io.ReadAll(r.Body)
      if err != nil {
          http.Error(w, "read error", http.StatusBadRequest)
          return
      }
      if err := agentadmit.VerifyWebhookSignature(
          payload,
          r.Header.Get("X-AgentAdmit-Signature"),
          os.Getenv("AGENTADMIT_WEBHOOK_SECRET"), // whsec_…
      ); err != nil {
          http.Error(w, "invalid signature", http.StatusBadRequest)
          return
      }
      // payload is authentic — parse and handle the alert
  })
  ```

  The header format is `t=<unix_ts>,v1=<hex>` — an HMAC-SHA256 of `{t}.{rawBody}` keyed with your signing secret. The helper compares in constant time and rejects timestamps more than 5 minutes off (replay protection); use `VerifyWebhookSignatureWithTolerance` to adjust.
- **React SDK** — Embed the `<AlertsPanel>` component so users can view their own alert history and tighten thresholds.
