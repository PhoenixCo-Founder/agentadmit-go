// Example: AgentAdmit in an MCP (Model Context Protocol) server
//
// MCP servers receive JSON-RPC 2.0 messages over stdio. AI agents call
// "tools" by sending tool-call requests. This example shows exactly where
// and how to plug in AgentAdmit token validation.
//
// The key insight: AgentAdmit tokens travel inside the JSON-RPC message —
// either in the tool's params or in a metadata field. You extract the token,
// validate it, and only process the tool call if the token is valid and has
// the required scopes.
//
// Run:
//
//	AGENTADMIT_API_KEY=aa_test_... go run main.go
//
// The server reads JSON-RPC messages from stdin and writes responses to stdout.
// Test with:
//
//	echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_workouts","arguments":{"agentadmit_token":"ag_at_YOUR_TOKEN"}}}' | AGENTADMIT_API_KEY=aa_test_... go run main.go
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/PhoenixCo-Founder/agentadmit-go"
)

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 types
// ---------------------------------------------------------------------------

// JSONRPCRequest is a JSON-RPC 2.0 request or notification.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse is a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      interface{}   `json:"id,omitempty"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// JSONRPCError is a JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Standard JSON-RPC error codes.
const (
	ErrMethodNotFound = -32601
	ErrInvalidParams  = -32602
	ErrUnauthorized   = -32001 // Custom: no/invalid AgentAdmit token
	ErrForbidden      = -32002 // Custom: insufficient scopes
)

// ---------------------------------------------------------------------------
// MCP tool definitions
// ---------------------------------------------------------------------------

// ToolDefinition describes a single MCP tool.
type ToolDefinition struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

// InputSchema is a minimal JSON Schema for tool inputs.
type InputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties"`
	Required   []string            `json:"required"`
}

// Property is a single JSON Schema property.
type Property struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

// tools is the list of MCP tools this server exposes.
var tools = []ToolDefinition{
	{
		Name:        "get_workouts",
		Description: "Retrieve the user's workout history. Requires read:workouts scope.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"agentadmit_token": {
					Type:        "string",
					Description: "AgentAdmit access token (ag_at_...). Obtained by exchanging a connection token.",
				},
				"limit": {
					Type:        "integer",
					Description: "Maximum number of workouts to return (default: 10).",
				},
			},
			Required: []string{"agentadmit_token"},
		},
	},
	{
		Name:        "log_workout",
		Description: "Log a new workout entry. Requires create:workouts scope.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"agentadmit_token": {
					Type:        "string",
					Description: "AgentAdmit access token (ag_at_...).",
				},
				"name": {
					Type:        "string",
					Description: "Workout name, e.g. 'Push Day'.",
				},
				"sets": {
					Type:        "integer",
					Description: "Number of sets completed.",
				},
			},
			Required: []string{"agentadmit_token", "name"},
		},
	},
	{
		Name:        "get_meals",
		Description: "Retrieve the user's meal log. Requires read:meals scope.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"agentadmit_token": {
					Type:        "string",
					Description: "AgentAdmit access token (ag_at_...).",
				},
			},
			Required: []string{"agentadmit_token"},
		},
	},
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	// Initialize AgentAdmit client once at startup — reuse across all requests.
	client, err := agentadmit.New(agentadmit.Config{
		APIKey: os.Getenv("AGENTADMIT_API_KEY"),
	})
	if err != nil {
		log.Fatalf("AgentAdmit init failed: %v", err)
	}

	server := &MCPServer{client: client}

	log.SetOutput(os.Stderr) // MCP servers use stderr for logs; stdout is for JSON-RPC
	log.Println("AgentAdmit MCP server started (reading from stdin)")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			writeResponse(JSONRPCResponse{
				JSONRPC: "2.0",
				Error:   &JSONRPCError{Code: -32700, Message: "Parse error"},
			})
			continue
		}

		resp := server.handle(context.Background(), req)
		writeResponse(resp)
	}
}

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------

// MCPServer handles JSON-RPC requests using AgentAdmit for authorization.
type MCPServer struct {
	client *agentadmit.Client
}

// handle dispatches a JSON-RPC request to the appropriate handler.
func (s *MCPServer) handle(ctx context.Context, req JSONRPCRequest) JSONRPCResponse {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolCall(ctx, req)
	default:
		return errorResponse(req.ID, ErrMethodNotFound, fmt.Sprintf("method not found: %s", req.Method))
	}
}

func (s *MCPServer) handleInitialize(req JSONRPCRequest) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools": map[string]bool{"listChanged": false},
			},
			"serverInfo": map[string]string{
				"name":    "agentadmit-mcp-example",
				"version": "1.0.0",
			},
		},
	}
}

func (s *MCPServer) handleToolsList(req JSONRPCRequest) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  map[string]interface{}{"tools": tools},
	}
}

// handleToolCall is where AgentAdmit validation happens.
// Every tool call must include an agentadmit_token in its arguments.
func (s *MCPServer) handleToolCall(ctx context.Context, req JSONRPCRequest) JSONRPCResponse {
	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return errorResponse(req.ID, ErrInvalidParams, "invalid params")
	}

	// -----------------------------------------------------------------------
	// STEP 1: Extract the AgentAdmit token from the tool call arguments.
	//
	// Convention: agents pass the token as "agentadmit_token" in the
	// tool arguments. This is set in each tool's inputSchema above so
	// agents know to include it.
	// -----------------------------------------------------------------------
	token, _ := params.Arguments["agentadmit_token"].(string)

	// -----------------------------------------------------------------------
	// STEP 2: Determine required scopes for this tool.
	// -----------------------------------------------------------------------
	requiredScopes := scopesForTool(params.Name)

	// -----------------------------------------------------------------------
	// STEP 3: Validate the token via AgentAdmit.
	//
	// This is the ONLY place validation happens. AgentAdmit checks:
	//   - Token exists and has not expired or been revoked
	//   - Token has the required scopes
	//
	// Mandatory introspection: every tool call triggers a real-time check
	// against api.agentadmit.com. No local JWT validation. No bypass.
	// -----------------------------------------------------------------------
	tokenInfo, err := s.client.ValidateContext(ctx, token, requiredScopes)
	if err != nil {
		log.Printf("AgentAdmit validation failed for tool %q: %v", params.Name, err)
		return agentAdmitErrorToRPC(req.ID, err)
	}

	// -----------------------------------------------------------------------
	// STEP 4: Token is valid and scoped. Execute the tool.
	// -----------------------------------------------------------------------
	log.Printf("Tool %q called by app_id=%s with scopes=%v", params.Name, tokenInfo.AppID, tokenInfo.Scopes)

	return s.executeTool(req.ID, params.Name, params.Arguments, tokenInfo)
}

// executeTool runs the actual business logic for each tool.
func (s *MCPServer) executeTool(id interface{}, toolName string, args map[string]interface{}, tokenInfo *agentadmit.TokenInfo) JSONRPCResponse {
	switch toolName {
	case "get_workouts":
		return s.toolGetWorkouts(id, args, tokenInfo)
	case "log_workout":
		return s.toolLogWorkout(id, args, tokenInfo)
	case "get_meals":
		return s.toolGetMeals(id, args, tokenInfo)
	default:
		return errorResponse(id, ErrMethodNotFound, fmt.Sprintf("unknown tool: %s", toolName))
	}
}

func (s *MCPServer) toolGetWorkouts(id interface{}, args map[string]interface{}, _ *agentadmit.TokenInfo) JSONRPCResponse {
	// In production: look up workouts for tokenInfo.AppID / the authenticated user.
	workouts := []map[string]interface{}{
		{"name": "Push Day", "date": "2026-03-20", "sets": 12},
		{"name": "Pull Day", "date": "2026-03-19", "sets": 10},
		{"name": "Leg Day", "date": "2026-03-18", "sets": 15},
	}
	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("Found %d workouts:\n"+
						"- Push Day (2026-03-20): 12 sets\n"+
						"- Pull Day (2026-03-19): 10 sets\n"+
						"- Leg Day (2026-03-18): 15 sets", len(workouts)),
				},
			},
		},
	}
}

func (s *MCPServer) toolLogWorkout(id interface{}, args map[string]interface{}, _ *agentadmit.TokenInfo) JSONRPCResponse {
	name, _ := args["name"].(string)
	sets, _ := args["sets"].(float64)
	if name == "" {
		return errorResponse(id, ErrInvalidParams, "workout name is required")
	}
	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("Logged workout: %s (%.0f sets)", name, sets),
				},
			},
		},
	}
}

func (s *MCPServer) toolGetMeals(id interface{}, args map[string]interface{}, _ *agentadmit.TokenInfo) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": "Today's meals:\n- Breakfast: Oatmeal (350 cal)\n- Lunch: Chicken & Rice (650 cal)\n- Dinner: Salmon & Vegetables (520 cal)",
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// scopesForTool returns the AgentAdmit scopes required for a given MCP tool.
// This is the authoritative mapping — update it as you add new tools.
func scopesForTool(toolName string) []string {
	scopes := map[string][]string{
		"get_workouts": {"read:workouts"},
		"log_workout":  {"create:workouts"},
		"get_meals":    {"read:meals"},
	}
	if s, ok := scopes[toolName]; ok {
		return s
	}
	return nil
}

// agentAdmitErrorToRPC converts an AgentAdmit error to a JSON-RPC error response.
func agentAdmitErrorToRPC(id interface{}, err error) JSONRPCResponse {
	if agentadmit.IsInvalidToken(err) {
		return errorResponse(id, ErrUnauthorized, "Invalid or expired AgentAdmit token. The user may need to generate a new connection token.")
	}
	if agentadmit.IsInsufficientScopes(err) {
		return errorResponse(id, ErrForbidden, "Token lacks required permissions for this tool. The user needs to grant additional scopes.")
	}
	if agentadmit.IsServiceUnavailable(err) {
		return errorResponse(id, -32603, "AgentAdmit service temporarily unavailable. Please retry.")
	}
	return errorResponse(id, -32603, "Token validation failed")
}

func errorResponse(id interface{}, code int, message string) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &JSONRPCError{Code: code, Message: message},
	}
}

func writeResponse(resp JSONRPCResponse) {
	b, _ := json.Marshal(resp)
	fmt.Println(string(b))
}
