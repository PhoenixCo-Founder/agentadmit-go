// Example: AgentAdmit with the Go standard library (net/http)
//
// Run:
//
//	AGENTADMIT_API_KEY=aa_test_... go run main.go
//
// Test with curl:
//
//	curl -H "Authorization: Bearer ag_at_YOUR_TOKEN" http://localhost:8080/api/workouts
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/PhoenixCo-Founder/agentadmit-go"
)

func main() {
	// 1. Initialize the AgentAdmit client with your API key.
	//    Get your API key from agentadmit.com after signing up.
	client, err := agentadmit.New(agentadmit.Config{
		APIKey: os.Getenv("AGENTADMIT_API_KEY"),
	})
	if err != nil {
		log.Fatalf("failed to create AgentAdmit client: %v", err)
	}

	mux := http.NewServeMux()

	// 2. Protect routes with AgentAdmit scope middleware.
	//
	// client.Middleware is a "dual-path" middleware: requests that carry an
	// AgentAdmit Bearer token are validated and scope-checked; requests with
	// NO token pass through unchanged so your existing user-auth layer can
	// handle them.
	//
	// IMPORTANT: because pass-through requests reach your handler with
	// tokenInfo == nil, YOU must enforce user authentication for those
	// requests in the handler itself (or via a separate auth middleware that
	// runs before or after this one). Never expose data to callers who
	// present neither an AgentAdmit token nor valid user credentials.
	//
	// Correct composition: run your user-auth middleware first, then
	// client.Middleware. Example (stub shown — replace with your real auth):
	//
	//   mux.Handle("/api/workouts",
	//       requireUserAuth(                       // your app's auth
	//           client.Middleware("read:workouts")( // then agent check
	//               http.HandlerFunc(getWorkouts),
	//           ),
	//       ),
	//   )
	//
	// The handlers below demonstrate the correct per-handler fallback pattern
	// (return 401 when tokenInfo is nil).
	mux.Handle("/api/workouts",
		client.Middleware("read:workouts")(http.HandlerFunc(getWorkouts)))

	mux.Handle("/api/workouts/create",
		client.Middleware("create:workouts")(http.HandlerFunc(createWorkout)))

	// /api/meals uses the same dual-path pattern. The getMeals handler checks
	// for a nil tokenInfo and falls back to your user-auth layer.
	mux.Handle("/api/meals",
		client.Middleware("read:meals")(http.HandlerFunc(getMeals)))

	// 3. (Optional) An endpoint only accessible by AI agents — not regular users.
	//    RequireAgentMiddleware always demands a valid AgentAdmit token; there
	//    is no unauthenticated pass-through path.
	mux.Handle("/api/agent-only",
		client.RequireAgentMiddleware("read:workouts")(http.HandlerFunc(agentOnly)))

	log.Println("AgentAdmit net/http example listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// getWorkouts is a regular HTTP handler. Use agentadmit.TokenFromContext to
// access the validated token metadata if you need it (e.g., to scope the
// query to the token's app_id or to log the agent's identity).
func getWorkouts(w http.ResponseWriter, r *http.Request) {
	// Retrieve validated token info from context (set by middleware).
	// This is nil for regular user requests — handle both paths if needed.
	tokenInfo := agentadmit.TokenFromContext(r.Context())

	var resp map[string]interface{}
	if tokenInfo != nil {
		// Agent request: respond with the agent's view.
		resp = map[string]interface{}{
			"source":   "agent_request",
			"app_id":   tokenInfo.AppID,
			"scopes":   tokenInfo.Scopes,
			"workouts": sampleWorkouts(),
		}
	} else {
		// Regular user request: your existing auth handles this.
		resp = map[string]interface{}{
			"source":   "user_request",
			"workouts": sampleWorkouts(),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func createWorkout(w http.ResponseWriter, r *http.Request) {
	tokenInfo := agentadmit.TokenFromContext(r.Context())
	if tokenInfo == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// In production: parse and validate the request body, then persist.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Workout created",
		"app_id":  tokenInfo.AppID,
	})
}

func getMeals(w http.ResponseWriter, r *http.Request) {
	tokenInfo := agentadmit.TokenFromContext(r.Context())
	if tokenInfo == nil {
		// No AgentAdmit token — enforce your app's own user authentication
		// here before returning data. This stub rejects unauthenticated
		// requests so the endpoint is never open without any credential.
		// Replace this block with your session/JWT/cookie check in production.
		http.Error(w, `{"error":"unauthorized","message":"authentication required"}`,
			http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"app_id": tokenInfo.AppID,
		"meals": []map[string]string{
			{"name": "Oatmeal", "calories": "350"},
			{"name": "Chicken & Rice", "calories": "650"},
		},
	})
}

func agentOnly(w http.ResponseWriter, r *http.Request) {
	// This handler is only reachable by valid AI agents (RequireAgentMiddleware).
	tokenInfo := agentadmit.TokenFromContext(r.Context())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Hello, agent!",
		"app_id":  tokenInfo.AppID,
		"scopes":  tokenInfo.Scopes,
	})
}

func sampleWorkouts() []map[string]string {
	return []map[string]string{
		{"name": "Push Day", "date": "2026-03-20", "sets": "12"},
		{"name": "Pull Day", "date": "2026-03-19", "sets": "10"},
		{"name": "Leg Day", "date": "2026-03-18", "sets": "15"},
	}
}
