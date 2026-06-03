// Example: AgentAdmit with the Gin framework
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
	"log"
	"net/http"
	"os"

	"github.com/PhoenixCo-Founder/agentadmit-go"
	aggin "github.com/PhoenixCo-Founder/agentadmit-go/gin"
	"github.com/gin-gonic/gin"
)

func main() {
	// 1. Initialize the AgentAdmit client.
	client, err := agentadmit.New(agentadmit.Config{
		APIKey: os.Getenv("AGENTADMIT_API_KEY"),
	})
	if err != nil {
		log.Fatalf("failed to create AgentAdmit client: %v", err)
	}

	r := gin.Default()

	// 2. Apply AgentAdmit middleware per route.
	//    Requests without a Bearer token pass through to your existing auth.
	//    Requests with a valid AgentAdmit token have TokenInfo stored in context.
	r.GET("/api/workouts",
		aggin.Middleware(client, "read:workouts"),
		getWorkouts,
	)

	r.POST("/api/workouts",
		aggin.Middleware(client, "create:workouts"),
		createWorkout,
	)

	r.GET("/api/meals",
		aggin.Middleware(client, "read:meals"),
		getMeals,
	)

	r.GET("/api/analytics",
		aggin.Middleware(client, "read:analytics"),
		getAnalytics,
	)

	// 3. Route group with shared AgentAdmit middleware.
	//    All routes in this group require a valid token.
	agentRoutes := r.Group("/agent", aggin.RequireAgent(client))
	{
		agentRoutes.GET("/profile", getAgentProfile)
	}

	log.Println("AgentAdmit Gin example listening on :8080")
	r.Run(":8080")
}

func getWorkouts(c *gin.Context) {
	// Retrieve validated token info from the Gin context.
	// nil means this was a regular user request (no AgentAdmit token).
	tokenInfo := aggin.GetTokenInfo(c)

	if tokenInfo != nil {
		c.JSON(http.StatusOK, gin.H{
			"source":   "agent_request",
			"app_id":   tokenInfo.AppID,
			"scopes":   tokenInfo.Scopes,
			"workouts": sampleWorkouts(),
		})
		return
	}

	// Regular user path — your existing auth would validate the session here.
	c.JSON(http.StatusOK, gin.H{
		"source":   "user_request",
		"workouts": sampleWorkouts(),
	})
}

func createWorkout(c *gin.Context) {
	tokenInfo := aggin.GetTokenInfo(c)
	if tokenInfo == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// In production: bind and validate c.ShouldBindJSON(&req), then persist.
	c.JSON(http.StatusCreated, gin.H{
		"message": "Workout created",
		"app_id":  tokenInfo.AppID,
	})
}

func getMeals(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"meals": []gin.H{
			{"name": "Oatmeal", "calories": 350},
			{"name": "Chicken & Rice", "calories": 650},
		},
	})
}

func getAnalytics(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"weekly_workouts": 4,
		"avg_calories":    2100,
		"streak_days":     12,
	})
}

func getAgentProfile(c *gin.Context) {
	// RequireAgent middleware guarantees tokenInfo is non-nil here.
	tokenInfo := aggin.GetTokenInfo(c)
	c.JSON(http.StatusOK, gin.H{
		"app_id":     tokenInfo.AppID,
		"scopes":     tokenInfo.Scopes,
		"expires_at": tokenInfo.ExpiresAt,
	})
}

func sampleWorkouts() []gin.H {
	return []gin.H{
		{"name": "Push Day", "date": "2026-03-20", "sets": 12},
		{"name": "Pull Day", "date": "2026-03-19", "sets": 10},
		{"name": "Leg Day", "date": "2026-03-18", "sets": 15},
	}
}
