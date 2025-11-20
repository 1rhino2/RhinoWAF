package auth

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config holds authentication configuration
type Config struct {
	Enabled            bool     `json:"enabled"`
	JWTSecret          string   `json:"jwt_secret"`          // Secret for JWT validation
	JWTHeader          string   `json:"jwt_header"`          // Header name for JWT (default: Authorization)
	SessionCookie      string   `json:"session_cookie"`      // Session cookie name (default: session_id)
	RateLimitPerUser   int      `json:"rate_limit_per_user"` // Rate limit per authenticated user (default: 1000)
	RateLimitWindow    int      `json:"rate_limit_window"`   // Window in seconds (default: 60)
	WhitelistUsernames []string `json:"whitelist_usernames"` // Users exempt from rate limiting
	TrackAnonymous     bool     `json:"track_anonymous"`     // Also track anonymous users by IP
}

// UserRateLimit tracks rate limiting per user
type UserRateLimit struct {
	Username string
	Requests []int64
	mu       sync.RWMutex
}

// RateLimiter handles per-user rate limiting
type RateLimiter struct {
	config Config
	users  map[string]*UserRateLimit
	mu     sync.RWMutex
}

// NewRateLimiter creates a new user rate limiter
func NewRateLimiter(config Config) *RateLimiter {
	if config.JWTHeader == "" {
		config.JWTHeader = "Authorization"
	}
	if config.SessionCookie == "" {
		config.SessionCookie = "session_id"
	}
	if config.RateLimitPerUser == 0 {
		config.RateLimitPerUser = 1000
	}
	if config.RateLimitWindow == 0 {
		config.RateLimitWindow = 60
	}

	limiter := &RateLimiter{
		config: config,
		users:  make(map[string]*UserRateLimit),
	}

	// Start cleanup goroutine
	go limiter.cleanup()

	return limiter
}

// ExtractUser extracts user from JWT or session cookie
func (rl *RateLimiter) ExtractUser(r *http.Request) string {
	if !rl.config.Enabled {
		return ""
	}

	// Try JWT first
	authHeader := r.Header.Get(rl.config.JWTHeader)
	if authHeader != "" {
		// Extract Bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			username := rl.parseJWT(parts[1])
			if username != "" {
				return username
			}
		}
	}

	// Try session cookie
	cookie, err := r.Cookie(rl.config.SessionCookie)
	if err == nil && cookie.Value != "" {
		return "session:" + cookie.Value
	}

	// No authentication found
	return ""
}

func (rl *RateLimiter) parseJWT(tokenString string) string {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(rl.config.JWTSecret), nil
	})

	if err != nil {
		return ""
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Try common username fields
		if username, ok := claims["username"].(string); ok {
			return username
		}
		if sub, ok := claims["sub"].(string); ok {
			return sub
		}
		if email, ok := claims["email"].(string); ok {
			return email
		}
		if userID, ok := claims["user_id"].(string); ok {
			return userID
		}
	}

	return ""
}

// CheckRateLimit checks if a user has exceeded their rate limit
func (rl *RateLimiter) CheckRateLimit(username string) bool {
	if !rl.config.Enabled || username == "" {
		return true // Allow if disabled or no user
	}

	// Check whitelist
	for _, whitelisted := range rl.config.WhitelistUsernames {
		if whitelisted == username {
			return true
		}
	}

	rl.mu.Lock()
	userLimit, exists := rl.users[username]
	if !exists {
		userLimit = &UserRateLimit{
			Username: username,
			Requests: make([]int64, 0),
		}
		rl.users[username] = userLimit
	}
	rl.mu.Unlock()

	userLimit.mu.Lock()
	defer userLimit.mu.Unlock()

	now := time.Now().Unix()
	windowStart := now - int64(rl.config.RateLimitWindow)

	// Remove old requests
	var filtered []int64
	for _, ts := range userLimit.Requests {
		if ts > windowStart {
			filtered = append(filtered, ts)
		}
	}
	userLimit.Requests = filtered

	// Check limit
	if len(userLimit.Requests) >= rl.config.RateLimitPerUser {
		return false
	}

	// Record request
	userLimit.Requests = append(userLimit.Requests, now)
	return true
}

// GetUserStats returns statistics for a user
func (rl *RateLimiter) GetUserStats(username string) map[string]interface{} {
	rl.mu.RLock()
	userLimit, exists := rl.users[username]
	rl.mu.RUnlock()

	if !exists {
		return map[string]interface{}{
			"exists": false,
		}
	}

	userLimit.mu.RLock()
	defer userLimit.mu.RUnlock()

	return map[string]interface{}{
		"exists":        true,
		"username":      username,
		"request_count": len(userLimit.Requests),
		"limit":         rl.config.RateLimitPerUser,
		"window":        rl.config.RateLimitWindow,
	}
}

// GetAllStats returns statistics for all tracked users
func (rl *RateLimiter) GetAllStats() map[string]interface{} {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	return map[string]interface{}{
		"tracked_users":  len(rl.users),
		"limit_per_user": rl.config.RateLimitPerUser,
		"window_seconds": rl.config.RateLimitWindow,
	}
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now().Unix()
		windowStart := now - int64(rl.config.RateLimitWindow)

		for username, userLimit := range rl.users {
			userLimit.mu.Lock()

			// Remove old requests
			var filtered []int64
			for _, ts := range userLimit.Requests {
				if ts > windowStart {
					filtered = append(filtered, ts)
				}
			}
			userLimit.Requests = filtered

			// Remove user if no recent activity
			if len(userLimit.Requests) == 0 {
				delete(rl.users, username)
			}

			userLimit.mu.Unlock()
		}
		rl.mu.Unlock()
	}
}

// Global rate limiter instance
var globalLimiter *RateLimiter

// Init initializes the global user rate limiter
func Init(config Config) {
	globalLimiter = NewRateLimiter(config)
	if config.Enabled {
		log.Printf("Per-user rate limiting enabled: %d requests per %d seconds", config.RateLimitPerUser, config.RateLimitWindow)
	}
}

// CheckUser checks if a user from the request has exceeded rate limit
func CheckUser(r *http.Request) (bool, string) {
	if globalLimiter == nil {
		return true, ""
	}

	username := globalLimiter.ExtractUser(r)
	if username == "" {
		return true, "" // No auth, allow (IP-based limits still apply)
	}

	allowed := globalLimiter.CheckRateLimit(username)
	return allowed, username
}

// GetUserInfo returns rate limit info for a user in a request
func GetUserInfo(r *http.Request) map[string]interface{} {
	if globalLimiter == nil {
		return map[string]interface{}{"enabled": false}
	}

	username := globalLimiter.ExtractUser(r)
	if username == "" {
		return map[string]interface{}{"authenticated": false}
	}

	return globalLimiter.GetUserStats(username)
}
