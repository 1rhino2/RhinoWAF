package challenge

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type Config struct {
	Enabled         bool
	DefaultType     ChallengeType
	Difficulty      int
	WhitelistPaths  []string
	RequireForPaths []string
}

type Middleware struct {
	manager *Manager
	config  Config
}

func NewMiddleware(manager *Manager, config Config) *Middleware {
	return &Middleware{
		manager: manager,
		config:  config,
	}
}

func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		if m.isWhitelisted(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		ip := m.getIP(r)
		token := m.getTokenFromCookie(r)

		if token != "" && m.manager.VerifySession(token) {
			next.ServeHTTP(w, r)
			return
		}

		if m.requiresChallenge(r.URL.Path) || token != "" {
			session := m.manager.CreateSession(ip, m.config.DefaultType, m.config.Difficulty)
			m.setTokenCookie(w, r, session.Token)
			m.manager.RenderChallengePage(w, session)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) VerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "This endpoint only accepts POST requests", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Token    string `json:"token"`
		Type     string `json:"type"`
		Solution string `json:"solution"`
		Response string `json:"response"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request format. Please refresh the page and try again.",
		})
		return
	}

	session, exists := m.manager.GetSession(req.Token)
	if !exists {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Challenge session expired. Please refresh the page to get a new challenge.",
		})
		return
	}

	ip := m.getIP(r)
	if session.IP != ip {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "IP address mismatch detected. Please ensure you're not using a VPN or proxy that changes IP addresses.",
		})
		return
	}

	verified := false
	errorMessage := ""

	switch ChallengeType(req.Type) {
	case TypeJavaScript:
		verified = true
	case TypeProofOfWork:
		verified = m.manager.VerifyPOW(session.Challenge, req.Solution, session.Difficulty)
		if !verified {
			errorMessage = "Proof-of-work solution is incorrect. Please try again."
		}
	case TypeHCaptcha:
		if req.Response == "" {
			errorMessage = "Please complete the CAPTCHA challenge before submitting."
		} else {
			success, err := m.manager.VerifyHCaptcha(req.Response, ip)
			if err != nil {
				errorMessage = fmt.Sprintf("CAPTCHA verification failed: %s. Please refresh the page and try again.", err.Error())
			} else if !success {
				errorMessage = "CAPTCHA verification failed. The response was invalid or expired. Please try again."
			}
			verified = success && err == nil
		}
	case TypeTurnstile:
		if req.Response == "" {
			errorMessage = "Please complete the challenge before submitting."
		} else {
			success, err := m.manager.VerifyTurnstile(req.Response, ip)
			if err != nil {
				errorMessage = fmt.Sprintf("Challenge verification failed: %s. Please refresh the page and try again.", err.Error())
			} else if !success {
				errorMessage = "Challenge verification failed. The response was invalid or expired. Please try again."
			}
			verified = success && err == nil
		}
	default:
		errorMessage = "Unknown challenge type. Please refresh the page and try again."
	}

	if verified {
		m.manager.MarkVerified(req.Token)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   errorMessage,
		})
	}
}

func (m *Middleware) isWhitelisted(path string) bool {
	for _, wp := range m.config.WhitelistPaths {
		if strings.HasPrefix(path, wp) {
			return true
		}
	}
	return false
}

func (m *Middleware) requiresChallenge(path string) bool {
	if len(m.config.RequireForPaths) == 0 {
		return false
	}
	for _, rp := range m.config.RequireForPaths {
		if strings.HasPrefix(path, rp) {
			return true
		}
	}
	return false
}

func (m *Middleware) getIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}

	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	return strings.Split(r.RemoteAddr, ":")[0]
}

func (m *Middleware) getTokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie("waf_challenge_token")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (m *Middleware) setTokenCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "waf_challenge_token",
		Value:    token,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   r.TLS != nil, // Auto-detect HTTPS
		SameSite: http.SameSiteLaxMode,
	})
}
