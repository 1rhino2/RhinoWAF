package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Enabled      bool     `json:"enabled"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	AuthURL      string   `json:"auth_url"`
	TokenURL     string   `json:"token_url"`
	RedirectURL  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes"`

	ProtectedPaths []string `json:"protected_paths"`
	SessionTimeout int      `json:"session_timeout"`
}

type Handler struct {
	config   Config
	sessions map[string]*Session
	states   map[string]time.Time
	mu       sync.RWMutex
}

type Session struct {
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
	UserInfo     map[string]interface{}
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

func NewHandler(cfg Config) *Handler {
	if cfg.SessionTimeout == 0 {
		cfg.SessionTimeout = 3600
	}

	h := &Handler{
		config:   cfg,
		sessions: make(map[string]*Session),
		states:   make(map[string]time.Time),
	}

	go h.cleanupLoop()
	return h
}

func (h *Handler) Handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		if r.URL.Path == "/oauth2/callback" {
			h.handleCallback(w, r)
			return
		}

		if r.URL.Path == "/oauth2/logout" {
			h.handleLogout(w, r)
			return
		}

		if !h.requiresAuth(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		sessionID := h.getSessionID(r)
		if sessionID == "" || !h.validateSession(sessionID) {
			h.redirectToAuth(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *Handler) requiresAuth(path string) bool {
	for _, p := range h.config.ProtectedPaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func (h *Handler) getSessionID(r *http.Request) string {
	cookie, err := r.Cookie("oauth2_session")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (h *Handler) validateSession(sessionID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	session, exists := h.sessions[sessionID]
	if !exists {
		return false
	}

	return time.Now().Before(session.Expiry)
}

func (h *Handler) redirectToAuth(w http.ResponseWriter, r *http.Request) {
	state := h.generateState()

	h.mu.Lock()
	h.states[state] = time.Now().Add(10 * time.Minute)
	h.mu.Unlock()

	authURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&state=%s&scope=%s",
		h.config.AuthURL,
		url.QueryEscape(h.config.ClientID),
		url.QueryEscape(h.config.RedirectURL),
		state,
		url.QueryEscape(strings.Join(h.config.Scopes, " ")),
	)

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handler) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if !h.validateState(state) {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	token, err := h.exchangeCode(code)
	if err != nil {
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}

	sessionID := h.generateSessionID()
	session := &Session{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(h.config.SessionTimeout) * time.Second),
	}

	h.mu.Lock()
	h.sessions[sessionID] = session
	delete(h.states, state)
	h.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "oauth2_session",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   h.config.SessionTimeout,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID := h.getSessionID(r)
	if sessionID != "" {
		h.mu.Lock()
		delete(h.sessions, sessionID)
		h.mu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "oauth2_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handler) exchangeCode(code string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", h.config.RedirectURL)
	data.Set("client_id", h.config.ClientID)
	data.Set("client_secret", h.config.ClientSecret)

	resp, err := http.PostForm(h.config.TokenURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var token TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}

	return &token, nil
}

func (h *Handler) validateState(state string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	expiry, exists := h.states[state]
	if !exists {
		return false
	}

	if time.Now().After(expiry) {
		delete(h.states, state)
		return false
	}

	return true
}

func (h *Handler) generateState() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (h *Handler) generateSessionID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (h *Handler) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		h.cleanup()
	}
}

func (h *Handler) cleanup() {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()

	for id, session := range h.sessions {
		if now.After(session.Expiry) {
			delete(h.sessions, id)
		}
	}

	for state, expiry := range h.states {
		if now.After(expiry) {
			delete(h.states, state)
		}
	}
}

func (h *Handler) GetSession(sessionID string) *Session {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.sessions[sessionID]
}
