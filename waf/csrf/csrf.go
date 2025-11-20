package csrf

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

type Config struct {
	Enabled       bool
	TokenLength   int
	TokenTTL      time.Duration
	CookieName    string
	HeaderName    string
	FormFieldName string
	SecureCookie  bool
	SameSite      http.SameSite
	ExemptMethods []string
	ExemptPaths   []string
	DoubleSubmit  bool
	ErrorMessage  string
}

type Manager struct {
	config Config
	tokens *sync.Map
}

type tokenData struct {
	value     string
	createdAt time.Time
	expires   time.Time
}

func NewManager(cfg Config) *Manager {
	// set some sane defaults
	if cfg.TokenLength == 0 {
		cfg.TokenLength = 32
	}
	if cfg.TokenTTL == 0 {
		cfg.TokenTTL = 1 * time.Hour
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "csrf_token"
	}
	if cfg.HeaderName == "" {
		cfg.HeaderName = "X-CSRF-Token"
	}
	if cfg.FormFieldName == "" {
		cfg.FormFieldName = "csrf_token"
	}
	if cfg.ErrorMessage == "" {
		cfg.ErrorMessage = "CSRF token validation failed"
	}
	if len(cfg.ExemptMethods) == 0 {
		cfg.ExemptMethods = []string{"GET", "HEAD", "OPTIONS", "TRACE"}
	}

	mgr := &Manager{
		config: cfg,
		tokens: &sync.Map{},
	}

	go mgr.cleanupExpired()

	return mgr
}

func (m *Manager) generateToken() (string, error) {
	b := make([]byte, m.config.TokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (m *Manager) isExemptMethod(method string) bool {
	for _, exempt := range m.config.ExemptMethods {
		if exempt == method {
			return true
		}
	}
	return false
}

func (m *Manager) isExemptPath(path string) bool {
	for _, exempt := range m.config.ExemptPaths {
		// Support both exact match and prefix match (if exempt ends with /)
		if exempt == path {
			return true
		}
		if len(exempt) > 0 && exempt[len(exempt)-1] == '/' {
			// Prefix match for paths ending with /
			if len(path) >= len(exempt) && path[:len(exempt)] == exempt {
				return true
			}
		}
	}
	return false
}

func (m *Manager) storeToken(sessionID, token string, ttl time.Duration) {
	data := &tokenData{
		value:     token,
		createdAt: time.Now(),
		expires:   time.Now().Add(ttl),
	}
	m.tokens.Store(sessionID, data)
}

func (m *Manager) validateToken(sessionID, token string) bool {
	val, ok := m.tokens.Load(sessionID)
	if !ok {
		return false
	}

	data, ok := val.(*tokenData)
	if !ok {
		return false
	}
	if time.Now().After(data.expires) {
		m.tokens.Delete(sessionID)
		return false
	}

	return data.value == token
}

// cleanup runs in background to remove expired tokens
func (m *Manager) cleanupExpired() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		m.tokens.Range(func(key, value interface{}) bool {
			data, ok := value.(*tokenData)
			if !ok {
				return true
			}
			if now.After(data.expires) {
				m.tokens.Delete(key)
			}
			return true
		})
	}
}

func (m *Manager) getSessionID(r *http.Request) string {
	if cookie, err := r.Cookie("session_id"); err == nil {
		return cookie.Value
	}
	// fall back to IP if no session cookie
	return r.RemoteAddr
}

func (m *Manager) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		if m.isExemptMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}

		if m.isExemptPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		sessionID := m.getSessionID(r)

		if m.config.DoubleSubmit {
			// double-submit cookie pattern - check cookie matches header/form
			cookieToken := ""
			if cookie, err := r.Cookie(m.config.CookieName); err == nil {
				cookieToken = cookie.Value
			}

			headerToken := r.Header.Get(m.config.HeaderName)
			if headerToken == "" {
				_ = r.ParseForm()
				headerToken = r.FormValue(m.config.FormFieldName)
			}

			if cookieToken == "" || headerToken == "" || cookieToken != headerToken {
				http.Error(w, m.config.ErrorMessage, http.StatusForbidden)
				return
			}
		} else {
			// server-side validation
			var providedToken string

			providedToken = r.Header.Get(m.config.HeaderName)

			// check form field if no header
			if providedToken == "" {
				_ = r.ParseForm()
				providedToken = r.FormValue(m.config.FormFieldName)
			}

			if providedToken == "" || !m.validateToken(sessionID, providedToken) {
				http.Error(w, m.config.ErrorMessage, http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (m *Manager) GenerateToken(w http.ResponseWriter, r *http.Request) (string, error) {
	token, err := m.generateToken()
	if err != nil {
		return "", err
	}

	sessionID := m.getSessionID(r)

	if m.config.DoubleSubmit {
		// set cookie for double-submit pattern
		cookie := &http.Cookie{
			Name:     m.config.CookieName,
			Value:    token,
			Path:     "/",
			MaxAge:   int(m.config.TokenTTL.Seconds()),
			HttpOnly: true,
			Secure:   m.config.SecureCookie,
			SameSite: m.config.SameSite,
		}
		http.SetCookie(w, cookie)
	} else {
		// store token server-side
		m.tokens.Store(sessionID, &tokenData{
			value:     token,
			createdAt: time.Now(),
			expires:   time.Now().Add(m.config.TokenTTL),
		})
	}

	return token, nil
}

func (m *Manager) GetToken(r *http.Request) string {
	if m.config.DoubleSubmit {
		if cookie, err := r.Cookie(m.config.CookieName); err == nil {
			return cookie.Value
		}
		return ""
	}

	sessionID := m.getSessionID(r)
	val, ok := m.tokens.Load(sessionID)
	if !ok {
		return ""
	}

	data, ok := val.(*tokenData)
	if !ok {
		return ""
	}
	if time.Now().After(data.expires) {
		m.tokens.Delete(sessionID)
		return ""
	}

	return data.value
}

func (m *Manager) DeleteToken(r *http.Request) {
	sessionID := m.getSessionID(r)
	m.tokens.Delete(sessionID)
}
