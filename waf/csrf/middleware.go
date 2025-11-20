package csrf

import (
	"encoding/json"
	"net/http"
)

type Middleware struct {
	manager *Manager
}

func NewMiddleware(mgr *Manager) *Middleware {
	return &Middleware{manager: mgr}
}

func (m *Middleware) Handler(next http.Handler) http.Handler {
	return m.manager.Protect(next)
}

// endpoint to get a new token
func (m *Middleware) TokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token, err := m.manager.GenerateToken(w, r)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"csrf_token": token,
		"header":     m.manager.config.HeaderName,
		"field":      m.manager.config.FormFieldName,
	})
}

// helper to inject token into HTML forms
func (m *Middleware) TokenField(r *http.Request) string {
	token := m.manager.GetToken(r)
	if token == "" {
		return ""
	}
	return `<input type="hidden" name="` + m.manager.config.FormFieldName + `" value="` + token + `">`
}

// helper for JavaScript fetch requests
func (m *Middleware) TokenMeta(r *http.Request) string {
	token := m.manager.GetToken(r)
	if token == "" {
		return ""
	}
	return `<meta name="csrf-token" content="` + token + `">`
}
