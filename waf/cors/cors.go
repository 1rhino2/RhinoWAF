package cors

import (
	"fmt"
	"net/http"
	"strings"
)

type Config struct {
	Enabled        bool
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
	ExposeHeaders  []string
	MaxAge         int
	AllowAll       bool
}

type Handler struct {
	config Config
}

func NewHandler(config Config) *Handler {
	if config.AllowedMethods == nil {
		config.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	}
	if config.AllowedHeaders == nil {
		config.AllowedHeaders = []string{"Accept", "Content-Type", "Authorization"}
	}
	if config.MaxAge == 0 {
		config.MaxAge = 86400
	}
	return &Handler{config: config}
}

func (h *Handler) isOriginAllowed(origin string) bool {
	if !h.config.Enabled {
		return false
	}
	if h.config.AllowAll {
		return true
	}
	for _, allowed := range h.config.AllowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) bool {
	if !h.config.Enabled {
		return false
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}

	if !h.isOriginAllowed(origin) {
		return false
	}

	if h.config.AllowAll {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
	}

	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(h.config.AllowedMethods, ", "))
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(h.config.AllowedHeaders, ", "))
		if len(h.config.ExposeHeaders) > 0 {
			w.Header().Set("Access-Control-Expose-Headers", strings.Join(h.config.ExposeHeaders, ", "))
		}
		w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", h.config.MaxAge))
		w.WriteHeader(http.StatusNoContent)
		return true
	}

	if len(h.config.ExposeHeaders) > 0 {
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(h.config.ExposeHeaders, ", "))
	}

	return false
}
