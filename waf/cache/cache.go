package cache

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
)

type Rule struct {
	Pattern string
	MaxAge  int
	NoCache bool
	NoStore bool
	Public  bool
	Private bool
}

type Config struct {
	Enabled bool
	Rules   []Rule
}

type Handler struct {
	config Config
}

func NewHandler(config Config) *Handler {
	return &Handler{config: config}
}

func (h *Handler) getRule(path string) *Rule {
	for _, rule := range h.config.Rules {
		matched, _ := filepath.Match(rule.Pattern, path)
		if matched {
			return &rule
		}
	}
	return nil
}

func (h *Handler) Apply(w http.ResponseWriter, r *http.Request) {
	if !h.config.Enabled {
		return
	}

	rule := h.getRule(r.URL.Path)
	if rule == nil {
		return
	}

	var parts []string

	if rule.NoCache {
		parts = append(parts, "no-cache")
	}
	if rule.NoStore {
		parts = append(parts, "no-store")
	}
	if rule.Public {
		parts = append(parts, "public")
	}
	if rule.Private {
		parts = append(parts, "private")
	}
	if rule.MaxAge > 0 && !rule.NoCache && !rule.NoStore {
		parts = append(parts, fmt.Sprintf("max-age=%d", rule.MaxAge))
	}

	if len(parts) > 0 {
		w.Header().Set("Cache-Control", strings.Join(parts, ", "))
	}
}
