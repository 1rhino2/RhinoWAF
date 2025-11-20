package rewrite

import (
	"net/http"
	"regexp"
	"strings"
)

type Rule struct {
	Pattern     string
	Replacement string
	compiled    *regexp.Regexp
}

type Config struct {
	Enabled bool
	Rules   []Rule
}

type Handler struct {
	config Config
}

func NewHandler(config Config) (*Handler, error) {
	for i := range config.Rules {
		compiled, err := regexp.Compile(config.Rules[i].Pattern)
		if err != nil {
			return nil, err
		}
		config.Rules[i].compiled = compiled
	}

	return &Handler{config: config}, nil
}

func (h *Handler) Rewrite(r *http.Request) bool {
	if !h.config.Enabled {
		return false
	}

	originalPath := r.URL.Path
	modified := false

	for _, rule := range h.config.Rules {
		if rule.compiled.MatchString(r.URL.Path) {
			newPath := rule.compiled.ReplaceAllString(r.URL.Path, rule.Replacement)
			r.URL.Path = newPath
			modified = true
			break
		}
	}

	return modified && originalPath != r.URL.Path
}

func (h *Handler) NormalizePath(path string) string {
	path = strings.TrimRight(path, "/")
	if path == "" {
		path = "/"
	}

	parts := strings.Split(path, "/")
	normalized := make([]string, 0, len(parts))

	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(normalized) > 0 {
				normalized = normalized[:len(normalized)-1]
			}
			continue
		}
		normalized = append(normalized, part)
	}

	if len(normalized) == 0 {
		return "/"
	}

	return "/" + strings.Join(normalized, "/")
}
