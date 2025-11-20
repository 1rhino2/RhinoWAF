package headers

import (
	"net/http"
	"path/filepath"
)

type Operation string

const (
	OpAdd    Operation = "add"
	OpSet    Operation = "set"
	OpRemove Operation = "remove"
)

type Rule struct {
	Path      string
	Operation Operation
	Header    string
	Value     string
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

func (h *Handler) ApplyRequest(r *http.Request) {
	if !h.config.Enabled {
		return
	}

	for _, rule := range h.config.Rules {
		if rule.Path != "" {
			matched, _ := filepath.Match(rule.Path, r.URL.Path)
			if !matched {
				continue
			}
		}

		switch rule.Operation {
		case OpAdd:
			r.Header.Add(rule.Header, rule.Value)
		case OpSet:
			r.Header.Set(rule.Header, rule.Value)
		case OpRemove:
			r.Header.Del(rule.Header)
		}
	}
}

func (h *Handler) ApplyResponse(w http.ResponseWriter, path string) {
	if !h.config.Enabled {
		return
	}

	for _, rule := range h.config.Rules {
		if rule.Path != "" {
			matched, _ := filepath.Match(rule.Path, path)
			if !matched {
				continue
			}
		}

		switch rule.Operation {
		case OpAdd:
			w.Header().Add(rule.Header, rule.Value)
		case OpSet:
			w.Header().Set(rule.Header, rule.Value)
		case OpRemove:
			w.Header().Del(rule.Header)
		}
	}
}
