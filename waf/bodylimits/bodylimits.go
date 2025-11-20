package bodylimits

import (
	"fmt"
	"net/http"
	"path/filepath"
)

type Config struct {
	GlobalLimit int64
	PathLimits  map[string]int64
	Enabled     bool
}

type Limiter struct {
	config Config
}

func NewLimiter(config Config) *Limiter {
	if config.PathLimits == nil {
		config.PathLimits = make(map[string]int64)
	}
	if config.GlobalLimit == 0 {
		config.GlobalLimit = 10 * 1024 * 1024 // 10MB default
	}
	return &Limiter{config: config}
}

func (l *Limiter) GetLimit(path string) int64 {
	if !l.config.Enabled {
		return l.config.GlobalLimit
	}

	for pattern, limit := range l.config.PathLimits {
		matched, _ := filepath.Match(pattern, path)
		if matched {
			return limit
		}
	}
	return l.config.GlobalLimit
}

func (l *Limiter) Check(r *http.Request) (bool, string) {
	if !l.config.Enabled {
		return true, ""
	}

	if r.Body == nil {
		return true, ""
	}

	limit := l.GetLimit(r.URL.Path)

	if r.ContentLength > limit {
		return false, fmt.Sprintf("Request body too large: %d bytes (limit: %d bytes)", r.ContentLength, limit)
	}

	return true, ""
}
