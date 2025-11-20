package compression

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
)

type Config struct {
	Enabled      bool
	Level        int
	MinSize      int
	ContentTypes []string
}

type responseWriter struct {
	http.ResponseWriter
	writer io.Writer
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	return rw.writer.Write(b)
}

type Handler struct {
	config Config
}

func NewHandler(config Config) *Handler {
	if config.Level == 0 {
		config.Level = 6
	}
	if config.MinSize == 0 {
		config.MinSize = 1024
	}
	if len(config.ContentTypes) == 0 {
		config.ContentTypes = []string{
			"text/html",
			"text/css",
			"text/javascript",
			"application/json",
			"application/javascript",
		}
	}

	return &Handler{config: config}
}

func (h *Handler) Handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		acceptEncoding := r.Header.Get("Accept-Encoding")
		if acceptEncoding == "" {
			next.ServeHTTP(w, r)
			return
		}

		var writer io.WriteCloser
		var encoding string

		if strings.Contains(acceptEncoding, "br") {
			writer = brotli.NewWriterLevel(w, h.config.Level)
			encoding = "br"
		} else if strings.Contains(acceptEncoding, "gzip") {
			writer, _ = gzip.NewWriterLevel(w, h.config.Level)
			encoding = "gzip"
		}

		if writer != nil {
			defer writer.Close()
			w.Header().Set("Content-Encoding", encoding)
			w.Header().Del("Content-Length")
			next.ServeHTTP(&responseWriter{ResponseWriter: w, writer: writer}, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}
