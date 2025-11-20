package requestid

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

type contextKey string

const (
	RequestIDHeader = "X-Request-ID"
	requestIDKey    = contextKey("requestID")
)

// Middleware adds a unique request ID to each request
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check if request already has an ID from upstream proxy
		reqID := r.Header.Get(RequestIDHeader)
		if reqID == "" {
			reqID = generate()
		}

		// add ID to response header for client tracking
		w.Header().Set(RequestIDHeader, reqID)

		// store in context for logging
		ctx := context.WithValue(r.Context(), requestIDKey, reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// FromContext retrieves request ID from context
func FromContext(ctx context.Context) string {
	if reqID, ok := ctx.Value(requestIDKey).(string); ok {
		return reqID
	}
	return ""
}

// FromRequest retrieves request ID from request context
func FromRequest(r *http.Request) string {
	return FromContext(r.Context())
}

func generate() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
